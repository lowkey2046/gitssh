package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"

	"github.com/lowkey2046/gitssh/helper"
	pb "github.com/lowkey2046/gitssh/proto"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

var (
	authorizedKeysPath = "ssh/authorized_keys"
	hostKeyPath        = "ssh/id_rsa"
	log                = logrus.New()
)

func sshConfig() *ssh.ServerConfig {
	authorizedKeysBytes, err := ioutil.ReadFile(authorizedKeysPath)
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(key.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(key),
					},
				}, nil
			}
			return nil, fmt.Errorf("unkonwn public key for %q", conn.User())
		},
	}

	privateBytes, err := ioutil.ReadFile(hostKeyPath)
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	privateKey, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(privateKey)

	return config
}

func parseGitCommand(payload []byte) (string, string, error) {
	index := bytes.IndexByte(payload, byte('g'))
	if index == -1 {
		return "", "", errors.New("not git command")
	}

	payloadStr := string(payload[index:])
	args := strings.Split(payloadStr, " ")
	if len(args) != 2 {
		return "", "", errors.New("git command args error")
	}

	command := strings.TrimSpace(args[0])
	repository := strings.Trim(strings.Trim(args[1], "'"), "/")

	return command, repository, nil
}

func handleChannel(channel ssh.Channel, requires <-chan *ssh.Request) {
	defer channel.Close()
	for req := range requires {
		req.Reply(req.Type == "exec", nil)

		if req.Type == "exec" {
			command, repository, err := parseGitCommand(req.Payload)
			if err != nil {
				log.Printf("parseGitCommand: %v", err)
				continue
			}

			log.Printf("git command: %s %s", command, repository)

			// TODO: 通过 repository 查询 ip 地址
			client, err := Get("127.0.0.1:8080")
			if err != nil {
				log.Fatal(err)
			}

			switch command {
			case "git-upload-pack":
				stream, err := client.SSHUploadPack(context.Background())
				if err != nil {
					log.Fatal(err)
				}

				msg := &pb.SSHUploadPackRequest{
					Repository: &pb.Repository{
						RelativePath: repository,
					},
				}
				if err := stream.Send(msg); err != nil {
					log.Fatal(err)
				}

				// 客户端 -> RPC
				go func() {
					sw := helper.NewRPCWriter(func(p []byte) error {
						return stream.Send(&pb.SSHUploadPackRequest{Stdin: p})
					})

					_, err := io.Copy(sw, channel)
					if err != nil && err != io.EOF {
						log.Printf("io.Copy: %s", err)
					}
					stream.CloseSend()
				}()

				// RPC -> 客户端
				for {
					response, err := stream.Recv()
					if err != nil {
						if err == io.EOF {
							channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						} else {
							log.Printf("stream.Recv: %v", err)
						}
						channel.Close()
						break
					}

					// 标准输出
					if len(response.GetStdout()) > 0 {
						if _, err := channel.Write(response.GetStdout()); err != nil {
							log.Printf("channel.Write: %v", err)
							break
						}
					}

					// 标准出错
					if len(response.GetStderr()) > 0 {
						stream.CloseSend()
						if _, err = channel.Stderr().Write(response.GetStderr()); err != nil {
							log.Printf("channel.Stderr.Write: %v", err)
							break
						}
					}
				}

			case "git-receive-pack":
				stream, err := client.SSHReceivePack(context.Background())
				if err != nil {
					log.Fatal(err)
				}

				request := &pb.SSHReceivePackRequest{
					Repository: &pb.Repository{
						RelativePath: repository,
					},
				}

				if err := stream.Send(request); err != nil {
					log.Fatal(err)
				}

				// 客户端 -> RPC
				go func() {
					sw := helper.NewRPCWriter(func(p []byte) error {
						return stream.Send(&pb.SSHReceivePackRequest{Stdin: p})
					})

					_, err := io.Copy(sw, channel)
					if err != nil && err != io.EOF {
						log.Printf("stream.Send %s", err)
					}
					stream.CloseSend()
				}()

				// RPC -> 客户端
				for {
					response, err := stream.Recv()
					if err != nil {
						if err == io.EOF {
							channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						} else {
							log.Printf("stream.Recv: %v", err)
						}
						channel.Close()
						break
					}
					_, err = channel.Write(response.GetStdout())
					if err != nil {
						log.Printf("channel.Write: %v", err)
						break
					}
				}

			default:
				log.Fatal(command)
			}
		}
	}
}

func handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("failed to handshake: %v", err)
		return
	}

	go ssh.DiscardRequests(reqs)
	log.Printf("key-sha1: %s", conn.Permissions.Extensions["pubkey-fp"])

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requires, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		handleChannel(channel, requires)
	}
}

func main() {
	config := sshConfig()

	listener, err := net.Listen("tcp", "0.0.0.0:2202")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection: %v", err)
			continue
		}

		go handleConnection(nConn, config)
	}
}

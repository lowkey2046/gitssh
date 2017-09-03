package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

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
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "git" && string(password) == "123456" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", conn.User())
		},
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
		log.Fatalf("req.Payload, %v", payload)
	}
	payloadStr := string(payload[index:])
	args := strings.Split(payloadStr, " ")
	if len(args) != 2 {
		log.Fatal(args)
	}
	command := strings.TrimSpace(args[0])
	repository := strings.Trim(strings.Trim(args[1], "'"), "/")

	return command, repository, nil
}

func handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
	}
	log.Printf("logged with key %s", conn.Permissions.Extensions["pubkey-fp"])

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		log.Printf("channel type: %s", newChannel.ChannelType())
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requires, err := newChannel.Accept()
		if err != nil {
			log.Fatalf("Could not accept channel: %v", err)
		}
		log.Printf("accpet new channel")

		go func(ch ssh.Channel, in <-chan *ssh.Request) {
			defer channel.Close()
			for req := range in {
				req.Reply(req.Type == "exec", nil)

				if req.Type == "exec" {
					command, repository, err := parseGitCommand(req.Payload)
					if err != nil {
						log.Fatal(err)
					}
					log.Printf("git command: %s %s", command, repository)

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

						request := &pb.SSHUploadPackRequest{
							Repository: &pb.Repository{
								Path:      repository,
								Namespace: repository,
							},
						}

						if err := stream.Send(request); err != nil {
							log.Fatal(err)
						}

						// receive
						go func() {
							for {
								response, err := stream.Recv()
								if err != nil {
									channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
									channel.Close()
									log.Printf("stream.Recv: %v", err)
									break
								}
								_, err = channel.Write(response.GetStdout())
								if err != nil {
									log.Printf("channel.Write: %v", err)
									break
								}
							}
						}()

						// send
						for {
							buf := make([]byte, 1024)
							n, err := channel.Read(buf)
							if err != nil {
								stream.CloseSend()
								log.Printf("channel.Read %v", err)
								break
							}
							request := pb.SSHUploadPackRequest{
								Stdin: buf[:n],
							}
							err = stream.Send(&request)
							if err != nil {
								log.Printf("stream.Send  %v", err)
								break
							}
						}
					case "git-receive-pack":
					default:
						log.Fatal(command)
					}
				}
			}
		}(channel, requires)
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
			log.Fatal("failed to accept incoming connection: ", err)
		}
		handleConnection(nConn, config)
	}
}

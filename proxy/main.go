package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"

	pb "github.com/lowkey2046/gitssh/proto"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

var (
	authorizedKeysPath = "ssh/authorized_keys"
	hostKeyPath        = "ssh/id_rsa"
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
					log.Printf("req type: %s", req.Type)

					if req.Type == "exec" {
						index := bytes.IndexByte(req.Payload, byte('g'))
						if index == -1 {
							log.Fatalf("req.Payload, %v", req.Payload)
						}
						payload := string(req.Payload[index:])
						args := strings.Split(payload, " ")
						if len(args) != 2 {
							log.Fatal(args)
						}
						command := strings.TrimSpace(args[0])
						repository := strings.Trim(strings.Trim(args[1], "'"), "/")

						log.Printf("%s %s", command, repository)

						client := Get("127.0.0.1:8080")

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
						case "git-receive-pack":
						default:
							log.Fatal(command)
						}
					}

					req.Reply(req.Type == "exec", nil)
				}
			}(channel, requires)
		}
	}
}

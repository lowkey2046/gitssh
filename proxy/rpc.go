package main

import (
	pb "github.com/lowkey2046/gitssh/proto"
	"google.golang.org/grpc"
)

var clients map[string]pb.SSHServiceClient

func init() {
	clients = make(map[string]pb.SSHServiceClient)
}

func Get(addr string) (pb.SSHServiceClient, error) {
	client, ok := clients[addr]
	if !ok {
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		if err != nil {
			return nil, err
		}
		client = pb.NewSSHServiceClient(conn)
		clients[addr] = client
	}

	return client, nil
}

package main

import (
	"log"
	"net"

	pb "github.com/lowkey2046/gitssh/proto"
	"google.golang.org/grpc"
)

var (
	addr = ":8080"
)

type sshServer struct {
}

func (s *sshServer) SSHUploadPack(stream pb.SSHService_SSHUploadPackServer) error {
	return nil
}

func (s *sshServer) SSHReceivePack(stream pb.SSHService_SSHReceivePackServer) error {
	return nil
}

func main() {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("falied to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterSSHServiceServer(grpcServer, new(sshServer))
	grpcServer.Serve(listener)
}

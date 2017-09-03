package main

import (
	"net"
	"os/exec"

	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	pb "github.com/lowkey2046/gitssh/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	addr    = ":8080"
	log     = logrus.New()
	workdir = "."
)

type sshServer struct {
}

func (s *sshServer) SSHUploadPack(stream pb.SSHService_SSHUploadPackServer) error {
	in, err := stream.Recv()
	if err != nil {
		return err
	}
	// TODO: nil
	repository := in.GetRepository()
	cmd := exec.Command("git", "upload-pack", repository.GetNamespace())
	cmd.Stdin = NewReader(func() ([]byte, error) {
		in, err := stream.Recv()
		return in.GetStdin(), err
	})
	cmd.Stdout = NewRPCWriter(func(p []byte) error {
		out := &pb.SSHUploadPackResponse{
			Stdout: p,
		}
		return stream.Send(out)
	})

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func (s *sshServer) SSHReceivePack(stream pb.SSHService_SSHReceivePackServer) error {
	in, err := stream.Recv()
	if err != nil {
		return err
	}
	// TODO: nil
	repository := in.GetRepository()
	cmd := exec.Command("git", "receive-pack", repository.GetNamespace())
	cmd.Stdin = NewReader(func() ([]byte, error) {
		in, err := stream.Recv()
		return in.GetStdin(), err
	})
	cmd.Stdout = NewRPCWriter(func(p []byte) error {
		out := &pb.SSHReceivePackResponse{
			Stdout: p,
		}
		return stream.Send(out)
	})

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func main() {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("falied to listen: %v", err)
	}

	logrusEntry := logrus.NewEntry(log)
	grpc_logrus.ReplaceGrpcLogger(logrusEntry)

	grpcServer := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(
			grpc_logrus.UnaryServerInterceptor(logrusEntry),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_logrus.StreamServerInterceptor(logrusEntry),
		),
	)
	pb.RegisterSSHServiceServer(grpcServer, new(sshServer))

	log.Info("server start")
	grpcServer.Serve(listener)
}

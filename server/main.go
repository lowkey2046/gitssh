package main

import (
	"errors"
	"net"
	"os/exec"

	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	"github.com/lowkey2046/gitssh-demo/helper"
	pb "github.com/lowkey2046/gitssh-demo/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	addr    = ":8080"
	log     = logrus.New()
	workDir = "."
)

type sshServer struct {
}

func (s *sshServer) SSHUploadPack(stream pb.SSHService_SSHUploadPackServer) error {
	in, err := stream.Recv()
	if err != nil {
		return err
	}

	repository := in.GetRepository()
	if repository == nil {
		return errors.New("repository is empty")
	}

	cmd := exec.Command("git-upload-pack", repository.GetRelativePath())
	cmd.Dir = workDir
	cmd.Stdin = helper.NewRPCReader(func() ([]byte, error) {
		in, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		return in.GetStdin(), nil
	})
	cmd.Stdout = helper.NewRPCWriter(func(p []byte) error {
		out := &pb.SSHUploadPackResponse{
			Stdout: p,
		}
		return stream.Send(out)
	})
	cmd.Stderr = helper.NewRPCWriter(func(p []byte) error {
		out := &pb.SSHUploadPackResponse{
			Stderr: p,
		}
		return stream.Send(out)
	})

	if err := cmd.Start(); err != nil {
		return err
	}

	return cmd.Wait()
}

func (s *sshServer) SSHReceivePack(stream pb.SSHService_SSHReceivePackServer) error {
	in, err := stream.Recv()
	if err != nil {
		return err
	}

	repository := in.GetRepository()
	if repository == nil {
		return errors.New("repository is empty")
	}

	cmd := exec.Command("git-receive-pack", repository.GetRelativePath())
	cmd.Dir = workDir
	cmd.Stdin = helper.NewRPCReader(func() ([]byte, error) {
		in, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		return in.GetStdin(), nil
	})
	cmd.Stdout = helper.NewRPCWriter(func(p []byte) error {
		out := &pb.SSHReceivePackResponse{
			Stdout: p,
		}
		return stream.Send(out)
	})
	cmd.Stderr = helper.NewRPCWriter(func(p []byte) error {
		out := &pb.SSHReceivePackResponse{
			Stderr: p,
		}
		return stream.Send(out)
	})

	if err := cmd.Start(); err != nil {
		return err
	}

	return cmd.Wait()
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

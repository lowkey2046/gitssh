// Code generated by protoc-gen-go. DO NOT EDIT.
// source: ssh.proto

/*
Package gitssh is a generated protocol buffer package.

It is generated from these files:
	ssh.proto

It has these top-level messages:
	Repository
	SSHUploadPackRequest
	SSHUploadPackResponse
	SSHReceivePackRequest
	SSHReceivePackResponse
*/
package gitssh

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Repository struct {
	Path      string `protobuf:"bytes,1,opt,name=path" json:"path,omitempty"`
	Namespace string `protobuf:"bytes,2,opt,name=namespace" json:"namespace,omitempty"`
}

func (m *Repository) Reset()                    { *m = Repository{} }
func (m *Repository) String() string            { return proto.CompactTextString(m) }
func (*Repository) ProtoMessage()               {}
func (*Repository) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Repository) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *Repository) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

type SSHUploadPackRequest struct {
	Repository *Repository `protobuf:"bytes,1,opt,name=repository" json:"repository,omitempty"`
	Stdin      []byte      `protobuf:"bytes,2,opt,name=stdin,proto3" json:"stdin,omitempty"`
}

func (m *SSHUploadPackRequest) Reset()                    { *m = SSHUploadPackRequest{} }
func (m *SSHUploadPackRequest) String() string            { return proto.CompactTextString(m) }
func (*SSHUploadPackRequest) ProtoMessage()               {}
func (*SSHUploadPackRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *SSHUploadPackRequest) GetRepository() *Repository {
	if m != nil {
		return m.Repository
	}
	return nil
}

func (m *SSHUploadPackRequest) GetStdin() []byte {
	if m != nil {
		return m.Stdin
	}
	return nil
}

type SSHUploadPackResponse struct {
	Stdout     []byte `protobuf:"bytes,1,opt,name=stdout,proto3" json:"stdout,omitempty"`
	Stderr     []byte `protobuf:"bytes,2,opt,name=stderr,proto3" json:"stderr,omitempty"`
	ExitStatus int32  `protobuf:"varint,3,opt,name=exit_status,json=exitStatus" json:"exit_status,omitempty"`
}

func (m *SSHUploadPackResponse) Reset()                    { *m = SSHUploadPackResponse{} }
func (m *SSHUploadPackResponse) String() string            { return proto.CompactTextString(m) }
func (*SSHUploadPackResponse) ProtoMessage()               {}
func (*SSHUploadPackResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *SSHUploadPackResponse) GetStdout() []byte {
	if m != nil {
		return m.Stdout
	}
	return nil
}

func (m *SSHUploadPackResponse) GetStderr() []byte {
	if m != nil {
		return m.Stderr
	}
	return nil
}

func (m *SSHUploadPackResponse) GetExitStatus() int32 {
	if m != nil {
		return m.ExitStatus
	}
	return 0
}

type SSHReceivePackRequest struct {
	Repository *Repository `protobuf:"bytes,1,opt,name=repository" json:"repository,omitempty"`
	Stdin      []byte      `protobuf:"bytes,2,opt,name=stdin,proto3" json:"stdin,omitempty"`
	GlId       string      `protobuf:"bytes,3,opt,name=gl_id,json=glId" json:"gl_id,omitempty"`
}

func (m *SSHReceivePackRequest) Reset()                    { *m = SSHReceivePackRequest{} }
func (m *SSHReceivePackRequest) String() string            { return proto.CompactTextString(m) }
func (*SSHReceivePackRequest) ProtoMessage()               {}
func (*SSHReceivePackRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *SSHReceivePackRequest) GetRepository() *Repository {
	if m != nil {
		return m.Repository
	}
	return nil
}

func (m *SSHReceivePackRequest) GetStdin() []byte {
	if m != nil {
		return m.Stdin
	}
	return nil
}

func (m *SSHReceivePackRequest) GetGlId() string {
	if m != nil {
		return m.GlId
	}
	return ""
}

type SSHReceivePackResponse struct {
	Stdout     []byte `protobuf:"bytes,1,opt,name=stdout,proto3" json:"stdout,omitempty"`
	Stderr     []byte `protobuf:"bytes,2,opt,name=stderr,proto3" json:"stderr,omitempty"`
	ExitStatus int32  `protobuf:"varint,3,opt,name=exit_status,json=exitStatus" json:"exit_status,omitempty"`
}

func (m *SSHReceivePackResponse) Reset()                    { *m = SSHReceivePackResponse{} }
func (m *SSHReceivePackResponse) String() string            { return proto.CompactTextString(m) }
func (*SSHReceivePackResponse) ProtoMessage()               {}
func (*SSHReceivePackResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *SSHReceivePackResponse) GetStdout() []byte {
	if m != nil {
		return m.Stdout
	}
	return nil
}

func (m *SSHReceivePackResponse) GetStderr() []byte {
	if m != nil {
		return m.Stderr
	}
	return nil
}

func (m *SSHReceivePackResponse) GetExitStatus() int32 {
	if m != nil {
		return m.ExitStatus
	}
	return 0
}

func init() {
	proto.RegisterType((*Repository)(nil), "gitssh.Repository")
	proto.RegisterType((*SSHUploadPackRequest)(nil), "gitssh.SSHUploadPackRequest")
	proto.RegisterType((*SSHUploadPackResponse)(nil), "gitssh.SSHUploadPackResponse")
	proto.RegisterType((*SSHReceivePackRequest)(nil), "gitssh.SSHReceivePackRequest")
	proto.RegisterType((*SSHReceivePackResponse)(nil), "gitssh.SSHReceivePackResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for SSHService service

type SSHServiceClient interface {
	SSHUploadPack(ctx context.Context, opts ...grpc.CallOption) (SSHService_SSHUploadPackClient, error)
	SSHReceivePack(ctx context.Context, opts ...grpc.CallOption) (SSHService_SSHReceivePackClient, error)
}

type sSHServiceClient struct {
	cc *grpc.ClientConn
}

func NewSSHServiceClient(cc *grpc.ClientConn) SSHServiceClient {
	return &sSHServiceClient{cc}
}

func (c *sSHServiceClient) SSHUploadPack(ctx context.Context, opts ...grpc.CallOption) (SSHService_SSHUploadPackClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_SSHService_serviceDesc.Streams[0], c.cc, "/gitssh.SSHService/SSHUploadPack", opts...)
	if err != nil {
		return nil, err
	}
	x := &sSHServiceSSHUploadPackClient{stream}
	return x, nil
}

type SSHService_SSHUploadPackClient interface {
	Send(*SSHUploadPackRequest) error
	Recv() (*SSHUploadPackResponse, error)
	grpc.ClientStream
}

type sSHServiceSSHUploadPackClient struct {
	grpc.ClientStream
}

func (x *sSHServiceSSHUploadPackClient) Send(m *SSHUploadPackRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *sSHServiceSSHUploadPackClient) Recv() (*SSHUploadPackResponse, error) {
	m := new(SSHUploadPackResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *sSHServiceClient) SSHReceivePack(ctx context.Context, opts ...grpc.CallOption) (SSHService_SSHReceivePackClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_SSHService_serviceDesc.Streams[1], c.cc, "/gitssh.SSHService/SSHReceivePack", opts...)
	if err != nil {
		return nil, err
	}
	x := &sSHServiceSSHReceivePackClient{stream}
	return x, nil
}

type SSHService_SSHReceivePackClient interface {
	Send(*SSHReceivePackRequest) error
	Recv() (*SSHReceivePackResponse, error)
	grpc.ClientStream
}

type sSHServiceSSHReceivePackClient struct {
	grpc.ClientStream
}

func (x *sSHServiceSSHReceivePackClient) Send(m *SSHReceivePackRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *sSHServiceSSHReceivePackClient) Recv() (*SSHReceivePackResponse, error) {
	m := new(SSHReceivePackResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for SSHService service

type SSHServiceServer interface {
	SSHUploadPack(SSHService_SSHUploadPackServer) error
	SSHReceivePack(SSHService_SSHReceivePackServer) error
}

func RegisterSSHServiceServer(s *grpc.Server, srv SSHServiceServer) {
	s.RegisterService(&_SSHService_serviceDesc, srv)
}

func _SSHService_SSHUploadPack_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(SSHServiceServer).SSHUploadPack(&sSHServiceSSHUploadPackServer{stream})
}

type SSHService_SSHUploadPackServer interface {
	Send(*SSHUploadPackResponse) error
	Recv() (*SSHUploadPackRequest, error)
	grpc.ServerStream
}

type sSHServiceSSHUploadPackServer struct {
	grpc.ServerStream
}

func (x *sSHServiceSSHUploadPackServer) Send(m *SSHUploadPackResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *sSHServiceSSHUploadPackServer) Recv() (*SSHUploadPackRequest, error) {
	m := new(SSHUploadPackRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _SSHService_SSHReceivePack_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(SSHServiceServer).SSHReceivePack(&sSHServiceSSHReceivePackServer{stream})
}

type SSHService_SSHReceivePackServer interface {
	Send(*SSHReceivePackResponse) error
	Recv() (*SSHReceivePackRequest, error)
	grpc.ServerStream
}

type sSHServiceSSHReceivePackServer struct {
	grpc.ServerStream
}

func (x *sSHServiceSSHReceivePackServer) Send(m *SSHReceivePackResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *sSHServiceSSHReceivePackServer) Recv() (*SSHReceivePackRequest, error) {
	m := new(SSHReceivePackRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _SSHService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "gitssh.SSHService",
	HandlerType: (*SSHServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SSHUploadPack",
			Handler:       _SSHService_SSHUploadPack_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "SSHReceivePack",
			Handler:       _SSHService_SSHReceivePack_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "ssh.proto",
}

func init() { proto.RegisterFile("ssh.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 303 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x92, 0x41, 0x4f, 0x3a, 0x31,
	0x10, 0xc5, 0xff, 0xfb, 0x17, 0x48, 0x76, 0x40, 0x0f, 0x23, 0x12, 0x42, 0x50, 0x49, 0x4f, 0x9c,
	0x88, 0xc1, 0xbb, 0x67, 0xbc, 0x99, 0x36, 0x9c, 0xb1, 0xee, 0x4e, 0xd8, 0x46, 0xa4, 0xb5, 0x53,
	0x88, 0x7e, 0x32, 0xbf, 0x9e, 0xb1, 0xac, 0xb2, 0xa0, 0x1c, 0xb9, 0x75, 0xde, 0xb4, 0xef, 0xd7,
	0x37, 0x2d, 0xa4, 0xcc, 0xc5, 0xc8, 0x79, 0x1b, 0x2c, 0x36, 0xe6, 0x26, 0x30, 0x17, 0xe2, 0x0e,
	0x40, 0x92, 0xb3, 0x6c, 0x82, 0xf5, 0xef, 0x88, 0x50, 0x73, 0x3a, 0x14, 0xdd, 0x64, 0x90, 0x0c,
	0x53, 0x19, 0xd7, 0xd8, 0x87, 0x74, 0xa9, 0x5f, 0x88, 0x9d, 0xce, 0xa8, 0xfb, 0x3f, 0x36, 0xb6,
	0x82, 0x78, 0x84, 0xb6, 0x52, 0x93, 0xa9, 0x5b, 0x58, 0x9d, 0x3f, 0xe8, 0xec, 0x59, 0xd2, 0xeb,
	0x8a, 0x38, 0xe0, 0x18, 0xc0, 0xff, 0xf8, 0x46, 0xbf, 0xe6, 0x18, 0x47, 0x1b, 0xe8, 0x68, 0x4b,
	0x94, 0x95, 0x5d, 0xd8, 0x86, 0x3a, 0x87, 0xdc, 0x2c, 0x23, 0xa5, 0x25, 0x37, 0x85, 0x28, 0xe0,
	0x62, 0x8f, 0xc0, 0xce, 0x2e, 0x99, 0xb0, 0x03, 0x0d, 0x0e, 0xb9, 0x5d, 0x85, 0x68, 0xdf, 0x92,
	0x65, 0x55, 0xea, 0xe4, 0x7d, 0xe9, 0x53, 0x56, 0x78, 0x0d, 0x4d, 0x7a, 0x33, 0x61, 0xc6, 0x41,
	0x87, 0x15, 0x77, 0x4f, 0x06, 0xc9, 0xb0, 0x2e, 0xe1, 0x4b, 0x52, 0x51, 0x11, 0xeb, 0x48, 0x92,
	0x94, 0x91, 0x59, 0xd3, 0x51, 0xc2, 0xe0, 0x39, 0xd4, 0xe7, 0x8b, 0x99, 0xc9, 0x23, 0x3d, 0x95,
	0xb5, 0xf9, 0xe2, 0x3e, 0x17, 0x06, 0x3a, 0xfb, 0xdc, 0x23, 0x45, 0x1c, 0x7f, 0x24, 0x00, 0x4a,
	0x4d, 0x14, 0xf9, 0xb5, 0xc9, 0x08, 0x25, 0x9c, 0xee, 0xcc, 0x16, 0xfb, 0xdf, 0xa9, 0xfe, 0x7a,
	0xd4, 0xde, 0xe5, 0x81, 0xee, 0xe6, 0xb6, 0xe2, 0xdf, 0x30, 0xb9, 0x49, 0x70, 0x0a, 0x67, 0xbb,
	0x69, 0xb0, 0x7a, 0xec, 0xf7, 0x74, 0x7b, 0x57, 0x87, 0xda, 0x55, 0xdb, 0xa7, 0x46, 0xfc, 0xb7,
	0xb7, 0x9f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x6b, 0xa2, 0x8a, 0xd2, 0xc4, 0x02, 0x00, 0x00,
}
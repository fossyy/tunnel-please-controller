package server

import (
	"context"
	"log"
	mathrand "math/rand"
	"net"
	"strings"
	"time"

	"git.fossy.my.id/bagas/tunnel-please-controller/db/sqlc/repository"
	identifier "git.fossy.my.id/bagas/tunnel-please-grpc/gen"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Server struct {
	Database *repository.Queries
	identifier.UnimplementedIdentityServer
}

func (s *Server) Get(ctx context.Context, request *identifier.IdentifierRequest) (*identifier.IdentifierResponse, error) {
	parse, err := uuid.Parse(request.GetId())
	if err != nil {
		return nil, err
	}
	data, err := s.Database.GetIdentifierById(ctx, parse)
	if err != nil {
		return nil, err
	}
	return &identifier.IdentifierResponse{
		Id:   data.ID.String(),
		Slug: data.Slug,
	}, nil
}

func (s *Server) Create(ctx context.Context, request *emptypb.Empty) (*identifier.IdentifierResponse, error) {
	createIdentifier, err := s.Database.CreateIdentifier(ctx, GenerateRandomString(32))
	if err != nil {
		return nil, err
	}
	return &identifier.IdentifierResponse{
		Id:   createIdentifier.ID.String(),
		Slug: createIdentifier.Slug,
	}, nil
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	seededRand := mathrand.New(mathrand.NewSource(time.Now().UnixNano() + int64(mathrand.Intn(9999))))
	var result strings.Builder
	for i := 0; i < length; i++ {
		randomIndex := seededRand.Intn(len(charset))
		result.WriteString(string(charset[randomIndex]))
	}
	return result.String()
}

func New(database *repository.Queries) *Server {
	return &Server{Database: database}
}

func (s *Server) ListenAndServe(Addr string) error {
	listener, err := net.Listen("tcp", Addr)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	reflection.Register(grpcServer)

	identifier.RegisterIdentityServer(grpcServer, s)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
	return nil
}

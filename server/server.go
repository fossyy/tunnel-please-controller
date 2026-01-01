package server

import (
	"context"
	"log"
	mathrand "math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"git.fossy.my.id/bagas/tunnel-please-controller/db/sqlc/repository"
	proto "git.fossy.my.id/bagas/tunnel-please-grpc/gen"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Server struct {
	Database   *repository.Queries
	Subscriber []chan *proto.Event
	mu         sync.RWMutex
	proto.UnimplementedIdentityServer
	proto.UnimplementedEventServiceServer
	proto.UnimplementedSlugServer
}

func (s *Server) ChangeSlug(ctx context.Context, request *proto.ChangeSlugRequest) (*proto.ChangeSlugResponse, error) {
	s.NotifyAllSubscriber(&proto.Event{
		Type:            proto.EventType_SLUG_CHANGE,
		TimestampUnixMs: time.Now().Unix(),
		Data: &proto.Event_DataEvent{DataEvent: &proto.SlugChangeEvent{
			Old: request.GetOld(),
			New: request.GetNew(),
		}},
	})
	return &proto.ChangeSlugResponse{}, nil
}

func (s *Server) Subscribe(request *emptypb.Empty, g grpc.ServerStreamingServer[proto.Event]) error {
	sr := make(chan *proto.Event)
	s.AddSubscriberChan(sr)
	defer s.RemoveSubscriberChan(sr)

	for ev := range sr {
		if err := g.Send(ev); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) NotifyAllSubscriber(event *proto.Event) {
	for _, subs := range s.Subscriber {
		subs <- event
	}
}

func (s *Server) AddSubscriberChan(event chan *proto.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Subscriber = append(s.Subscriber, event)
}

func (s *Server) RemoveSubscriberChan(ch chan *proto.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Subscriber) == 0 || ch == nil {
		return
	}
	newSubs := s.Subscriber[:0]
	for _, c := range s.Subscriber {
		if c == ch {
			continue
		}
		newSubs = append(newSubs, c)
	}
	s.Subscriber = newSubs

	close(ch)
}

func (s *Server) Get(ctx context.Context, request *proto.IdentifierRequest) (*proto.IdentifierResponse, error) {
	parse, err := uuid.Parse(request.GetId())
	if err != nil {
		return nil, err
	}
	data, err := s.Database.GetIdentifierById(ctx, parse)
	if err != nil {
		return nil, err
	}
	return &proto.IdentifierResponse{
		Id:   data.ID.String(),
		Slug: data.Slug,
	}, nil
}

func (s *Server) Create(ctx context.Context, request *emptypb.Empty) (*proto.IdentifierResponse, error) {
	createIdentifier, err := s.Database.CreateIdentifier(ctx, GenerateRandomString(32))
	if err != nil {
		return nil, err
	}
	return &proto.IdentifierResponse{
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
	return &Server{Database: database, Subscriber: make([]chan *proto.Event, 0)}
}

func (s *Server) ListenAndServe(Addr string) error {
	listener, err := net.Listen("tcp", Addr)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	reflection.Register(grpcServer)

	proto.RegisterIdentityServer(grpcServer, s)
	proto.RegisterEventServiceServer(grpcServer, s)
	proto.RegisterSlugServer(grpcServer, s)

	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
	return nil
}

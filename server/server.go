package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"git.fossy.my.id/bagas/tunnel-please-controller/db/sqlc/repository"
	proto "git.fossy.my.id/bagas/tunnel-please-grpc/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type Subscriber struct {
	client     chan *proto.Client
	controller chan *proto.Controller
	done       chan struct{}
	closeOnce  sync.Once
}
type Server struct {
	Database    *repository.Queries
	Subscribers map[string]*Subscriber
	mu          *sync.RWMutex
	authToken   string
	proto.UnimplementedEventServiceServer
	proto.UnimplementedSlugChangeServer
}

func New(database *repository.Queries, authToken string) *Server {
	return &Server{
		Database:    database,
		Subscribers: make(map[string]*Subscriber),
		mu:          new(sync.RWMutex),
		authToken:   authToken,
	}
}

func (s *Server) Subscribe(event grpc.BidiStreamingServer[proto.Client, proto.Controller]) error {
	ctx := event.Context()
	recv, err := event.Recv()
	if err != nil {
		return err
	}
	if recv == nil {
		return status.Error(codes.InvalidArgument, "missing authentication event")
	}
	if recv.GetType() != proto.EventType_AUTHENTICATION {
		return status.Errorf(codes.InvalidArgument, "invalid event type: %s", recv.GetType())
	}
	payload, ok := recv.GetPayload().(*proto.Client_AuthEvent)
	if !ok || payload == nil || payload.AuthEvent == nil {
		return status.Error(codes.InvalidArgument, "missing auth payload")
	}
	identity := payload.AuthEvent.Identity
	if identity == "" {
		return status.Error(codes.InvalidArgument, "missing identity")
	}
	token := payload.AuthEvent.AuthToken
	if token != s.authToken {
		return status.Error(codes.Unauthenticated, "invalid auth token")
	}

	log.Printf("Client %s authenticated successfully", identity)

	requestChan := &Subscriber{
		client:     make(chan *proto.Client, 10),
		controller: make(chan *proto.Controller, 10),
		done:       make(chan struct{}),
	}

	if err = s.AddEventSubscriber(identity, requestChan); err != nil {
		return status.Error(codes.AlreadyExists, err.Error())
	}
	defer func() {
		s.RemoveEventSubscriber(identity)
		log.Printf("Client %s disconnected and unsubscribed", identity)
	}()

	return processEventStream(ctx, requestChan, event)
}

func processEventStream(ctx context.Context, requestChan *Subscriber, event grpc.BidiStreamingServer[proto.Client, proto.Controller]) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-requestChan.done:
			return nil
		case request, ok := <-requestChan.controller:
			if !ok {
				return nil
			}
			if request == nil {
				continue
			}
			log.Printf("Received event request: %v", request)
			switch request.GetType() {
			case proto.EventType_SLUG_CHANGE:
				payload, ok := request.GetPayload().(*proto.Controller_SlugEvent)
				if !ok || payload == nil || payload.SlugEvent == nil {
					log.Printf("invalid slug change payload")
					continue
				}
				slugEvent := payload.SlugEvent
				log.Printf("Processing slug change event: old=%s, new=%s", slugEvent.Old, slugEvent.New)
				if err := event.Send(request); err != nil {
					return err
				}
				recv, err := event.Recv()
				if err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case requestChan.client <- recv:
				}
				log.Printf("Received slug change event: %v", recv)
			default:
				log.Printf("Unknown event type: %v", request.GetType())
			}
		}
	}
}

func (s *Server) AddEventSubscriber(identity string, req *Subscriber) error {
	if identity == "" || req == nil {
		return fmt.Errorf("invalid subscriber")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exist := s.Subscribers[identity]; exist {
		return fmt.Errorf("identity %s already subscribed", identity)
	}
	s.Subscribers[identity] = req
	return nil
}

func (s *Server) RemoveEventSubscriber(identity string) {
	s.mu.Lock()
	sub := s.Subscribers[identity]
	delete(s.Subscribers, identity)
	s.mu.Unlock()

	if sub != nil {
		sub.closeOnce.Do(func() { close(sub.done) })
	}
}

func (s *Server) GetEventSubscriber(identity string) (*Subscriber, error) {
	if identity == "" {
		return nil, status.Error(codes.InvalidArgument, "missing identity")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.Subscribers[identity]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "identity %s not subscribed", identity)
	}
	return req, nil
}

func (s *Server) RequestChangeSlug(ctx context.Context, request *proto.ChangeSlugRequest) (*proto.ChangeSlugResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	if request.GetNode() == "" {
		return nil, status.Error(codes.InvalidArgument, "node is required")
	}
	if request.Old == "" || request.New == "" {
		return nil, status.Error(codes.InvalidArgument, "old and new slugs are required")
	}

	subscriber, err := s.GetEventSubscriber(request.GetNode())
	if err != nil {
		return nil, err
	}

	controllerMsg := &proto.Controller{
		Type: proto.EventType_SLUG_CHANGE,
		Payload: &proto.Controller_SlugEvent{
			SlugEvent: &proto.SlugChangeEvent{
				Old: request.Old,
				New: request.New,
			},
		},
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-subscriber.done:
		return nil, status.Error(codes.Canceled, "subscriber removed")
	case subscriber.controller <- controllerMsg:
	}

	var resp *proto.Client
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-subscriber.done:
		return nil, status.Error(codes.Canceled, "subscriber removed")
	case resp = <-subscriber.client:
	}
	if resp == nil {
		return nil, status.Error(codes.FailedPrecondition, "empty response from client")
	}
	response, ok := resp.Payload.(*proto.Client_SlugEventResponse)
	if !ok || response == nil || response.SlugEventResponse == nil {
		return nil, status.Error(codes.FailedPrecondition, "invalid slug response payload")
	}
	return (*proto.ChangeSlugResponse)(response.SlugEventResponse), nil
}

func (s *Server) ListenAndServe(Addr string) error {
	listener, err := net.Listen("tcp", Addr)
	if err != nil {
		return err
	}

	kaParams := keepalive.ServerParameters{
		MaxConnectionIdle:     0,
		MaxConnectionAge:      0,
		MaxConnectionAgeGrace: 0,
		Time:                  30 * time.Second,
		Timeout:               10 * time.Second,
	}
	kaPolicy := keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	}

	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(kaParams),
		grpc.KeepaliveEnforcementPolicy(kaPolicy),
	)
	reflection.Register(grpcServer)

	proto.RegisterSlugChangeServer(grpcServer, s)
	proto.RegisterEventServiceServer(grpcServer, s)

	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	return grpcServer.Serve(listener)
}

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"

	"git.fossy.my.id/bagas/tunnel-please-controller/db/sqlc/repository"
	"git.fossy.my.id/bagas/tunnel-please-controller/internal/config"
	proto "git.fossy.my.id/bagas/tunnel-please-grpc/gen"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	defaultSubscriberResponseWait = 5 * time.Second
	jwkRegisterTimeout            = 5 * time.Second
)

type Subscriber struct {
	node      chan *proto.Node
	events    chan *proto.Events
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
}
type Server struct {
	Database    *repository.Queries
	Subscribers map[string]*Subscriber
	mu          *sync.RWMutex
	authToken   string
	jwkCache    *jwk.Cache
	proto.UnimplementedEventServiceServer
	proto.UnimplementedUserServiceServer
}

func New(database *repository.Queries, authToken string, jwkCache *jwk.Cache) *Server {
	return &Server{
		Database:    database,
		Subscribers: make(map[string]*Subscriber),
		mu:          new(sync.RWMutex),
		authToken:   authToken,
		jwkCache:    jwkCache,
	}
}

func (s *Server) Check(ctx context.Context, request *proto.CheckRequest) (*proto.CheckResponse, error) {
	user, err := s.Database.GetVerifiedEmailBySSHIdentifier(ctx, request.GetAuthToken())
	if err != nil || user == "" {
		return &proto.CheckResponse{
			Response: proto.AuthorizationResponse_MESSAGE_TYPE_UNAUTHORIZED,
			User:     "",
		}, err
	}

	return &proto.CheckResponse{
		Response: proto.AuthorizationResponse_MESSAGE_TYPE_AUTHORIZED,
		User:     user,
	}, nil
}

func (s *Server) Subscribe(event grpc.BidiStreamingServer[proto.Node, proto.Events]) error {
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
	payload, ok := recv.GetPayload().(*proto.Node_AuthEvent)
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
		node:   make(chan *proto.Node, 10),
		events: make(chan *proto.Events, 10),
		done:   make(chan struct{}),
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

func processEventStream(ctx context.Context, requestChan *Subscriber, event grpc.BidiStreamingServer[proto.Node, proto.Events]) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-requestChan.done:
			return nil
		case request, ok := <-requestChan.events:
			if !ok {
				return nil
			}
			if request == nil {
				continue
			}
			log.Printf("Received event request: %v", request)
			switch request.GetType() {
			case proto.EventType_SLUG_CHANGE:
				payload, ok := request.GetPayload().(*proto.Events_SlugEvent)
				if !ok || payload == nil || payload.SlugEvent == nil {
					log.Printf("invalid slug change payload")
					continue
				}
				slugEvent := payload.SlugEvent
				log.Printf("Processing slug change event: old=%s, new=%s", slugEvent.Old, slugEvent.New)
				if err := event.Send(request); err != nil {
					return err
				}
				recv, err := recvClientWithTimeout(ctx, requestChan.done, event, defaultSubscriberResponseWait)
				if err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case requestChan.node <- recv:
				}
				log.Printf("Received slug change event: %v", recv)
			case proto.EventType_GET_SESSIONS:
				log.Printf("Processing session event")
				if err := event.Send(request); err != nil {
					return err
				}
				recv, err := recvClientWithTimeout(ctx, requestChan.done, event, defaultSubscriberResponseWait)
				if err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case requestChan.node <- recv:
				}
				log.Printf("Received SESSIONS  event: %v", recv)
			default:
				log.Printf("Unknown event type: %v", request.GetType())
			}
		}
	}
}

func recvClientWithTimeout(ctx context.Context, done <-chan struct{}, event grpc.BidiStreamingServer[proto.Node, proto.Events], timeout time.Duration) (*proto.Node, error) {
	respCh := make(chan *proto.Node, 1)
	errCh := make(chan error, 1)

	go func() {
		recv, err := event.Recv()
		if err != nil {
			errCh <- err
			return
		}
		respCh <- recv
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return nil, status.Error(codes.Canceled, "subscriber removed")
	case err := <-errCh:
		return nil, err
	case <-timer.C:
		return nil, status.Error(codes.DeadlineExceeded, "client response timeout")
	case recv := <-respCh:
		return recv, nil
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

type SubscriberResult struct {
	Identity string
	Response *proto.Node
	Err      error
}

func (s *Server) notifyAllSubscriber(ctx context.Context, recvChan <-chan *proto.Events, resultChan chan<- []SubscriberResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case controllerReq, ok := <-recvChan:
			if !ok {
				return
			}
			if controllerReq == nil {
				continue
			}

			s.mu.RLock()
			subs := make(map[string]*Subscriber, len(s.Subscribers))
			for id, sub := range s.Subscribers {
				subs[id] = sub
			}
			s.mu.RUnlock()
			results := make([]SubscriberResult, 0, len(subs))
			for id, sub := range subs {
				select {
				case <-ctx.Done():
					return
				case <-sub.done:
					results = append(results, SubscriberResult{Identity: id, Err: status.Error(codes.Canceled, "subscriber removed")})
					continue
				case sub.events <- controllerReq:
				default:
					results = append(results, SubscriberResult{Identity: id, Err: status.Error(codes.Unavailable, "controller channel blocked")})
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-sub.done:
					results = append(results, SubscriberResult{Identity: id, Err: status.Error(codes.Canceled, "subscriber removed")})
				case resp, ok := <-sub.node:
					if !ok {
						results = append(results, SubscriberResult{Identity: id, Err: status.Error(codes.FailedPrecondition, "client channel closed")})
						continue
					}
					results = append(results, SubscriberResult{Identity: id, Response: resp})
				}
			}
			select {
			case <-ctx.Done():
				return
			case resultChan <- results:
			}
		}
	}
}

type Slug struct {
	Old string `json:"old"`
	New string `json:"new"`
}

func (s *Server) StartAPI(ctx context.Context, Addr string) error {
	handler := http.NewServeMux()
	httpServer := http.Server{
		Addr:         Addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	jwkURL := config.Getenv("JWKS_URL", "")
	if jwkURL != "" {
		registerCtx, cancel := context.WithTimeout(ctx, jwkRegisterTimeout)
		defer cancel()

		if err := s.jwkCache.Register(registerCtx, jwkURL); err != nil {
			return fmt.Errorf("failed to register jwk cache: %w", err)
		}
	}
	handler.HandleFunc("PATCH /api/session/{node}", func(writer http.ResponseWriter, request *http.Request) {
		writeError := func(status int, msg string) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(status)
			_ = json.NewEncoder(writer).Encode(map[string]string{"error": msg})
		}

		var token jwt.Token
		var err error
		if jwkURL != "" {
			keyset, err := s.jwkCache.Lookup(request.Context(), jwkURL)
			if err != nil {
				log.Printf("jwks lookup failed: %v", err)
				writeError(http.StatusBadGateway, "unable to fetch jwks")
				return
			}

			token, err = jwt.ParseRequest(request, jwt.WithKeySet(keyset))
			if err != nil {
				log.Printf("jwt parse failed: %v", err)
				writeError(http.StatusUnauthorized, "invalid or expired token")
				return
			}
		} else {
			token, err = jwt.ParseRequest(request, jwt.WithVerify(false))
			if err != nil {
				log.Printf("jwt parse failed (no verification): %v", err)
				writeError(http.StatusBadRequest, "invalid token")
				return
			}
		}

		var email string
		err = token.Get("email", &email)
		if err != nil {
			log.Printf("email claim not found: %v", err)
			writeError(http.StatusBadRequest, "missing email claim in token")
			return
		}
		if email == "" {
			writeError(http.StatusBadRequest, "empty email claim in token")
			return
		}
		node := request.PathValue("node")
		if node == "" {
			writeError(http.StatusBadRequest, "no node specified")
			return
		}
		var slug *Slug
		if err := json.NewDecoder(request.Body).Decode(&slug); err != nil {
			writeError(http.StatusBadRequest, "invalid request body")
			return
		}
		subscriber, err := s.GetEventSubscriber(node)
		if err != nil {
			writeError(http.StatusBadRequest, "no node found")
			return
		}

		subscriber.events <- &proto.Events{
			Type: proto.EventType_SLUG_CHANGE,
			Payload: &proto.Events_SlugEvent{
				SlugEvent: &proto.SlugChangeEvent{
					User: email,
					Old:  slug.Old,
					New:  slug.New,
				},
			},
		}

		select {
		case response := <-subscriber.node:
			resp, ok := response.Payload.(*proto.Node_SlugEventResponse)
			if !ok {
				writeError(http.StatusInternalServerError, "received an unexpected response from the node")
				return
			}
			if !resp.SlugEventResponse.Success {
				writeError(http.StatusBadRequest, resp.SlugEventResponse.Message)
				return
			}
			log.Printf("Received slug change response: %v", response)
			writer.WriteHeader(http.StatusNoContent)
		case <-request.Context().Done():
		}
	})

	handler.HandleFunc("/api/sessions", func(writer http.ResponseWriter, request *http.Request) {
		writeError := func(status int, msg string) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(status)
			_ = json.NewEncoder(writer).Encode(map[string]string{"error": msg})
		}

		var token jwt.Token
		var err error
		if jwkURL != "" {
			keyset, err := s.jwkCache.Lookup(request.Context(), jwkURL)
			if err != nil {
				log.Printf("jwks lookup failed: %v", err)
				writeError(http.StatusBadGateway, "unable to fetch jwks")
				return
			}

			token, err = jwt.ParseRequest(request, jwt.WithKeySet(keyset))
			if err != nil {
				log.Printf("jwt parse failed: %v", err)
				writeError(http.StatusUnauthorized, "invalid or expired token")
				return
			}
		} else {
			token, err = jwt.ParseRequest(request, jwt.WithVerify(false))
			if err != nil {
				log.Printf("jwt parse failed (no verification): %v", err)
				writeError(http.StatusBadRequest, "invalid token")
				return
			}
		}

		var email string
		err = token.Get("email", &email)
		if err != nil {
			log.Printf("email claim not found: %v", err)
			writeError(http.StatusBadRequest, "missing email claim in token")
			return
		}
		if email == "" {
			writeError(http.StatusBadRequest, "empty email claim in token")
			return
		}

		results := s.broadcastAndCollect(request.Context(), func(ctx context.Context, subscriber *Subscriber) (interface{}, bool) {
			receive, err := s.sendAndReceive(ctx, subscriber, &proto.Events{
				Type: proto.EventType_GET_SESSIONS,
				Payload: &proto.Events_GetSessionsEvent{
					GetSessionsEvent: &proto.GetSessionsEvent{
						Identity: email,
					},
				},
			}, defaultSubscriberResponseWait)
			if err != nil {
				log.Printf("get sessions request failed: %v", err)
				return nil, false
			}
			if receive == nil {
				log.Printf("get sessions request returned nil response")
				return nil, false
			}
			payload, ok := receive.Payload.(*proto.Node_GetSessionsEvent)
			if !ok || payload == nil || payload.GetSessionsEvent == nil {
				log.Printf("unexpected get sessions payload type: %T", receive.Payload)
				return nil, false
			}
			return payload.GetSessionsEvent.Details, true
		})

		flatten := flattenInterfaces(results)

		writer.Header().Set("Content-Type", "application/json")

		if len(flatten) == 0 {
			_, err := writer.Write([]byte("[]"))
			if err != nil {
				log.Printf("write empty sessions response failed: %v", err)
			}
			return
		}

		marshal, err := json.Marshal(flatten)
		if err != nil {
			log.Printf("marshal sessions failed: %v", err)
			writeError(http.StatusInternalServerError, "failed to marshal sessions")
			return
		}
		_, err = writer.Write(marshal)
		if err != nil {
			log.Printf("write sessions response failed: %v", err)
			return
		}
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func flattenInterfaces(values []interface{}) []interface{} {
	var flat []interface{}
	for _, v := range values {
		if v == nil {
			continue
		}
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Slice {
			for i := 0; i < rv.Len(); i++ {
				flat = append(flat, rv.Index(i).Interface())
			}
			continue
		}
		flat = append(flat, v)
	}
	return flat
}

func (s *Server) StartController(ctx context.Context, Addr string) error {
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

	proto.RegisterEventServiceServer(grpcServer, s)
	proto.RegisterUserServiceServer(grpcServer, s)

	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- grpcServer.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		grpcServer.GracefulStop()
		err := <-serveErr
		if err != nil {
			return err
		}
		return ctx.Err()
	case err := <-serveErr:
		return err
	}
}

func (s *Server) sendAndReceive(ctx context.Context, sub *Subscriber, req *proto.Events, wait time.Duration) (*proto.Node, error) {
	if sub == nil || req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing subscriber or request")
	}

	sub.mu.Lock()
	defer sub.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-sub.done:
		return nil, status.Error(codes.Canceled, "subscriber removed")
	case sub.events <- req:
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-sub.done:
		return nil, status.Error(codes.Canceled, "subscriber removed")
	case <-timer.C:
		return nil, status.Error(codes.DeadlineExceeded, "subscriber response timeout")
	case resp, ok := <-sub.node:
		if !ok {
			return nil, status.Error(codes.FailedPrecondition, "client channel closed")
		}
		return resp, nil
	}
}

func (s *Server) snapshotSubscribers() []*Subscriber {
	s.mu.RLock()
	defer s.mu.RUnlock()
	subs := make([]*Subscriber, 0, len(s.Subscribers))
	for _, sub := range s.Subscribers {
		subs = append(subs, sub)
	}
	return subs
}

func (s *Server) broadcastAndCollect(ctx context.Context, worker func(context.Context, *Subscriber) (interface{}, bool)) []interface{} {
	subs := s.snapshotSubscribers()
	if len(subs) == 0 {
		return nil
	}

	resultsCh := make(chan interface{}, len(subs))
	var wg sync.WaitGroup
	for _, sub := range subs {
		wg.Add(1)
		go func(subscriber *Subscriber) {
			defer wg.Done()
			if val, ok := worker(ctx, subscriber); ok {
				resultsCh <- val
			}
		}(sub)
	}

	wg.Wait()
	close(resultsCh)

	var results []interface{}
	for val := range resultsCh {
		results = append(results, val)
	}
	return results
}

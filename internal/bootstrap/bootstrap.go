package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"git.fossy.my.id/bagas/tunnel-please-controller/internal/config"
	"git.fossy.my.id/bagas/tunnel-please-controller/internal/db/sqlc/repository"
	"git.fossy.my.id/bagas/tunnel-please-controller/internal/server"
	"github.com/jackc/pgx/v5"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type bootstrap struct {
	config     config.Config
	errChan    chan error
	signalChan chan os.Signal
}

type Bootstrap interface {
	Run() error
}

func New(config config.Config) Bootstrap {
	errChan := make(chan error, 5)
	signalChan := make(chan os.Signal, 1)
	return &bootstrap{
		config:     config,
		errChan:    errChan,
		signalChan: signalChan,
	}
}

func (b *bootstrap) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signal.Notify(b.signalChan, os.Interrupt, syscall.SIGTERM)

	dbURL := b.config.DatabaseURL()
	repo, err := startDatabase(ctx, dbURL)
	if err != nil {
		return err
	}

	client := httprc.NewClient()
	jwkCache, err := jwk.NewCache(ctx, client)
	if err != nil {
		return err
	}
	s := server.New(repo, jwkCache, b.config)

	b.errChan = make(chan error, 2)

	go func() {
		if err = s.StartAPI(ctx, b.config.ApiAddr()); err != nil && !errors.Is(err, context.Canceled) {
			b.errChan <- err
		}
	}()

	go func() {
		if err = s.StartController(ctx, b.config.ControllerAddr()); err != nil && !errors.Is(err, context.Canceled) {
			b.errChan <- err
		}
	}()

	select {
	case err = <-b.errChan:
		return fmt.Errorf("service error: %w", err)
	case sig := <-b.signalChan:
		log.Printf("Received signal %s, initiating graceful shutdown", sig)
		cancel()
		return nil
	}
}

func startDatabase(ctx context.Context, dbURL string) (*repository.Queries, error) {
	connect, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return nil, err
	}

	defer func(connect *pgx.Conn, ctx context.Context) {
		err = connect.Close(ctx)
		if err != nil {
			panic(err)
		}
	}(connect, ctx)

	return repository.New(connect), nil
}

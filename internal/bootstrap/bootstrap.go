package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"git.fossy.my.id/bagas/tunnel-please-controller/internal/config"
	"git.fossy.my.id/bagas/tunnel-please-controller/internal/db/sqlc/repository"
	"git.fossy.my.id/bagas/tunnel-please-controller/internal/server"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
	return &bootstrap{
		config:     config,
		errChan:    make(chan error, 2),
		signalChan: make(chan os.Signal, 1),
	}
}

func (b *bootstrap) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signal.Notify(b.signalChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(b.signalChan)

	repo, pool, err := startDatabase(ctx, b.config.DatabaseURL())
	if err != nil {
		return err
	}

	client := httprc.NewClient()
	jwkCache, err := jwk.NewCache(ctx, client)
	if err != nil {
		pool.Close()
		return err
	}
	s := server.New(repo, jwkCache, b.config)

	var wg sync.WaitGroup
	wg.Go(func() {
		if err := s.StartAPI(ctx, b.config.ApiAddr()); err != nil && !errors.Is(err, context.Canceled) {
			b.errChan <- err
		}
	})
	wg.Go(func() {
		if err := s.StartController(ctx, b.config.ControllerAddr()); err != nil && !errors.Is(err, context.Canceled) {
			b.errChan <- err
		}
	})

	select {
	case err := <-b.errChan:
		cancel()
		wg.Wait()
		pool.Close()
		return fmt.Errorf("service error: %w", err)
	case sig := <-b.signalChan:
		log.Printf("Received signal %s, initiating graceful shutdown", sig)
		cancel()
		wg.Wait()
		pool.Close()
		return nil
	}
}

func startDatabase(ctx context.Context, dbURL string) (*repository.Queries, *pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, nil, err
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, err
	}
	if err = checkSchema(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, err
	}
	return repository.New(pool), pool, nil
}

var requiredTables = []string{"user", "account", "refresh_token"}
var requiredIndexes = []string{"account_provider_account_unique", "refresh_token_hash_unique"}

func checkSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, table := range requiredTables {
		identifier := "public." + pgx.Identifier{table}.Sanitize()
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", identifier).Scan(&exists); err != nil {
			return fmt.Errorf("schema check: %w", err)
		}
		if !exists {
			return fmt.Errorf("schema check: table %s is missing; apply the migrations in internal/db/sqlc/migrations with your migration tool before starting", identifier)
		}
	}
	for _, index := range requiredIndexes {
		identifier := "public." + pgx.Identifier{index}.Sanitize()
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", identifier).Scan(&exists); err != nil {
			return fmt.Errorf("schema check: %w", err)
		}
		if !exists {
			return fmt.Errorf("schema check: index %s is missing; apply the migrations in internal/db/sqlc/migrations with your migration tool before starting", identifier)
		}
	}
	return nil
}

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"git.fossy.my.id/bagas/tunnel-please-controller/db/sqlc/repository"
	"git.fossy.my.id/bagas/tunnel-please-controller/server"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func main() {
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(".env"); err != nil {
			log.Printf("Warning: Failed to load .env file: %s", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	controllerAddr := getenv("CONTROLLER_ADDR", ":8080")
	apiAddr := getenv("API_ADDR", ":8081")
	authToken := getenv("AUTH_TOKEN", "")
	if authToken == "" {
		authToken = generateAuthToken()
		log.Printf("No AUTH_TOKEN provided. Generated token: %s", authToken)
	}

	connect, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		panic(err)
		return
	}
	defer func(connect *pgx.Conn, ctx context.Context) {
		err := connect.Close(ctx)
		if err != nil {
			panic(err)
		}
	}(connect, ctx)

	repo := repository.New(connect)
	client := httprc.NewClient()
	jwkCache, err := jwk.NewCache(ctx, client)
	if err != nil {
		log.Printf("failed to initialize jwk cache : %s", err)
	}
	s := server.New(repo, authToken, jwkCache)

	log.Printf("Listening controller on %s", controllerAddr)
	log.Printf("Listening api on %s", apiAddr)

	errCh := make(chan error, 2)

	go func() {
		if err := s.StartAPI(ctx, apiAddr); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()

	go func() {
		if err := s.StartController(ctx, controllerAddr); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutting down: %v", ctx.Err())
	case err := <-errCh:
		log.Fatalf("server error: %v", err)
	}
}

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

func generateAuthToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

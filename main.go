package main

import (
	"context"
	"log"
	"os"

	"git.fossy.my.id/bagas/tunnel-please-controller/db/sqlc/repository"
	"git.fossy.my.id/bagas/tunnel-please-controller/server"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
)

func main() {
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(".env"); err != nil {
			log.Printf("Warning: Failed to load .env file: %s", err)
		}
	}

	ctx := context.Background()

	connect, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
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
	s := server.New(repo)

	log.Printf("Listening on :8080\n")
	err = s.ListenAndServe(":8080")
	if err != nil {
		panic(err)
		return
	}
}

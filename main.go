package main

import (
	"log"
	"os"

	"git.fossy.my.id/bagas/tunnel-please-controller/internal/bootstrap"
	"git.fossy.my.id/bagas/tunnel-please-controller/internal/config"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	conf, err := config.MustLoad()
	if err != nil {
		log.Fatalf("Config load error: %v", err)
	}

	boot := bootstrap.New(conf)

	if err = boot.Run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

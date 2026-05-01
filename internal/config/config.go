package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type config struct {
	databaseUrl    string
	controllerAddr string
	apiAddr        string
	authToken      string
	jwksUrl        string
}

type Config interface {
	DatabaseURL() string
	ControllerAddr() string
	ApiAddr() string
	AuthToken() string
	JwksURL() string
}

func (c *config) DatabaseURL() string    { return c.databaseUrl }
func (c *config) ControllerAddr() string { return c.controllerAddr }
func (c *config) ApiAddr() string        { return c.apiAddr }
func (c *config) AuthToken() string      { return c.authToken }
func (c *config) JwksURL() string        { return c.jwksUrl }

func MustLoad() (Config, error) {
	if err := loadEnvFile(); err != nil {
		return nil, err
	}

	cfg, err := parse()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func loadEnvFile() error {
	if _, err := os.Stat(".env"); err == nil {
		return godotenv.Load(".env")
	}
	return nil
}

func parse() (*config, error) {
	databaseUrl := getenv("DATABASE_URL", "")
	if databaseUrl == "" {
		return nil, errors.New("DATABASE_URL environment variable not set")
	}
	controllerAddr := getenv("CONTROLLER_ADDR", ":8080")
	apiAddr := getenv("API_ADDR", ":8081")
	authToken := getenv("AUTH_TOKEN", "")
	if authToken == "" {
		authToken = generateAuthToken()
		log.Printf("No AUTH_TOKEN provided. Generated token: %s", authToken)
	}
	jwksUrl := getenv("JWKS_URL", "")

	return &config{
		databaseUrl:    databaseUrl,
		controllerAddr: controllerAddr,
		apiAddr:        apiAddr,
		authToken:      authToken,
		jwksUrl:        jwksUrl,
	}, nil
}

func getenv(key, defaultValue string) string {
	val := os.Getenv(key)
	if val == "" {
		val = defaultValue
	}

	return val
}

func generateAuthToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

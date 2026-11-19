package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/joho/godotenv"
)

const (
	minimumJWTSecretLength = 32
	defaultJWTTTL          = 5 * time.Minute
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
)

type config struct {
	databaseUrl    string
	controllerAddr string
	apiAddr        string
	authToken      string
	oauth          oauthSettings
}

type oauthSettings struct {
	clientID        string
	clientSecret    string
	redirectURL     string
	frontendURL     string
	jwtSecret       []byte
	jwtTTL          time.Duration
	refreshTokenTTL time.Duration
}

type Config interface {
	DatabaseURL() string
	ControllerAddr() string
	ApiAddr() string
	AuthToken() string
}

type OAuthConfig interface {
	GoogleClientID() string
	GoogleClientSecret() string
	GoogleRedirectURL() string
	FrontendURL() string
	JWTSecret() []byte
	JWTTTL() time.Duration
	RefreshTokenTTL() time.Duration
}

func (c *config) DatabaseURL() string    { return c.databaseUrl }
func (c *config) ControllerAddr() string { return c.controllerAddr }
func (c *config) ApiAddr() string        { return c.apiAddr }
func (c *config) AuthToken() string      { return c.authToken }

func (c *config) GoogleClientID() string         { return c.oauth.clientID }
func (c *config) GoogleClientSecret() string     { return c.oauth.clientSecret }
func (c *config) GoogleRedirectURL() string      { return c.oauth.redirectURL }
func (c *config) FrontendURL() string            { return c.oauth.frontendURL }
func (c *config) JWTSecret() []byte              { return c.oauth.jwtSecret }
func (c *config) JWTTTL() time.Duration          { return c.oauth.jwtTTL }
func (c *config) RefreshTokenTTL() time.Duration { return c.oauth.refreshTokenTTL }

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
	oauth, err := parseOAuth()
	if err != nil {
		return nil, err
	}

	return &config{
		databaseUrl:    databaseUrl,
		controllerAddr: controllerAddr,
		apiAddr:        apiAddr,
		authToken:      authToken,
		oauth:          *oauth,
	}, nil
}

func parseOAuth() (*oauthSettings, error) {
	clientID := getenv("GOOGLE_CLIENT_ID", "")
	if clientID == "" {
		return nil, errors.New("GOOGLE_CLIENT_ID environment variable not set")
	}
	clientSecret := getenv("GOOGLE_CLIENT_SECRET", "")
	if clientSecret == "" {
		return nil, errors.New("GOOGLE_CLIENT_SECRET environment variable not set")
	}
	redirectURL := getenv("GOOGLE_REDIRECT_URL", "")
	if err := requireHTTPSURL(redirectURL, "GOOGLE_REDIRECT_URL"); err != nil {
		return nil, err
	}
	frontendURL := getenv("FRONTEND_URL", "")
	if err := requireHTTPSURL(frontendURL, "FRONTEND_URL"); err != nil {
		return nil, err
	}
	secret := getenv("JWT_SECRET", "")
	if len(secret) < minimumJWTSecretLength {
		return nil, fmt.Errorf("JWT_SECRET environment variable must be at least %d bytes", minimumJWTSecretLength)
	}
	jwtTTL, err := parsePositiveDuration("JWT_TTL", defaultJWTTTL)
	if err != nil {
		return nil, err
	}
	refreshTokenTTL, err := parsePositiveDuration("REFRESH_TOKEN_TTL", defaultRefreshTokenTTL)
	if err != nil {
		return nil, err
	}

	return &oauthSettings{
		clientID:        clientID,
		clientSecret:    clientSecret,
		redirectURL:     redirectURL,
		frontendURL:     frontendURL,
		jwtSecret:       []byte(secret),
		jwtTTL:          jwtTTL,
		refreshTokenTTL: refreshTokenTTL,
	}, nil
}

func parsePositiveDuration(envName string, defaultValue time.Duration) (time.Duration, error) {
	duration, err := time.ParseDuration(getenv(envName, defaultValue.String()))
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s environment variable must be a positive duration", envName)
	}
	return duration, nil
}

func requireHTTPSURL(raw string, envName string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s environment variable must be a valid https URL", envName)
	}
	return nil
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

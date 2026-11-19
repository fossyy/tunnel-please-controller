package config

import (
	"strings"
	"testing"
	"time"
)

type envValues map[string]string

const testJWTSecret = "0123456789abcdef0123456789abcdef"

var validEnv = envValues{
	"DATABASE_URL":         "postgres://localhost/test",
	"AUTH_TOKEN":           "test-token",
	"GOOGLE_CLIENT_ID":     "client-id",
	"GOOGLE_CLIENT_SECRET": "client-secret",
	"GOOGLE_REDIRECT_URL":  "https://backend.example.com/callback",
	"FRONTEND_URL":         "https://app.example.com",
	"JWT_SECRET":           testJWTSecret,
}

func setEnv(t *testing.T, values envValues) {
	t.Helper()
	for _, key := range []string{
		"DATABASE_URL",
		"CONTROLLER_ADDR",
		"API_ADDR",
		"AUTH_TOKEN",
		"GOOGLE_CLIENT_ID",
		"GOOGLE_CLIENT_SECRET",
		"GOOGLE_REDIRECT_URL",
		"FRONTEND_URL",
		"JWT_SECRET",
		"JWT_TTL",
		"REFRESH_TOKEN_TTL",
	} {
		t.Setenv(key, values[key])
	}
}

func parseWithEnv(t *testing.T, overrides envValues) (*config, error) {
	t.Helper()
	env := envValues{}
	for key, value := range validEnv {
		env[key] = value
	}
	for key, value := range overrides {
		env[key] = value
	}
	setEnv(t, env)
	return parse()
}

func TestParseOAuthRequiredVars(t *testing.T) {
	tests := []struct {
		name      string
		overrides envValues
		wantError string
	}{
		{name: "missing google client id", overrides: envValues{"GOOGLE_CLIENT_ID": ""}, wantError: "GOOGLE_CLIENT_ID environment variable not set"},
		{name: "missing google client secret", overrides: envValues{"GOOGLE_CLIENT_SECRET": ""}, wantError: "GOOGLE_CLIENT_SECRET environment variable not set"},
		{name: "missing google redirect url", overrides: envValues{"GOOGLE_REDIRECT_URL": ""}, wantError: "GOOGLE_REDIRECT_URL environment variable must be a valid https URL"},
		{name: "missing frontend url", overrides: envValues{"FRONTEND_URL": ""}, wantError: "FRONTEND_URL environment variable must be a valid https URL"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oauth, err := parseWithEnv(t, test.overrides)
			if err == nil {
				t.Fatalf("expected error, got settings %+v", oauth)
			}
			if err.Error() != test.wantError {
				t.Errorf("error = %q, want %q", err.Error(), test.wantError)
			}
		})
	}
}

func TestParseOAuthHTTPSValidation(t *testing.T) {
	tests := []struct {
		name      string
		overrides envValues
	}{
		{name: "redirect url over http", overrides: envValues{"GOOGLE_REDIRECT_URL": "http://backend.example.com/callback"}},
		{name: "redirect url without scheme", overrides: envValues{"GOOGLE_REDIRECT_URL": "backend.example.com/callback"}},
		{name: "redirect url without host", overrides: envValues{"GOOGLE_REDIRECT_URL": "https:///callback"}},
		{name: "frontend url over http", overrides: envValues{"FRONTEND_URL": "http://app.example.com"}},
		{name: "frontend url garbage", overrides: envValues{"FRONTEND_URL": "not a url"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oauth, err := parseWithEnv(t, test.overrides)
			if err == nil {
				t.Fatalf("expected error, got settings %+v", oauth)
			}
			if !strings.HasSuffix(err.Error(), "environment variable must be a valid https URL") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseOAuthJWTSecretMinimumLength(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{name: "too short", secret: strings.Repeat("x", 31), wantErr: true},
		{name: "exactly minimum", secret: strings.Repeat("x", 32)},
		{name: "longer", secret: strings.Repeat("x", 64)},
		{name: "empty", secret: "", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oauth, err := parseWithEnv(t, envValues{"JWT_SECRET": test.secret})
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got settings %+v", oauth)
				}
				if !strings.Contains(err.Error(), "JWT_SECRET environment variable must be at least 32 bytes") {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := string(oauth.JWTSecret()); got != test.secret {
				t.Errorf("JWTSecret() = %q, want %q", got, test.secret)
			}
		})
	}
}

func TestParseOAuthTTLOverrides(t *testing.T) {
	tests := []struct {
		name                string
		overrides           envValues
		wantJWT             time.Duration
		wantRefreshTokenTTL time.Duration
	}{
		{name: "defaults", overrides: envValues{}, wantJWT: 5 * time.Minute, wantRefreshTokenTTL: 30 * 24 * time.Hour},
		{name: "custom values", overrides: envValues{"JWT_TTL": "90s", "REFRESH_TOKEN_TTL": "48h"}, wantJWT: 90 * time.Second, wantRefreshTokenTTL: 48 * time.Hour},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oauth, err := parseWithEnv(t, test.overrides)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := oauth.JWTTTL(); got != test.wantJWT {
				t.Errorf("JWTTTL() = %v, want %v", got, test.wantJWT)
			}
			if got := oauth.RefreshTokenTTL(); got != test.wantRefreshTokenTTL {
				t.Errorf("RefreshTokenTTL() = %v, want %v", got, test.wantRefreshTokenTTL)
			}
		})
	}
}

func TestParseOAuthInvalidDurations(t *testing.T) {
	tests := []struct {
		name      string
		overrides envValues
	}{
		{name: "jwt ttl not a duration", overrides: envValues{"JWT_TTL": "soon"}},
		{name: "jwt ttl zero", overrides: envValues{"JWT_TTL": "0"}},
		{name: "jwt ttl negative", overrides: envValues{"JWT_TTL": "-5m"}},
		{name: "refresh ttl not a duration", overrides: envValues{"REFRESH_TOKEN_TTL": "thirty days"}},
		{name: "refresh ttl zero", overrides: envValues{"REFRESH_TOKEN_TTL": "0"}},
		{name: "refresh ttl negative", overrides: envValues{"REFRESH_TOKEN_TTL": "-24h"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oauth, err := parseWithEnv(t, test.overrides)
			if err == nil {
				t.Fatalf("expected error, got settings %+v", oauth)
			}
			if !strings.HasSuffix(err.Error(), "environment variable must be a positive duration") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseRequiredDatabaseURL(t *testing.T) {
	setEnv(t, envValues{
		"DATABASE_URL":         "",
		"AUTH_TOKEN":           "test-token",
		"GOOGLE_CLIENT_ID":     "client-id",
		"GOOGLE_CLIENT_SECRET": "client-secret",
		"GOOGLE_REDIRECT_URL":  "https://backend.example.com/callback",
		"FRONTEND_URL":         "https://app.example.com",
		"JWT_SECRET":           testJWTSecret,
	})
	cfg, err := parse()
	if err == nil {
		t.Fatalf("expected error, got config %+v", cfg)
	}
	if err.Error() != "DATABASE_URL environment variable not set" {
		t.Errorf("error = %q", err.Error())
	}
}

func TestParseValid(t *testing.T) {
	setEnv(t, envValues{
		"DATABASE_URL":         "postgres://localhost/test",
		"CONTROLLER_ADDR":      ":9000",
		"API_ADDR":             ":9001",
		"AUTH_TOKEN":           "test-token",
		"GOOGLE_CLIENT_ID":     "client-id",
		"GOOGLE_CLIENT_SECRET": "client-secret",
		"GOOGLE_REDIRECT_URL":  "https://backend.example.com/callback",
		"FRONTEND_URL":         "https://app.example.com",
		"JWT_SECRET":           testJWTSecret,
	})
	cfg, err := parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DatabaseURL() != "postgres://localhost/test" {
		t.Errorf("DatabaseURL() = %q", cfg.DatabaseURL())
	}
	if cfg.ControllerAddr() != ":9000" {
		t.Errorf("ControllerAddr() = %q", cfg.ControllerAddr())
	}
	if cfg.ApiAddr() != ":9001" {
		t.Errorf("ApiAddr() = %q", cfg.ApiAddr())
	}
	if cfg.AuthToken() != "test-token" {
		t.Errorf("AuthToken() = %q", cfg.AuthToken())
	}
	if cfg.GoogleClientID() != "client-id" {
		t.Errorf("GoogleClientID() = %q", cfg.GoogleClientID())
	}
	if cfg.GoogleRedirectURL() != "https://backend.example.com/callback" {
		t.Errorf("GoogleRedirectURL() = %q", cfg.GoogleRedirectURL())
	}
}

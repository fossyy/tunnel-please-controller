package bootstrap

import (
	"context"
	"testing"
	"time"
)

type fakeConfig struct {
	databaseURL string
}

func (f fakeConfig) DatabaseURL() string    { return f.databaseURL }
func (f fakeConfig) ControllerAddr() string { return ":0" }
func (f fakeConfig) ApiAddr() string        { return ":0" }
func (f fakeConfig) AuthToken() string      { return "" }
func (f fakeConfig) JwksURL() string        { return "" }

func TestStartDatabaseInvalidURL(t *testing.T) {
	if _, _, err := startDatabase(context.Background(), "not-a-valid-url"); err == nil {
		t.Fatal("expected error for invalid database URL")
	}
}

func TestStartDatabaseUnreachableHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	repo, pool, err := startDatabase(ctx, "postgres://user:pass@127.0.0.1:1/db?connect_timeout=1")
	if err == nil {
		t.Fatal("expected error for unreachable database")
	}
	if repo != nil || pool != nil {
		t.Fatal("expected nil repo and pool on connection failure")
	}
}

func TestRunReturnsDatabaseError(t *testing.T) {
	b := New(fakeConfig{databaseURL: "not-a-valid-url"})
	if err := b.Run(); err == nil {
		t.Fatal("expected Run to fail when the database cannot be configured")
	}
}

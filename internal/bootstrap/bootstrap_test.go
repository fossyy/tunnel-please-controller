package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const testDatabaseURLEnv = "TP_TEST_DATABASE_URL"
const schemaCheckDatabaseName = "tp_test_bootstrap"

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

func schemaCheckPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	adminURL := os.Getenv(testDatabaseURLEnv)
	if adminURL == "" {
		t.Skipf("%s not set; skipping schema check test", testDatabaseURLEnv)
	}
	if !strings.Contains(adminURL, "/tp_test") {
		t.Fatalf("%s must point to the disposable tp_test database", testDatabaseURLEnv)
	}
	target, _, _ := strings.Cut(adminURL, "?")
	target = strings.Replace(target, "/tp_test", "/"+schemaCheckDatabaseName, 1)

	pool, err := pgxpool.New(context.Background(), adminURL)
	if err != nil {
		t.Fatalf("connect admin database: %v", err)
	}
	t.Cleanup(pool.Close)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+schemaCheckDatabaseName+" WITH (FORCE)"); err != nil {
			t.Logf("drop %s: %v", schemaCheckDatabaseName, err)
		}
	})
	if _, err := pool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+schemaCheckDatabaseName+" WITH (FORCE)"); err != nil {
		t.Fatalf("drop stale %s: %v", schemaCheckDatabaseName, err)
	}
	if _, err := pool.Exec(context.Background(), "CREATE DATABASE "+schemaCheckDatabaseName); err != nil {
		t.Fatalf("create %s: %v", schemaCheckDatabaseName, err)
	}

	targetPool, err := pgxpool.New(context.Background(), target)
	if err != nil {
		t.Fatalf("connect %s: %v", schemaCheckDatabaseName, err)
	}
	t.Cleanup(targetPool.Close)
	return targetPool
}

func applyMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	entries, err := filepath.Glob(filepath.Join("..", "..", "internal", "db", "sqlc", "migrations", "*.up.sql"))
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(entries)
	for _, entry := range entries {
		sql, err := os.ReadFile(entry)
		if err != nil {
			t.Fatalf("read migration %s: %v", entry, err)
		}
		if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
			t.Fatalf("apply migration %s: %v", entry, err)
		}
	}
}

func TestStartDatabaseMissingSchema(t *testing.T) {
	schemaCheckPool(t)

	target, _, _ := strings.Cut(os.Getenv(testDatabaseURLEnv), "?")
	target = strings.Replace(target, "/tp_test", "/"+schemaCheckDatabaseName, 1)
	repo, dbPool, err := startDatabase(context.Background(), target)
	if err == nil {
		dbPool.Close()
		t.Fatal("expected error when schema is missing")
	}
	if repo != nil || dbPool != nil {
		t.Fatal("expected nil repo and pool on schema failure")
	}
	if !strings.Contains(err.Error(), "internal/db/sqlc/migrations") {
		t.Fatalf("expected actionable migration guidance, got: %v", err)
	}
}

func TestStartDatabaseWithAppliedMigrations(t *testing.T) {
	pool := schemaCheckPool(t)
	applyMigrations(t, pool)

	target, _, _ := strings.Cut(os.Getenv(testDatabaseURLEnv), "?")
	target = strings.Replace(target, "/tp_test", "/"+schemaCheckDatabaseName, 1)

	repo, dbPool, err := startDatabase(context.Background(), target)
	if err != nil {
		t.Fatalf("expected success after migrations, got: %v", err)
	}
	defer dbPool.Close()
	if repo == nil || dbPool == nil {
		t.Fatal("expected non-nil repo and pool after migrations")
	}
}

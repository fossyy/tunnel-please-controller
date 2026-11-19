package server

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"git.fossy.my.id/bagas/tunnel-please-controller/internal/db/sqlc/repository"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const testDatabaseURLEnv = "TP_TEST_DATABASE_URL"

func openTestPool(t *testing.T) (*pgxpool.Pool, *repository.Queries) {
	t.Helper()

	databaseURL := os.Getenv(testDatabaseURLEnv)
	if databaseURL == "" {
		t.Skipf("%s not set; skipping database test", testDatabaseURLEnv)
	}
	if !strings.Contains(databaseURL, "/tp_test") {
		t.Fatalf("%s must point to the disposable tp_test database", testDatabaseURLEnv)
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	t.Cleanup(pool.Close)

	return pool, repository.New(pool)
}

func applyMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	if _, err := pool.Exec(context.Background(), "SELECT 1 FROM public.refresh_token LIMIT 1"); err == nil {
		return
	}
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

func testClaims(subject, email string) *googleIDClaims {
	return &googleIDClaims{subject: subject, email: email, name: "Tester " + subject}
}

func TestUpsertGoogleUserAgainstPostgres(t *testing.T) {
	pool, repo := openTestPool(t)
	applyMigrations(t, pool)
	if _, err := pool.Exec(context.Background(), `TRUNCATE refresh_token, account, public."user" CASCADE`); err != nil {
		t.Fatalf("truncate test tables: %v", err)
	}
	srv := New(repo, nil, fakeConfig{})
	ctx := context.Background()

	t.Run("new user gets canonical sub identifier", func(t *testing.T) {
		claims := testClaims("sub-1", "one@example.com")
		sshIdentifier, userID, err := srv.upsertGoogleUser(ctx, claims)
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if sshIdentifier != "sub-1" {
			t.Errorf("ssh_identifier = %q, want sub-1", sshIdentifier)
		}
		var accountUserID string
		if err := pool.QueryRow(ctx,
			"SELECT user_id FROM public.account WHERE provider_id = 'google' AND account_id = 'sub-1'",
		).Scan(&accountUserID); err != nil {
			t.Fatalf("load account: %v", err)
		}
		if accountUserID != userID {
			t.Errorf("account user_id = %q, want persisted id %q", accountUserID, userID)
		}
	})

	t.Run("existing verified email links without new user", func(t *testing.T) {
		existingID := "user-existing"
		if _, err := pool.Exec(ctx,
			`INSERT INTO public."user" (id, ssh_identifier, name, email, email_verified) VALUES ($1, 'legacy-ident', 'Existing', 'two@example.com', true)`,
			existingID,
		); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, userID, err := srv.upsertGoogleUser(ctx, testClaims("sub-2", "two@example.com"))
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if userID != existingID {
			t.Errorf("user id = %q, want existing %q", userID, existingID)
		}
		var sshIdentifier string
		if err := pool.QueryRow(ctx,
			`SELECT ssh_identifier FROM public."user" WHERE id = $1`, existingID,
		).Scan(&sshIdentifier); err != nil {
			t.Fatalf("load user: %v", err)
		}
		if sshIdentifier != "sub-2" {
			t.Errorf("ssh_identifier = %q, want canonical sub-2", sshIdentifier)
		}
	})

	t.Run("existing google subject is not reassigned", func(t *testing.T) {
		if _, _, err := srv.upsertGoogleUser(ctx, testClaims("sub-3", "owner@example.com")); err != nil {
			t.Fatalf("seed owner: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO public."user" (id, ssh_identifier, name, email, email_verified) VALUES ('user-other', 'other-ident', 'Other', 'other@example.com', true)`,
		); err != nil {
			t.Fatalf("seed other user: %v", err)
		}

		sshIdentifier, userID, err := srv.upsertGoogleUser(ctx, testClaims("sub-3", "other@example.com"))
		if err != nil {
			t.Fatalf("upsert with mismatched verified email: %v", err)
		}
		if sshIdentifier != "sub-3" {
			t.Errorf("ssh_identifier = %q, want sub-3", sshIdentifier)
		}
		var accountUserID string
		if err := pool.QueryRow(ctx,
			"SELECT user_id FROM public.account WHERE provider_id = 'google' AND account_id = 'sub-3'",
		).Scan(&accountUserID); err != nil {
			t.Fatalf("load account: %v", err)
		}
		if accountUserID != userID {
			t.Errorf("account owner %q does not match returned user %q; subject must stay bound to its owner", accountUserID, userID)
		}
		if accountUserID == "user-other" {
			t.Error("google subject was reassigned to a different user")
		}
	})

	t.Run("legacy unverified same email row is claimed", func(t *testing.T) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO public."user" (id, ssh_identifier, name, email, email_verified) VALUES ('user-legacy', 'legacy-ident-4', 'Legacy', 'four@example.com', false)`,
		); err != nil {
			t.Fatalf("seed legacy user: %v", err)
		}
		_, userID, err := srv.upsertGoogleUser(ctx, testClaims("sub-4", "four@example.com"))
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if userID != "user-legacy" {
			t.Errorf("user id = %q, want claimed legacy row user-legacy", userID)
		}
	})
}

func TestRefreshTokenLifecycleAgainstPostgres(t *testing.T) {
	pool, repo := openTestPool(t)
	applyMigrations(t, pool)
	if _, err := pool.Exec(context.Background(), `TRUNCATE refresh_token, account, public."user" CASCADE`); err != nil {
		t.Fatalf("truncate test tables: %v", err)
	}
	srv := New(repo, nil, fakeConfig{})
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO public."user" (id, ssh_identifier, name, email, email_verified) VALUES ('user-rt', 'sub-rt', 'RT', 'rt@example.com', true)`,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	refreshToken, err := srv.startRefreshFamily(ctx, "user-rt")
	if err != nil {
		t.Fatalf("start refresh family: %v", err)
	}

	var familyID string
	t.Run("rotation replaces token atomically", func(t *testing.T) {
		rotated, err := repo.RotateRefreshToken(ctx, repository.RotateRefreshTokenParams{
			LookupHash:   hashToken(refreshToken),
			NewID:        "rt-2",
			NewTokenHash: hashToken("second-token"),
			NewExpiresAt: mustTimestamp(time.Now().Add(time.Hour)),
		})
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		if rotated.UserID != "user-rt" || rotated.FamilyID == "" {
			t.Errorf("rotation returned %+v, want user-rt and a family id", rotated)
		}
		familyID = rotated.FamilyID
		var count int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM public.refresh_token WHERE family_id = $1`, rotated.FamilyID,
		).Scan(&count); err != nil {
			t.Fatalf("count family: %v", err)
		}
		if count != 2 {
			t.Errorf("family token count = %d, want 2 (rotated + replacement)", count)
		}
	})

	t.Run("replay of rotated token revokes family", func(t *testing.T) {
		if _, err := repo.RotateRefreshToken(ctx, repository.RotateRefreshTokenParams{
			LookupHash:   hashToken(refreshToken),
			NewID:        "rt-3",
			NewTokenHash: hashToken("third-token"),
			NewExpiresAt: mustTimestamp(time.Now().Add(time.Hour)),
		}); err == nil {
			t.Fatal("expected replayed rotation to fail")
		}
		srv.rejectRefreshToken(ctx, hashToken(refreshToken))
		var revoked int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM public.refresh_token WHERE family_id = $1 AND revoked_at IS NOT NULL`, familyID,
		).Scan(&revoked); err != nil {
			t.Fatalf("count revoked: %v", err)
		}
		if revoked != 2 {
			t.Errorf("revoked rows in family = %d, want 2 (rotated + replacement)", revoked)
		}
	})

	t.Run("session token subject is canonical identifier", func(t *testing.T) {
		token, err := srv.signSessionToken("sub-rt", "rt@example.com")
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		parsed, err := jwt.Parse([]byte(token),
			jwt.WithKey(jwa.HS256(), []byte(testJWTSecret)),
			jwt.WithIssuer(jwtIssuer),
			jwt.WithAudience(jwtAudience),
		)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		subject, _ := parsed.Subject()
		if subject != "sub-rt" {
			t.Errorf("subject = %q, want sub-rt", subject)
		}
	})
}

func mustTimestamp(t time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{Time: t, Valid: true}
}

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
		var migrated bool
		if err = pool.QueryRow(context.Background(), "SELECT data_type = 'timestamp with time zone' FROM information_schema.columns WHERE table_schema='public' AND table_name='refresh_token' AND column_name='expires_at'").Scan(&migrated); err == nil && migrated {
			return
		}
		migration, err := os.ReadFile(filepath.Join("..", "..", "internal", "db", "sqlc", "migrations", "000005_refresh_token_timestamptz.up.sql"))
		if err != nil {
			t.Fatalf("read migration 000005: %v", err)
		}
		if _, err := pool.Exec(context.Background(), string(migration)); err != nil {
			t.Fatalf("apply migration 000005: %v", err)
		}
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
		assertReturnedIdentifierMatchesDB(t, pool, userID, sshIdentifier)
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
		returnedIdentifier, _, err := srv.upsertGoogleUser(ctx, testClaims("sub-2", "two@example.com"))
		if err != nil {
			t.Fatalf("re-upsert: %v", err)
		}
		assertReturnedIdentifierMatchesDB(t, pool, existingID, returnedIdentifier)
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
		sshIdentifier, userID, err := srv.upsertGoogleUser(ctx, testClaims("sub-4", "four@example.com"))
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if userID != "user-legacy" {
			t.Errorf("user id = %q, want claimed legacy row user-legacy", userID)
		}
		assertReturnedIdentifierMatchesDB(t, pool, userID, sshIdentifier)
	})

	t.Run("subject held by another user fails login explicitly", func(t *testing.T) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO public."user" (id, ssh_identifier, name, email, email_verified) VALUES ('user-holder', 'sub-5', 'Holder', 'holder@example.com', true)`,
		); err != nil {
			t.Fatalf("seed subject holder: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO public."user" (id, ssh_identifier, name, email, email_verified) VALUES ('user-email', 'legacy-ident-5', 'Email', 'five@example.com', true)`,
		); err != nil {
			t.Fatalf("seed email user: %v", err)
		}
		_, _, err := srv.upsertGoogleUser(ctx, testClaims("sub-5", "five@example.com"))
		if err == nil || !strings.Contains(err.Error(), "canonical ssh identifier unavailable") {
			t.Fatalf("upsert with conflicting subject holder: err = %v, want explicit identity conflict", err)
		}
		var emailIdentifier, holderIdentifier string
		if err := pool.QueryRow(ctx,
			`SELECT ssh_identifier FROM public."user" WHERE id = 'user-email'`,
		).Scan(&emailIdentifier); err != nil {
			t.Fatalf("load email user: %v", err)
		}
		if emailIdentifier != "legacy-ident-5" {
			t.Errorf("email user ssh_identifier = %q, want legacy-ident-5 unchanged on failed login", emailIdentifier)
		}
		if err := pool.QueryRow(ctx,
			`SELECT ssh_identifier FROM public."user" WHERE id = 'user-holder'`,
		).Scan(&holderIdentifier); err != nil {
			t.Fatalf("load holder user: %v", err)
		}
		if holderIdentifier != "sub-5" {
			t.Errorf("holder ssh_identifier = %q, want unchanged", holderIdentifier)
		}
		var accountCount int
		if err := pool.QueryRow(ctx,
			"SELECT count(*) FROM public.account WHERE provider_id = 'google' AND account_id = 'sub-5'",
		).Scan(&accountCount); err != nil {
			t.Fatalf("count account: %v", err)
		}
		if accountCount != 0 {
			t.Errorf("account rows for sub-5 = %d, want 0; google subject must not link to a user that cannot be canonicalized", accountCount)
		}
		var freshUserID, freshIdentifier string
		if err := pool.QueryRow(ctx,
			`SELECT id, ssh_identifier FROM public."user" WHERE email = 'fresh-holder@example.com'`,
		).Scan(&freshUserID, &freshIdentifier); err == nil {
			t.Errorf("unexpected user row created for held subject: id %q identifier %q", freshUserID, freshIdentifier)
		}
	})

	t.Run("new user insert skipped when subject held without email match", func(t *testing.T) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO public."user" (id, ssh_identifier, name, email, email_verified) VALUES ('user-holder-2', 'sub-6', 'Holder2', 'unrelated@example.com', false)`,
		); err != nil {
			t.Fatalf("seed subject holder: %v", err)
		}
		_, _, err := srv.upsertGoogleUser(ctx, testClaims("sub-6", "six@example.com"))
		if err == nil || !strings.Contains(err.Error(), "canonical ssh identifier unavailable") {
			t.Fatalf("upsert with held subject and unmatched email: err = %v, want explicit identity conflict", err)
		}
		var count int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM public."user" WHERE email = 'six@example.com'`,
		).Scan(&count); err != nil {
			t.Fatalf("count users: %v", err)
		}
		if count != 0 {
			t.Errorf("user rows for six@example.com = %d, want 0; insert must not violate subject uniqueness", count)
		}
	})
}

func assertReturnedIdentifierMatchesDB(t *testing.T, pool *pgxpool.Pool, userID, sshIdentifier string) {
	t.Helper()
	var persisted string
	if err := pool.QueryRow(context.Background(),
		`SELECT ssh_identifier FROM public."user" WHERE id = $1`, userID,
	).Scan(&persisted); err != nil {
		t.Fatalf("load user %s: %v", userID, err)
	}
	if persisted != sshIdentifier {
		t.Errorf("returned ssh_identifier = %q, want persisted DB value %q", sshIdentifier, persisted)
	}
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
		if rotated.UserID != "user-rt" || rotated.FamilyID == "" || rotated.SshIdentifier != "sub-rt" || rotated.Email != "rt@example.com" {
			t.Errorf("rotation returned %+v, want user identity and family", rotated)
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

func TestDeleteExpiredRefreshTokensAgainstPostgres(t *testing.T) {
	pool, repo := openTestPool(t)
	applyMigrations(t, pool)
	if _, err := pool.Exec(context.Background(), `TRUNCATE refresh_token, account, public."user" CASCADE`); err != nil {
		t.Fatalf("truncate test tables: %v", err)
	}
	ctx := context.Background()

	insertToken := func(t *testing.T, id, token string, expiresAt time.Time) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO public.refresh_token (id, user_id, family_id, token_hash, expires_at) VALUES ($1, 'user-rt', 'fam-rt', $2, $3)`,
			id, hashToken(token), expiresAt,
		); err != nil {
			t.Fatalf("insert token %s: %v", id, err)
		}
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO public."user" (id, ssh_identifier, name, email, email_verified) VALUES ('user-rt', 'sub-rt', 'RT', 'rt@example.com', true)`,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	t.Run("deletes only expired rows within the batch limit", func(t *testing.T) {
		insertToken(t, "rt-expired-1", "expired-1", time.Now().Add(-time.Hour))
		insertToken(t, "rt-expired-2", "expired-2", time.Now().Add(-time.Minute))
		insertToken(t, "rt-live", "live", time.Now().Add(time.Hour))

		deleted, err := repo.DeleteExpiredRefreshTokens(ctx, 1)
		if err != nil {
			t.Fatalf("delete expired: %v", err)
		}
		if deleted != 1 {
			t.Errorf("deleted = %d, want 1 (batch limit)", deleted)
		}
		var liveCount, expiredCount int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM public.refresh_token WHERE token_hash = $1`, hashToken("live"),
		).Scan(&liveCount); err != nil {
			t.Fatalf("count live: %v", err)
		}
		if liveCount != 1 {
			t.Errorf("live token count = %d, want 1", liveCount)
		}
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM public.refresh_token WHERE expires_at < now()`,
		).Scan(&expiredCount); err != nil {
			t.Fatalf("count expired: %v", err)
		}
		if expiredCount != 1 {
			t.Errorf("remaining expired rows = %d, want 1", expiredCount)
		}
	})
}

func mustTimestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

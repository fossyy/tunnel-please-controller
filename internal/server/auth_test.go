package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.fossy.my.id/bagas/tunnel-please-controller/internal/db/sqlc/repository"
	"github.com/jackc/pgx/v5"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type stubAuthStore struct {
	rotateErr      error
	rotateRow      repository.RotateRefreshTokenRow
	lookupRow      repository.GetRefreshTokenByHashRow
	lookupErr      error
	lookupCalls    int
	revokeCalls    []string
	cleanupDeleted int64
	cleanupErr     error
}

func (s *stubAuthStore) GetVerifiedSSHIdentifier(context.Context, string) (string, error) {
	return "", pgx.ErrNoRows
}

func (s *stubAuthStore) UpsertGoogleUser(context.Context, repository.UpsertGoogleUserParams) (repository.UpsertGoogleUserRow, error) {
	return repository.UpsertGoogleUserRow{}, errors.New("not implemented")
}

func (s *stubAuthStore) GetUserIdentity(context.Context, string) (repository.GetUserIdentityRow, error) {
	return repository.GetUserIdentityRow{}, errors.New("not implemented")
}

func (s *stubAuthStore) CreateRefreshToken(context.Context, repository.CreateRefreshTokenParams) error {
	return errors.New("not implemented")
}

func (s *stubAuthStore) GetRefreshTokenByHash(context.Context, string) (repository.GetRefreshTokenByHashRow, error) {
	s.lookupCalls++
	return s.lookupRow, s.lookupErr
}

func (s *stubAuthStore) RotateRefreshToken(context.Context, repository.RotateRefreshTokenParams) (repository.RotateRefreshTokenRow, error) {
	return s.rotateRow, s.rotateErr
}

func (s *stubAuthStore) RevokeRefreshTokenFamily(_ context.Context, familyID string) error {
	s.revokeCalls = append(s.revokeCalls, familyID)
	return nil
}

func (s *stubAuthStore) DeleteExpiredRefreshTokens(context.Context, int32) (int64, error) {
	return s.cleanupDeleted, s.cleanupErr
}

func newAuthTestServer(t *testing.T, db authStore) *Server {
	t.Helper()
	cache, err := jwk.NewCache(context.Background(), httprc.NewClient())
	if err != nil {
		t.Fatalf("build jwk cache: %v", err)
	}
	return New(db, cache, fakeConfig{})
}

func TestSameOriginUsesFrontendURL(t *testing.T) {
	srv := newAuthTestServer(t, &stubAuthStore{})

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "no origin header", origin: "", want: true},
		{name: "frontend origin", origin: testFrontendURL, want: true},
		{name: "frontend origin with path", origin: testFrontendURL + "/settings", want: true},
		{name: "backend origin is not the browser origin", origin: "https://api.example.com", want: false},
		{name: "foreign origin", origin: "https://evil.example.com", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if got := srv.sameOrigin(req); got != tt.want {
				t.Errorf("sameOrigin(origin %q) = %t, want %t", tt.origin, got, tt.want)
			}
		})
	}
}

func callRefresh(t *testing.T, srv *Server, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: refreshToken})
	srv.handleRefresh(rec, req)
	return rec
}

func TestHandleRefreshTriage(t *testing.T) {
	t.Run("successful rotation returns cookies and no revocation", func(t *testing.T) {
		store := &stubAuthStore{
			rotateRow: repository.RotateRefreshTokenRow{UserID: "user-1", FamilyID: "fam-1", SshIdentifier: "sub-1", Email: "one@example.com"},
		}
		srv := newAuthTestServer(t, store)
		rec := callRefresh(t, srv, "current-token")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
		}
		cookies := recorderCookies(rec)
		if findCookie(cookies, sessionCookieName) == nil || findCookie(cookies, refreshCookieName) == nil {
			t.Errorf("cookies = %+v, want session and refresh cookies set", cookies)
		}
		if len(store.revokeCalls) != 0 {
			t.Errorf("revoke calls = %v, want none", store.revokeCalls)
		}
	})

	t.Run("replay revokes family and returns unauthorized", func(t *testing.T) {
		store := &stubAuthStore{
			rotateErr: pgx.ErrNoRows,
			lookupRow: repository.GetRefreshTokenByHashRow{ID: "rt-1", FamilyID: "fam-1"},
		}
		srv := newAuthTestServer(t, store)
		rec := callRefresh(t, srv, "replayed-token")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if len(store.revokeCalls) != 1 || store.revokeCalls[0] != "fam-1" {
			t.Errorf("revoke calls = %v, want one revocation of fam-1", store.revokeCalls)
		}
	})

	t.Run("unknown token is rejected without revocation", func(t *testing.T) {
		store := &stubAuthStore{rotateErr: pgx.ErrNoRows, lookupErr: pgx.ErrNoRows}
		srv := newAuthTestServer(t, store)
		rec := callRefresh(t, srv, "unknown-token")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if len(store.revokeCalls) != 0 {
			t.Errorf("revoke calls = %v, want none for unknown token", store.revokeCalls)
		}
	})

	t.Run("transient database error does not revoke the family", func(t *testing.T) {
		store := &stubAuthStore{rotateErr: errors.New("connection refused")}
		srv := newAuthTestServer(t, store)
		rec := callRefresh(t, srv, "live-token")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
		}
		if store.lookupCalls != 0 || len(store.revokeCalls) != 0 {
			t.Errorf("lookup calls = %d, revoke calls = %v, want no family revocation on transient error", store.lookupCalls, store.revokeCalls)
		}
	})
}

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"git.fossy.my.id/bagas/tunnel-please-controller/internal/db/sqlc/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	jwtIssuer            = "tunnel-please-controller"
	jwtAudience          = "tunnel-please-controller"
	sessionCookieName    = "session"
	refreshCookieName    = "refresh_token"
	refreshCookiePath    = "/api/auth/"
	oauthStateCookieName = "tp_oauth_state"
	oauthStateTTL        = 10 * time.Minute
	oauthExchangeTimeout = 10 * time.Second
	googleIssuer         = "https://accounts.google.com"
	googleAuthEndpoint   = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint  = "https://oauth2.googleapis.com/token"
	googleJWKSURL        = "https://www.googleapis.com/oauth2/v3/certs"
	oauthScope           = "openid email profile"
	pkceChallengeMethod  = "S256"
	oauthFailureReason   = "login_failed"
	oauthStateCookiePath = "/api/auth/"

	refreshCleanupBatch = 100

	errInvalidToken        = "invalid or expired token"
	errInvalidRefreshToken = "invalid refresh token"
	errAuthUnavailable     = "authentication is not configured"
	errLoginStart          = "failed to start login"
	errEmailClaimMissing   = "missing email claim in token"
	errCrossOrigin         = "cross-origin request rejected"
	errRefreshFailed       = "failed to refresh session"
)

type authStore interface {
	GetVerifiedSSHIdentifier(ctx context.Context, sshIdentifier string) (string, error)
	UpsertGoogleUser(ctx context.Context, arg repository.UpsertGoogleUserParams) (repository.UpsertGoogleUserRow, error)
	GetUserIdentity(ctx context.Context, id string) (repository.GetUserIdentityRow, error)
	CreateRefreshToken(ctx context.Context, arg repository.CreateRefreshTokenParams) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (repository.GetRefreshTokenByHashRow, error)
	RotateRefreshToken(ctx context.Context, arg repository.RotateRefreshTokenParams) (repository.RotateRefreshTokenRow, error)
	RevokeRefreshTokenFamily(ctx context.Context, familyID string) error
	DeleteExpiredRefreshTokens(ctx context.Context, maxRows int32) (int64, error)
}

type userHandler func(http.ResponseWriter, *http.Request, string)

func (s *Server) oauthReady() bool {
	return s.auth != nil && s.jwkCache != nil
}

func (s *Server) withAuth(next userHandler) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		subject, ok := s.authenticatedUser(writer, request)
		if !ok {
			return
		}
		next(writer, request, subject)
	}
}

func (s *Server) authenticatedUser(writer http.ResponseWriter, request *http.Request) (string, bool) {
	if s.auth == nil {
		writeError(writer, http.StatusServiceUnavailable, errAuthUnavailable)
		return "", false
	}
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, errInvalidToken)
		return "", false
	}
	token, err := jwt.Parse([]byte(cookie.Value),
		jwt.WithKey(jwa.HS256(), s.auth.JWTSecret()),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(jwtAudience),
		jwt.WithRequiredClaim("sub"),
	)
	if err != nil {
		log.Printf("session token validation failed: %v", err)
		writeError(writer, http.StatusUnauthorized, errInvalidToken)
		return "", false
	}

	subject, ok := token.Subject()
	if !ok || subject == "" {
		writeError(writer, http.StatusUnauthorized, errInvalidToken)
		return "", false
	}
	return subject, true
}

func (s *Server) signSessionToken(subject, email string) (string, error) {
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer).
		Audience([]string{jwtAudience}).
		Subject(subject).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(s.auth.JWTTTL())).
		Claim("email", email).
		Build()
	if err != nil {
		return "", fmt.Errorf("build session token: %w", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), s.auth.JWTSecret()))
	if err != nil {
		return "", fmt.Errorf("sign session token: %w", err)
	}
	return string(signed), nil
}

func (s *Server) signStateToken(state, nonce, verifier string) (string, error) {
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer).
		Audience([]string{jwtAudience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(oauthStateTTL)).
		Claim("state", state).
		Claim("nonce", nonce).
		Claim("verifier", verifier).
		Build()
	if err != nil {
		return "", fmt.Errorf("build oauth state token: %w", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), s.auth.JWTSecret()))
	if err != nil {
		return "", fmt.Errorf("sign oauth state token: %w", err)
	}
	return string(signed), nil
}

func randomValue() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func oauthRandomValues() (state, nonce, verifier string, err error) {
	state, err = randomValue()
	if err != nil {
		return "", "", "", err
	}
	nonce, err = randomValue()
	if err != nil {
		return "", "", "", err
	}
	verifier, err = randomValue()
	if err != nil {
		return "", "", "", err
	}
	return state, nonce, verifier, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Server) sameOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	allowed, err := url.Parse(s.auth.FrontendURL())
	if err != nil {
		return false
	}
	return parsed.Scheme == allowed.Scheme && parsed.Host == allowed.Host
}

func frontendRedirect(baseURL, reason string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	query := parsed.Query()
	query.Set("error", reason)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func clearStateCookie(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     oauthStateCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func setSessionCookie(writer http.ResponseWriter, value string, ttl time.Duration) {
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func setRefreshCookie(writer http.ResponseWriter, value string, ttl time.Duration) {
	http.SetCookie(writer, &http.Cookie{
		Name:     refreshCookieName,
		Value:    value,
		Path:     refreshCookiePath,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearAuthCookies(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(writer, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) googleAuthRedirect(state, nonce, verifier string) string {
	query := url.Values{}
	query.Set("client_id", s.auth.GoogleClientID())
	query.Set("redirect_uri", s.auth.GoogleRedirectURL())
	query.Set("response_type", "code")
	query.Set("scope", oauthScope)
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", pkceChallenge(verifier))
	query.Set("code_challenge_method", pkceChallengeMethod)
	return googleAuthEndpoint + "?" + query.Encode()
}

func (s *Server) handleLogin(writer http.ResponseWriter, request *http.Request) {
	if !s.oauthReady() {
		writeError(writer, http.StatusServiceUnavailable, errAuthUnavailable)
		return
	}
	state, nonce, verifier, err := oauthRandomValues()
	if err != nil {
		log.Printf("generate oauth state failed: %v", err)
		writeError(writer, http.StatusInternalServerError, errLoginStart)
		return
	}
	stateToken, err := s.signStateToken(state, nonce, verifier)
	if err != nil {
		log.Printf("sign oauth state failed: %v", err)
		writeError(writer, http.StatusInternalServerError, errLoginStart)
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    stateToken,
		Path:     oauthStateCookiePath,
		MaxAge:   int(oauthStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(writer, request, s.googleAuthRedirect(state, nonce, verifier), http.StatusFound)
}

func (s *Server) handleCallback(writer http.ResponseWriter, request *http.Request) {
	if !s.oauthReady() {
		if s.auth != nil {
			http.Redirect(writer, request, frontendRedirect(s.auth.FrontendURL(), oauthFailureReason), http.StatusFound)
			return
		}
		writeError(writer, http.StatusServiceUnavailable, errAuthUnavailable)
		return
	}
	nonce, verifier, ok := s.validateCallbackState(writer, request)
	if !ok {
		return
	}
	failureRedirect := frontendRedirect(s.auth.FrontendURL(), oauthFailureReason)
	fail := func() {
		http.Redirect(writer, request, failureRedirect, http.StatusFound)
	}
	if request.FormValue("error") != "" {
		fail()
		return
	}
	code := request.FormValue("code")
	if code == "" {
		fail()
		return
	}
	rawIDToken, err := s.exchangeGoogleCode(request.Context(), code, verifier)
	if err != nil {
		log.Printf("google code exchange failed: %v", err)
		fail()
		return
	}
	claims, err := s.verifyGoogleIDToken(request.Context(), rawIDToken, nonce)
	if err != nil {
		log.Printf("google id token validation failed: %v", err)
		fail()
		return
	}
	sshIdentifier, userID, err := s.upsertGoogleUser(request.Context(), claims)
	if err != nil {
		log.Printf("upsert google user failed: %v", err)
		fail()
		return
	}
	sessionToken, err := s.signSessionToken(sshIdentifier, claims.email)
	if err != nil {
		log.Printf("sign session token failed: %v", err)
		fail()
		return
	}
	refreshToken, err := s.startRefreshFamily(request.Context(), userID)
	if err != nil {
		log.Printf("create refresh token failed: %v", err)
		fail()
		return
	}
	setSessionCookie(writer, sessionToken, s.auth.JWTTTL())
	setRefreshCookie(writer, refreshToken, s.auth.RefreshTokenTTL())
	http.Redirect(writer, request, s.auth.FrontendURL(), http.StatusFound)
}

func (s *Server) validateCallbackState(writer http.ResponseWriter, request *http.Request) (string, string, bool) {
	clearStateCookie(writer)
	failureRedirect := frontendRedirect(s.auth.FrontendURL(), oauthFailureReason)
	reject := func() {
		http.Redirect(writer, request, failureRedirect, http.StatusFound)
	}
	if !s.sameOrigin(request) {
		reject()
		return "", "", false
	}
	cookie, err := request.Cookie(oauthStateCookieName)
	if err != nil || request.FormValue("state") == "" {
		reject()
		return "", "", false
	}
	stateToken, err := jwt.Parse([]byte(cookie.Value),
		jwt.WithKey(jwa.HS256(), s.auth.JWTSecret()),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(jwtAudience),
	)
	if err != nil {
		reject()
		return "", "", false
	}
	var storedState, nonce, verifier string
	if err = stateToken.Get("state", &storedState); err != nil ||
		subtle.ConstantTimeCompare([]byte(storedState), []byte(request.FormValue("state"))) != 1 {
		reject()
		return "", "", false
	}
	if err = stateToken.Get("nonce", &nonce); err != nil || nonce == "" {
		reject()
		return "", "", false
	}
	if err = stateToken.Get("verifier", &verifier); err != nil || verifier == "" {
		reject()
		return "", "", false
	}
	return nonce, verifier, true
}

type googleIDClaims struct {
	subject string
	email   string
	name    string
	picture string
}

func (s *Server) verifyGoogleIDToken(ctx context.Context, rawIDToken, nonce string) (*googleIDClaims, error) {
	keyset, err := s.jwkCache.Lookup(ctx, googleJWKSURL)
	if err != nil {
		return nil, fmt.Errorf("lookup google jwks: %w", err)
	}
	token, err := jwt.Parse([]byte(rawIDToken),
		jwt.WithKeySet(keyset),
		jwt.WithIssuer(googleIssuer),
		jwt.WithAudience(s.auth.GoogleClientID()),
		jwt.WithRequiredClaim("sub"),
		jwt.WithRequiredClaim("exp"),
		jwt.WithRequiredClaim("email"),
		jwt.WithRequiredClaim("nonce"),
	)
	if err != nil {
		return nil, fmt.Errorf("validate google id token: %w", err)
	}
	var emailVerified bool
	if err = token.Get("email_verified", &emailVerified); err != nil || !emailVerified {
		return nil, errors.New("google account email is not verified")
	}
	var email, subject, tokenNonce string
	if err = token.Get("email", &email); err != nil || email == "" {
		return nil, errors.New("google id token has empty email claim")
	}
	if err = token.Get("sub", &subject); err != nil || subject == "" {
		return nil, errors.New("google id token has empty sub claim")
	}
	if err = token.Get("nonce", &tokenNonce); err != nil ||
		subtle.ConstantTimeCompare([]byte(tokenNonce), []byte(nonce)) != 1 {
		return nil, errors.New("google id token nonce mismatch")
	}
	claims := &googleIDClaims{subject: subject, email: email}
	_ = token.Get("name", &claims.name)
	_ = token.Get("picture", &claims.picture)
	return claims, nil
}

type googleTokenResponse struct {
	IDToken string `json:"id_token"`
	Error   string `json:"error"`
}

func (s *Server) exchangeGoogleCode(ctx context.Context, code, verifier string) (string, error) {
	exchangeCtx, cancel := context.WithTimeout(ctx, oauthExchangeTimeout)
	defer cancel()
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", s.auth.GoogleClientID())
	form.Set("client_secret", s.auth.GoogleClientSecret())
	form.Set("redirect_uri", s.auth.GoogleRedirectURL())
	form.Set("grant_type", "authorization_code")
	form.Set("code_verifier", verifier)
	tokenRequest, err := http.NewRequestWithContext(exchangeCtx, http.MethodPost, googleTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.httpClient.Do(tokenRequest)
	if err != nil {
		return "", fmt.Errorf("token endpoint request: %w", err)
	}
	defer func() {
		if err = response.Body.Close(); err != nil {
			log.Printf("close token response body failed: %v", err)
		}
	}()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned status %d", response.StatusCode)
	}
	var payload googleTokenResponse
	if err = json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if payload.Error != "" || payload.IDToken == "" {
		return "", errors.New("token endpoint returned no id token")
	}
	return payload.IDToken, nil
}

func (s *Server) upsertGoogleUser(ctx context.Context, claims *googleIDClaims) (string, string, error) {
	userID, err := randomValue()
	if err != nil {
		return "", "", err
	}
	accountRowID, err := randomValue()
	if err != nil {
		return "", "", err
	}
	name := claims.name
	if name == "" {
		name = claims.email
	}
	row, err := s.Database.UpsertGoogleUser(ctx, repository.UpsertGoogleUserParams{
		UserID:        userID,
		UserName:      name,
		UserEmail:     claims.email,
		Image:         pgtype.Text{String: claims.picture, Valid: claims.picture != ""},
		AccountRowID:  accountRowID,
		GoogleSubject: claims.subject,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", errors.New("canonical ssh identifier unavailable: subject held by another user")
		}
		return "", "", fmt.Errorf("upsert google user: %w", err)
	}
	return row.SshIdentifier, row.UserID, nil
}

func (s *Server) startRefreshFamily(ctx context.Context, userID string) (string, error) {
	refreshToken, err := randomValue()
	if err != nil {
		return "", err
	}
	tokenID, err := randomValue()
	if err != nil {
		return "", err
	}
	familyID, err := randomValue()
	if err != nil {
		return "", err
	}
	err = s.Database.CreateRefreshToken(ctx, repository.CreateRefreshTokenParams{
		ID:        tokenID,
		UserID:    userID,
		FamilyID:  familyID,
		TokenHash: hashToken(refreshToken),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(s.auth.RefreshTokenTTL()), Valid: true},
	})
	if err != nil {
		return "", fmt.Errorf("create refresh token: %w", err)
	}
	s.cleanupExpiredRefreshTokens(ctx)
	return refreshToken, nil
}

func (s *Server) cleanupExpiredRefreshTokens(ctx context.Context) {
	if _, err := s.Database.DeleteExpiredRefreshTokens(ctx, refreshCleanupBatch); err != nil {
		log.Printf("delete expired refresh tokens failed: %v", err)
	}
}

func (s *Server) handleRefresh(writer http.ResponseWriter, request *http.Request) {
	if !s.oauthReady() {
		writeError(writer, http.StatusServiceUnavailable, errAuthUnavailable)
		return
	}
	if !s.sameOrigin(request) {
		writeError(writer, http.StatusForbidden, errCrossOrigin)
		return
	}
	cookie, err := request.Cookie(refreshCookieName)
	if err != nil || cookie.Value == "" {
		writeError(writer, http.StatusUnauthorized, errInvalidRefreshToken)
		return
	}
	tokenHash := hashToken(cookie.Value)
	refreshToken, err := randomValue()
	if err != nil {
		writeError(writer, http.StatusInternalServerError, errRefreshFailed)
		return
	}
	tokenID, err := randomValue()
	if err != nil {
		writeError(writer, http.StatusInternalServerError, errRefreshFailed)
		return
	}
	rotated, err := s.Database.RotateRefreshToken(request.Context(), repository.RotateRefreshTokenParams{
		LookupHash:   tokenHash,
		NewID:        tokenID,
		NewTokenHash: hashToken(refreshToken),
		NewExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(s.auth.RefreshTokenTTL()), Valid: true},
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Printf("rotate refresh token failed: %v", err)
			writeError(writer, http.StatusServiceUnavailable, errRefreshFailed)
			return
		}
		s.rejectRefreshToken(request.Context(), tokenHash)
		writeError(writer, http.StatusUnauthorized, errInvalidRefreshToken)
		return
	}
	s.cleanupExpiredRefreshTokens(request.Context())
	sessionToken, err := s.signSessionToken(rotated.SshIdentifier, rotated.Email)
	if err != nil {
		log.Printf("sign session token failed: %v", err)
		writeError(writer, http.StatusInternalServerError, errRefreshFailed)
		return
	}
	setSessionCookie(writer, sessionToken, s.auth.JWTTTL())
	setRefreshCookie(writer, refreshToken, s.auth.RefreshTokenTTL())
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) rejectRefreshToken(ctx context.Context, tokenHash string) {
	row, err := s.Database.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return
	}
	if err := s.Database.RevokeRefreshTokenFamily(ctx, row.FamilyID); err != nil {
		log.Printf("revoke refresh token family failed: %v", err)
	}
}

func (s *Server) handleLogout(writer http.ResponseWriter, request *http.Request) {
	if !s.oauthReady() {
		writeError(writer, http.StatusServiceUnavailable, errAuthUnavailable)
		return
	}
	if !s.sameOrigin(request) {
		writeError(writer, http.StatusForbidden, errCrossOrigin)
		return
	}
	if cookie, err := request.Cookie(refreshCookieName); err == nil && cookie.Value != "" {
		if row, err := s.Database.GetRefreshTokenByHash(request.Context(), hashToken(cookie.Value)); err == nil {
			if err := s.Database.RevokeRefreshTokenFamily(request.Context(), row.FamilyID); err != nil {
				log.Printf("revoke refresh token family failed: %v", err)
			}
		}
	}
	clearAuthCookies(writer)
	writer.WriteHeader(http.StatusNoContent)
}

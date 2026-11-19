package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"git.fossy.my.id/bagas/tunnel-please-controller/internal/config"
	proto "git.fossy.my.id/bagas/tunnel-please-grpc/gen"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	testJWTSecret    = "test-only-secret-0123456789abcdef"
	testClientID     = "test-client-id"
	testClientSecret = "test-client-secret"
	testRedirectURL  = "https://api.example.com/api/auth/callback"
	testFrontendURL  = "https://app.example.com"
	testFailureURL   = testFrontendURL + "?error=" + oauthFailureReason
)

type fakeConfig struct{}

func (fakeConfig) DatabaseURL() string            { return "" }
func (fakeConfig) ControllerAddr() string         { return "" }
func (fakeConfig) ApiAddr() string                { return "" }
func (fakeConfig) AuthToken() string              { return "test-auth-token" }
func (fakeConfig) GoogleClientID() string         { return testClientID }
func (fakeConfig) GoogleClientSecret() string     { return testClientSecret }
func (fakeConfig) GoogleRedirectURL() string      { return testRedirectURL }
func (fakeConfig) FrontendURL() string            { return testFrontendURL }
func (fakeConfig) JWTSecret() []byte              { return []byte(testJWTSecret) }
func (fakeConfig) JWTTTL() time.Duration          { return 5 * time.Minute }
func (fakeConfig) RefreshTokenTTL() time.Duration { return 720 * time.Hour }

var _ config.OAuthConfig = fakeConfig{}

func TestFlattenInterfaces(t *testing.T) {
	tests := []struct {
		name  string
		input []interface{}
		want  []interface{}
	}{
		{name: "nil input", input: nil, want: nil},
		{name: "nil entries skipped", input: []interface{}{nil}, want: nil},
		{name: "non-slice kept as-is", input: []interface{}{"a", 1}, want: []interface{}{"a", 1}},
		{
			name:  "slices flattened",
			input: []interface{}{[]string{"a", "b"}, "c", []int{1}},
			want:  []interface{}{"a", "b", "c", 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := flattenInterfaces(tt.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("flattenInterfaces() = %v, want %v", got, tt.want)
			}
		})
	}
}

func startTestAPI(t *testing.T) (*Server, string, func()) {
	t.Helper()

	srv := newOAuthReadyServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.StartAPI(ctx, addr)
	}()
	waitForListener(t, addr)

	return srv, "http://" + addr, func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("StartAPI returned error: %v", err)
		}
	}
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()

	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("api listener not reachable on %s", addr)
}

func sessionCookieValue(t *testing.T, srv *Server) string {
	t.Helper()
	token, err := srv.signSessionToken("user-1", "tester@example.com")
	if err != nil {
		t.Fatalf("sign session token: %v", err)
	}
	return token
}

func addTestSubscriber(t *testing.T, srv *Server, identity string, respond func(*proto.Events) *proto.Node) {
	t.Helper()

	sub := &Subscriber{
		node:   make(chan *proto.Node, 1),
		events: make(chan *proto.Events, 10),
		done:   make(chan struct{}),
	}
	if err := srv.AddEventSubscriber(identity, sub); err != nil {
		t.Fatalf("add subscriber: %v", err)
	}
	t.Cleanup(func() { srv.RemoveEventSubscriber(identity) })
	go func() {
		for event := range sub.events {
			sub.node <- respond(event)
		}
	}()
}

func slugResponse(success bool, message string) *proto.Node {
	return &proto.Node{Payload: &proto.Node_SlugEventResponse{SlugEventResponse: &proto.SlugChangeEventResponse{Success: success, Message: message}}}
}

func terminateResponse(success bool, message string) *proto.Node {
	return &proto.Node{Payload: &proto.Node_TerminateSessionEventResponse{TerminateSessionEventResponse: &proto.TerminateSessionEventResponse{Success: success, Message: message}}}
}

func doJSON(t *testing.T, baseURL, method, path, sessionToken, body string) (*http.Response, map[string]string) {
	t.Helper()

	req, err := http.NewRequest(method, baseURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var decoded map[string]string
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("decode body %q: %v", payload, err)
		}
	}
	return resp, decoded
}

func TestAPIAuthRejectsBadCookie(t *testing.T) {
	_, baseURL, stop := startTestAPI(t)
	defer stop()

	endpoints := []struct{ method, path, body string }{
		{http.MethodPatch, "/api/session/node1", `{"old":"a","new":"b"}`},
		{http.MethodDelete, "/api/session/node1/http/sess-1", ""},
		{http.MethodGet, "/api/sessions", ""},
	}

	t.Run("missing cookie", func(t *testing.T) {
		for _, ep := range endpoints {
			req, err := http.NewRequest(ep.method, baseURL+ep.path, strings.NewReader(ep.body))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			payload, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s status = %d, want %d", ep.method, ep.path, resp.StatusCode, http.StatusUnauthorized)
			}
			var decoded map[string]string
			if err := json.Unmarshal(payload, &decoded); err != nil {
				t.Fatalf("decode body %q: %v", payload, err)
			}
			if decoded["error"] != errInvalidToken {
				t.Errorf("%s %s error = %q, want %q", ep.method, ep.path, decoded["error"], errInvalidToken)
			}
		}
	})

	t.Run("invalid cookie", func(t *testing.T) {
		resp, decoded := doJSON(t, baseURL, http.MethodGet, "/api/sessions", "not-a-jwt", "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
		if decoded["error"] != errInvalidToken {
			t.Errorf("error = %q, want %q", decoded["error"], errInvalidToken)
		}
	})
}

func TestPatchSessionInvalidBody(t *testing.T) {
	srv, baseURL, stop := startTestAPI(t)
	defer stop()

	resp, decoded := doJSON(t, baseURL, http.MethodPatch, "/api/session/node1", sessionCookieValue(t, srv), "not-json")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type = %q, want application/json", got)
	}
	if decoded["error"] != errRequestBody {
		t.Errorf("error = %q, want %q", decoded["error"], errRequestBody)
	}
}

func TestPatchSessionUnknownNode(t *testing.T) {
	srv, baseURL, stop := startTestAPI(t)
	defer stop()

	resp, decoded := doJSON(t, baseURL, http.MethodPatch, "/api/session/ghost", sessionCookieValue(t, srv), `{"old":"a","new":"b"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if decoded["error"] != errNoNode {
		t.Errorf("error = %q, want %q", decoded["error"], errNoNode)
	}
}

func TestPatchSessionNodeResponse(t *testing.T) {
	srv, baseURL, stop := startTestAPI(t)
	defer stop()

	addTestSubscriber(t, srv, "node-ok", func(*proto.Events) *proto.Node {
		return slugResponse(true, "")
	})
	addTestSubscriber(t, srv, "node-fail", func(*proto.Events) *proto.Node {
		return slugResponse(false, "slug already taken")
	})

	token := sessionCookieValue(t, srv)
	t.Run("success returns 204", func(t *testing.T) {
		resp, _ := doJSON(t, baseURL, http.MethodPatch, "/api/session/node-ok", token, `{"old":"a","new":"b"}`)
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
	})
	t.Run("node failure surfaces message as 400", func(t *testing.T) {
		resp, decoded := doJSON(t, baseURL, http.MethodPatch, "/api/session/node-fail", token, `{"old":"a","new":"b"}`)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		if decoded["error"] != "slug already taken" {
			t.Errorf("error = %q, want node message", decoded["error"])
		}
	})
}

func TestPatchSessionNilNodeResponse(t *testing.T) {
	srv, baseURL, stop := startTestAPI(t)
	defer stop()

	addTestSubscriber(t, srv, "node-nil", func(*proto.Events) *proto.Node { return nil })

	resp, decoded := doJSON(t, baseURL, http.MethodPatch, "/api/session/node-nil", sessionCookieValue(t, srv), `{"old":"a","new":"b"}`)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	if decoded["error"] != errUnexpectedNode {
		t.Errorf("error = %q, want unexpected response message", decoded["error"])
	}
}

func TestDeleteSessionInvalidType(t *testing.T) {
	srv, baseURL, stop := startTestAPI(t)
	defer stop()

	resp, decoded := doJSON(t, baseURL, http.MethodDelete, "/api/session/node1/udp/sess-1", sessionCookieValue(t, srv), "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if decoded["error"] != errSessionType {
		t.Errorf("error = %q, want %q", decoded["error"], errSessionType)
	}
}

func TestDeleteSessionNodeResponse(t *testing.T) {
	srv, baseURL, stop := startTestAPI(t)
	defer stop()

	addTestSubscriber(t, srv, "node-ok", func(*proto.Events) *proto.Node {
		return terminateResponse(true, "")
	})
	addTestSubscriber(t, srv, "node-fail", func(*proto.Events) *proto.Node {
		return terminateResponse(false, "session not found")
	})

	token := sessionCookieValue(t, srv)
	t.Run("success returns 204", func(t *testing.T) {
		resp, _ := doJSON(t, baseURL, http.MethodDelete, "/api/session/node-ok/http/sess-1", token, "")
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
	})
	t.Run("node failure surfaces message as 400", func(t *testing.T) {
		resp, decoded := doJSON(t, baseURL, http.MethodDelete, "/api/session/node-fail/tcp/sess-1", token, "")
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		if decoded["error"] != "session not found" {
			t.Errorf("error = %q, want node message", decoded["error"])
		}
	})
}

func TestGetSessions(t *testing.T) {
	t.Run("no subscribers returns empty array", func(t *testing.T) {
		srv, baseURL, stop := startTestAPI(t)
		defer stop()

		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/sessions", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookieValue(t, srv)})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q, want application/json", got)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != "[]" {
			t.Errorf("body = %q, want []", body)
		}
	})

	t.Run("flattens node details", func(t *testing.T) {
		srv, baseURL, stop := startTestAPI(t)
		defer stop()

		addTestSubscriber(t, srv, "node1", func(event *proto.Events) *proto.Node {
			if event.GetType() != proto.EventType_GET_SESSIONS {
				return nil
			}
			return &proto.Node{Payload: &proto.Node_GetSessionsEvent{GetSessionsEvent: &proto.GetSessionsResponse{
				Details: []*proto.Detail{{Node: "node1", Slug: "demo", UserId: "tester@example.com"}},
			}}}
		})

		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/sessions", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookieValue(t, srv)})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q, want application/json", got)
		}
		var details []proto.Detail
		if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if len(details) != 1 || details[0].Slug != "demo" {
			t.Errorf("details = %+v, want one slug demo entry", details)
		}
	})
}

func newOAuthReadyServer(t *testing.T) *Server {
	t.Helper()
	cache, err := jwk.NewCache(context.Background(), httprc.NewClient())
	if err != nil {
		t.Fatalf("build jwk cache: %v", err)
	}
	return New(nil, cache, fakeConfig{})
}

func callLogin(t *testing.T, srv *Server) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handleLogin(rec, httptest.NewRequest(http.MethodGet, "/api/auth/login", nil))
	return rec
}

func recorderCookies(rec *httptest.ResponseRecorder) []*http.Cookie {
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	return resp.Cookies()
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func assertRedirect(t *testing.T, rec *httptest.ResponseRecorder, wantURL string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != wantURL {
		t.Errorf("location = %q, want %q", got, wantURL)
	}
}

func TestLoginRedirectsToGoogleWithStateCookie(t *testing.T) {
	srv := newOAuthReadyServer(t)

	rec := callLogin(t, srv)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if location.Scheme != "https" || location.Host != "accounts.google.com" || location.Path != "/o/oauth2/v2/auth" {
		t.Errorf("location = %q, want google authorization endpoint", location)
	}
	query := location.Query()
	if query.Get("client_id") != testClientID {
		t.Errorf("client_id = %q, want %q", query.Get("client_id"), testClientID)
	}
	if query.Get("redirect_uri") != testRedirectURL {
		t.Errorf("redirect_uri = %q, want %q", query.Get("redirect_uri"), testRedirectURL)
	}
	if query.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", query.Get("response_type"))
	}
	if query.Get("scope") != oauthScope {
		t.Errorf("scope = %q, want %q", query.Get("scope"), oauthScope)
	}
	if query.Get("code_challenge_method") != pkceChallengeMethod {
		t.Errorf("code_challenge_method = %q, want %q", query.Get("code_challenge_method"), pkceChallengeMethod)
	}
	for _, key := range []string{"state", "nonce", "code_challenge"} {
		if query.Get(key) == "" {
			t.Errorf("query %s is empty", key)
		}
	}

	stateCookie := findCookie(recorderCookies(rec), oauthStateCookieName)
	if stateCookie == nil {
		t.Fatal("state cookie not set")
	}
	if !stateCookie.HttpOnly || !stateCookie.Secure || stateCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("state cookie flags = httponly %t, secure %t, samesite %v, want httponly, secure, lax", stateCookie.HttpOnly, stateCookie.Secure, stateCookie.SameSite)
	}
	if stateCookie.Path != oauthStateCookiePath {
		t.Errorf("state cookie path = %q, want %q", stateCookie.Path, oauthStateCookiePath)
	}
	if stateCookie.MaxAge != int(oauthStateTTL.Seconds()) {
		t.Errorf("state cookie max age = %d, want %d", stateCookie.MaxAge, int(oauthStateTTL.Seconds()))
	}

	stateToken, err := jwt.Parse([]byte(stateCookie.Value),
		jwt.WithKey(jwa.HS256(), []byte(testJWTSecret)),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(jwtAudience),
	)
	if err != nil {
		t.Fatalf("parse state cookie: %v", err)
	}
	var cookieState string
	if err := stateToken.Get("state", &cookieState); err != nil {
		t.Fatalf("read state claim: %v", err)
	}
	if cookieState != query.Get("state") {
		t.Errorf("state claim %q does not match redirect state %q", cookieState, query.Get("state"))
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	srv := newOAuthReadyServer(t)

	loginRec := callLogin(t, srv)
	stateCookie := findCookie(recorderCookies(loginRec), oauthStateCookieName)
	if stateCookie == nil {
		t.Fatal("state cookie not set on login")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?state=tampered-state&code=auth-code", nil)
	req.AddCookie(stateCookie)
	srv.handleCallback(rec, req)

	assertRedirect(t, rec, testFailureURL)
	cleared := findCookie(recorderCookies(rec), oauthStateCookieName)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("state cookie not cleared: %+v", cleared)
	}
}

func TestCallbackRejectsWithoutExchange(t *testing.T) {
	srv := newOAuthReadyServer(t)

	loginRec := callLogin(t, srv)
	stateCookie := findCookie(recorderCookies(loginRec), oauthStateCookieName)
	if stateCookie == nil {
		t.Fatal("state cookie not set on login")
	}
	var stateToken struct {
		State string `json:"state"`
	}
	parsed, err := jwt.Parse([]byte(stateCookie.Value), jwt.WithKey(jwa.HS256(), []byte(testJWTSecret)), jwt.WithIssuer(jwtIssuer), jwt.WithAudience(jwtAudience))
	if err != nil {
		t.Fatalf("parse state cookie: %v", err)
	}
	if err := parsed.Get("state", &stateToken.State); err != nil {
		t.Fatalf("read state claim: %v", err)
	}

	tests := []struct {
		name       string
		query      string
		withCookie bool
	}{
		{name: "missing state cookie", query: "state=" + stateToken.State + "&code=auth-code", withCookie: false},
		{name: "missing state param", query: "code=auth-code", withCookie: true},
		{name: "google error response", query: "state=" + stateToken.State + "&error=access_denied", withCookie: true},
		{name: "missing code", query: "state=" + stateToken.State, withCookie: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/auth/callback?"+tt.query, nil)
			if tt.withCookie {
				req.AddCookie(stateCookie)
			}
			srv.handleCallback(rec, req)

			assertRedirect(t, rec, testFailureURL)
		})
	}
}

func TestOAuthNotReady(t *testing.T) {
	srv := New(nil, nil, fakeConfig{})

	loginRec := callLogin(t, srv)
	if loginRec.Code != http.StatusServiceUnavailable {
		t.Errorf("login status = %d, want %d", loginRec.Code, http.StatusServiceUnavailable)
	}
	var decoded map[string]string
	if err := json.Unmarshal(loginRec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode body %q: %v", loginRec.Body.String(), err)
	}
	if decoded["error"] != errAuthUnavailable {
		t.Errorf("login error = %q, want %q", decoded["error"], errAuthUnavailable)
	}

	callbackRec := httptest.NewRecorder()
	srv.handleCallback(callbackRec, httptest.NewRequest(http.MethodGet, "/api/auth/callback", nil))
	assertRedirect(t, callbackRec, testFailureURL)
}

var _ config.Config = fakeConfig{}

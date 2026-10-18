package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sentinel-bpf/sentinel/internal/config"
	"github.com/sentinel-bpf/sentinel/internal/container"
	"github.com/sentinel-bpf/sentinel/internal/hub"
	"github.com/sentinel-bpf/sentinel/internal/proctable"
	"github.com/sentinel-bpf/sentinel/internal/rules"
)

func setupTestServer(authToken string) (*Server, http.Handler) {
	cfg := config.DefaultConfig()
	cfg.Server.AuthToken = authToken
	cfg.Server.AllowedOrigins = []string{"http://trusted.domain"}

	h := hub.New()
	pt := proctable.New(100)
	ct := container.New(100)
	re := rules.NewEngine(cfg, pt, ct)

	pt.Put(&proctable.ProcessInfo{
		Pid:  1234,
		Ppid: 1,
		Comm: "test_daemon",
		Path: "/usr/bin/test_daemon",
	})

	srv := NewServer(cfg, h, re, pt)
	return srv, srv.Handler()
}

func TestHealthEndpoint(t *testing.T) {
	_, handler := setupTestServer("")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", res["status"])
	}
}

func TestAuthEnforcement(t *testing.T) {
	_, handler := setupTestServer("secret-token-123")

	// 1. Request without token -> 401
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rrNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrNoAuth, reqNoAuth)
	if rrNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rrNoAuth.Code)
	}

	// 2. Request with valid Bearer token -> 200
	reqValid := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	reqValid.Header.Set("Authorization", "Bearer secret-token-123")
	rrValid := httptest.NewRecorder()
	handler.ServeHTTP(rrValid, reqValid)
	if rrValid.Code != http.StatusOK {
		t.Errorf("expected 200 OK with valid bearer token, got %d", rrValid.Code)
	}

	// 3. Request with valid query parameter token -> 200
	reqQuery := httptest.NewRequest(http.MethodGet, "/api/v1/status?token=secret-token-123", nil)
	rrQuery := httptest.NewRecorder()
	handler.ServeHTTP(rrQuery, reqQuery)
	if rrQuery.Code != http.StatusOK {
		t.Errorf("expected 200 OK with query token, got %d", rrQuery.Code)
	}
}

func TestProcessDetailEndpoint(t *testing.T) {
	_, handler := setupTestServer("")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/process/1234", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	proc, ok := res["process"].(map[string]interface{})
	if !ok || proc["comm"] != "test_daemon" {
		t.Errorf("expected process comm 'test_daemon', got %v", proc)
	}
}

func TestOriginCheck(t *testing.T) {
	srv, _ := setupTestServer("")

	// Localhost allowed
	r1 := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r1.Header.Set("Origin", "http://localhost:3000")
	if !srv.checkOrigin(r1) {
		t.Error("expected localhost origin to be allowed")
	}

	// Trusted domain in config allowed
	r2 := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r2.Header.Set("Origin", "http://trusted.domain")
	if !srv.checkOrigin(r2) {
		t.Error("expected configured trusted origin to be allowed")
	}

	// Untrusted domain rejected
	r3 := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r3.Header.Set("Origin", "http://evil.hacker.com")
	if srv.checkOrigin(r3) {
		t.Error("expected untrusted origin to be rejected")
	}
}

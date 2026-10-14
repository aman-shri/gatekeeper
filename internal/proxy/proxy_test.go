package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aman-shri/gatekeeper/internal/auth"
	"github.com/aman-shri/gatekeeper/internal/config"
)

func TestGateway_HealthCheck(t *testing.T) {
	cfg := config.NewDefaultConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	expected := `{"status":"ok","service":"gatekeeper"}`
	if rec.Body.String() != expected {
		t.Errorf("expected body %q, got %q", expected, rec.Body.String())
	}
}

func TestGateway_ProxyForwarding(t *testing.T) {
	// 1. Create a mock upstream backend server
	var receivedHeader string
	var receivedPath string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Gateway")
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"upstream":"success"}`))
	}))
	defer upstream.Close()

	// 2. Configure gateway routing to upstream
	cfg := config.NewDefaultConfig()
	cfg.Routes = []config.Route{
		{
			PathPrefix: "/api/service",
			TargetURL:  upstream.URL,
		},
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// 3. Send request through Gateway
	req := httptest.NewRequest(http.MethodGet, "/api/service/items/123", nil)
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	// 4. Assert client response and upstream inspection
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	if receivedHeader != "Gatekeeper" {
		t.Errorf("expected upstream to receive X-Gateway header, got %q", receivedHeader)
	}

	if receivedPath != "/api/service/items/123" {
		t.Errorf("expected upstream path /api/service/items/123, got %q", receivedPath)
	}

	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"upstream":"success"}` {
		t.Errorf("unexpected client body: %s", body)
	}
}

func TestGateway_StripPrefix(t *testing.T) {
	var upstreamPath string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.NewDefaultConfig()
	cfg.Routes = []config.Route{
		{
			PathPrefix:  "/api/v1",
			TargetURL:   upstream.URL,
			StripPrefix: true,
		},
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orders/create", nil)
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	if upstreamPath != "/orders/create" {
		t.Errorf("expected stripped path /orders/create, got %q", upstreamPath)
	}
}

func TestGateway_RouteNotFound(t *testing.T) {
	cfg := config.NewDefaultConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/unregistered/path", nil)
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error != "ROUTE_NOT_FOUND" {
		t.Errorf("expected error code ROUTE_NOT_FOUND, got %q", errResp.Error)
	}
}

func TestGateway_UpstreamUnavailable(t *testing.T) {
	// Create and immediately close an upstream server to simulate connection failure
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	upstreamURL := upstream.URL
	upstream.Close()

	cfg := config.NewDefaultConfig()
	cfg.Routes = []config.Route{
		{
			PathPrefix: "/api/dead",
			TargetURL:  upstreamURL,
		},
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/dead/action", nil)
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", rec.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error != "UPSTREAM_UNAVAILABLE" {
		t.Errorf("expected error code UPSTREAM_UNAVAILABLE, got %q", errResp.Error)
	}
}

func TestGateway_RateLimiting(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"success"}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultConfig()
	cfg.Routes = []config.Route{
		{
			PathPrefix: "/api/limited",
			TargetURL:  upstream.URL,
			RateLimit:  2,
			Window:     10 * time.Second,
		},
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	defer func() { _ = gw.Close() }()

	clientA := "192.0.2.1:1111"
	clientB := "192.0.2.2:2222"

	// Request 1 from Client A: Allowed (remaining 1)
	req1 := httptest.NewRequest(http.MethodGet, "/api/limited/items", nil)
	req1.RemoteAddr = clientA
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("Client A req 1: expected 200, got %d", rec1.Code)
	}
	if rec1.Header().Get("X-RateLimit-Remaining") != "1" {
		t.Errorf("Client A req 1: expected remaining 1, got %s", rec1.Header().Get("X-RateLimit-Remaining"))
	}

	// Request 2 from Client A: Allowed (remaining 0)
	req2 := httptest.NewRequest(http.MethodGet, "/api/limited/items", nil)
	req2.RemoteAddr = clientA
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("Client A req 2: expected 200, got %d", rec2.Code)
	}
	if rec2.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("Client A req 2: expected remaining 0, got %s", rec2.Header().Get("X-RateLimit-Remaining"))
	}

	// Request 3 from Client A: Throttled (429)
	req3 := httptest.NewRequest(http.MethodGet, "/api/limited/items", nil)
	req3.RemoteAddr = clientA
	rec3 := httptest.NewRecorder()
	gw.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusTooManyRequests {
		t.Errorf("Client A req 3: expected 429, got %d", rec3.Code)
	}
	if rec3.Header().Get("Retry-After") == "" {
		t.Errorf("Client A req 3: expected Retry-After header, got empty")
	}

	// Request from Client B: Allowed (independent quota!)
	reqB := httptest.NewRequest(http.MethodGet, "/api/limited/items", nil)
	reqB.RemoteAddr = clientB
	recB := httptest.NewRecorder()
	gw.ServeHTTP(recB, reqB)

	if recB.Code != http.StatusOK {
		t.Errorf("Client B req 1: expected 200, got %d", recB.Code)
	}
	if recB.Header().Get("X-RateLimit-Remaining") != "1" {
		t.Errorf("Client B req 1: expected remaining 1, got %s", recB.Header().Get("X-RateLimit-Remaining"))
	}
}

func TestGateway_AuthAndHeaderPropagation(t *testing.T) {
	var capturedHeaders http.Header

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	jwtSecret := "gatekeeper-jwt-integration-secret-32b"
	cfg := config.NewDefaultConfig()
	cfg.Auth = config.AuthConfig{
		JWTSecret: jwtSecret,
		APIKeys: []config.APIKeyConfig{
			{
				Key:      "api_key_admin_123",
				TenantID: "tenant-enterprise",
				Tier:     "enterprise",
				Roles:    []string{"admin", "editor"},
				Enabled:  true,
			},
			{
				Key:      "api_key_viewer_456",
				TenantID: "tenant-free",
				Tier:     "free",
				Roles:    []string{"viewer"},
				Enabled:  true,
			},
		},
	}
	cfg.Routes = []config.Route{
		{
			PathPrefix:    "/api/secure/admin",
			TargetURL:     upstream.URL,
			AuthRequired:  true,
			AuthType:      "any",
			RequiredRoles: []string{"admin"},
		},
		{
			PathPrefix:   "/api/secure/any",
			TargetURL:    upstream.URL,
			AuthRequired: true,
			AuthType:     "any",
		},
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	defer func() { _ = gw.Close() }()

	// 1. Missing credentials on protected route returns 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/secure/admin/users", nil)
	recUnauth := httptest.NewRecorder()
	gw.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", recUnauth.Code)
	}

	// 2. Insufficient role returns 403 Forbidden
	reqForbidden := httptest.NewRequest(http.MethodGet, "/api/secure/admin/users", nil)
	reqForbidden.Header.Set("X-API-Key", "api_key_viewer_456")
	recForbidden := httptest.NewRecorder()
	gw.ServeHTTP(recForbidden, reqForbidden)
	if recForbidden.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", recForbidden.Code)
	}

	// 3. Valid API Key with admin role succeeds (200) and propagates headers upstream
	reqAdmin := httptest.NewRequest(http.MethodGet, "/api/secure/admin/users", nil)
	reqAdmin.Header.Set("X-API-Key", "api_key_admin_123")
	recAdmin := httptest.NewRecorder()
	gw.ServeHTTP(recAdmin, reqAdmin)

	if recAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", recAdmin.Code)
	}
	if recAdmin.Header().Get("X-Request-ID") == "" {
		t.Errorf("expected X-Request-ID in client response headers")
	}

	if capturedHeaders.Get("X-Tenant-ID") != "tenant-enterprise" {
		t.Errorf("expected upstream X-Tenant-ID 'tenant-enterprise', got %q", capturedHeaders.Get("X-Tenant-ID"))
	}
	if capturedHeaders.Get("X-Tenant-Tier") != "enterprise" {
		t.Errorf("expected upstream X-Tenant-Tier 'enterprise', got %q", capturedHeaders.Get("X-Tenant-Tier"))
	}
	if capturedHeaders.Get("X-Request-ID") == "" {
		t.Errorf("expected upstream X-Request-ID to be propagated")
	}

	// 4. Valid JWT on /api/secure/any succeeds and propagates claims upstream
	tokenString, err := gw.JWTValidator().GenerateToken(auth.Claims{
		TenantID: "tenant-acme-jwt",
		UserID:   "usr-bob",
		Tier:     "pro",
		Roles:    []string{"developer"},
	})
	if err != nil {
		t.Fatalf("failed to generate test JWT: %v", err)
	}

	reqJWT := httptest.NewRequest(http.MethodGet, "/api/secure/any/data", nil)
	reqJWT.Header.Set("Authorization", "Bearer "+tokenString)
	recJWT := httptest.NewRecorder()
	gw.ServeHTTP(recJWT, reqJWT)

	if recJWT.Code != http.StatusOK {
		t.Errorf("expected 200 OK for valid JWT, got %d", recJWT.Code)
	}
	if capturedHeaders.Get("X-Tenant-ID") != "tenant-acme-jwt" {
		t.Errorf("expected upstream X-Tenant-ID 'tenant-acme-jwt', got %q", capturedHeaders.Get("X-Tenant-ID"))
	}
	if capturedHeaders.Get("X-User-ID") != "usr-bob" {
		t.Errorf("expected upstream X-User-ID 'usr-bob', got %q", capturedHeaders.Get("X-User-ID"))
	}
}

func TestGateway_MultiTenantTieredRateLimiting(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.NewDefaultConfig()
	cfg.Auth = config.AuthConfig{
		APIKeys: []config.APIKeyConfig{
			{
				Key:               "key_enterprise_vip",
				TenantID:          "tenant-vip",
				Tier:              "enterprise",
				RateLimitOverride: 5, // Custom override: 5 req/min instead of route limit 2
				Enabled:           true,
			},
			{
				Key:      "key_standard",
				TenantID: "tenant-standard",
				Tier:     "free",
				Enabled:  true, // Uses default route limit 2
			},
		},
	}
	cfg.Routes = []config.Route{
		{
			PathPrefix:   "/api/metered",
			TargetURL:    upstream.URL,
			AuthRequired: true,
			RateLimit:    2, // default route quota is 2
			Window:       time.Minute,
		},
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	defer func() { _ = gw.Close() }()

	// Standard tenant: 1st and 2nd allowed, 3rd throttled (429)
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/metered/res", nil)
		req.Header.Set("X-API-Key", "key_standard")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("standard req %d: expected 200, got %d", i, rec.Code)
		}
	}

	req3 := httptest.NewRequest(http.MethodGet, "/api/metered/res", nil)
	req3.Header.Set("X-API-Key", "key_standard")
	rec3 := httptest.NewRecorder()
	gw.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Errorf("standard req 3: expected 429 Too Many Requests, got %d", rec3.Code)
	}

	// VIP tenant: has RateLimitOverride = 5, so can make 5 requests successfully!
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/metered/res", nil)
		req.Header.Set("X-API-Key", "key_enterprise_vip")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("VIP req %d: expected 200, got %d", i, rec.Code)
		}
	}

	// VIP 6th request: throttled (429)
	req6 := httptest.NewRequest(http.MethodGet, "/api/metered/res", nil)
	req6.Header.Set("X-API-Key", "key_enterprise_vip")
	rec6 := httptest.NewRecorder()
	gw.ServeHTTP(rec6, req6)
	if rec6.Code != http.StatusTooManyRequests {
		t.Errorf("VIP req 6: expected 429 Too Many Requests, got %d", rec6.Code)
	}
}


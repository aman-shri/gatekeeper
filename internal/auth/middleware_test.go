package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aman-shri/gatekeeper/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

func TestAuthMiddleware(t *testing.T) {
	secret := "test-secret-key-gatekeeper-auth"
	jwtVal := NewJWTValidator(secret, "", "")
	keyStore := NewMemoryKeyStore([]config.APIKeyConfig{
		{
			Key:      "valid_admin_key",
			TenantID: "tenant-corp",
			Tier:     "pro",
			Roles:    []string{"admin"},
			Enabled:  true,
		},
		{
			Key:      "valid_user_key",
			TenantID: "tenant-individual",
			Tier:     "free",
			Roles:    []string{"user"},
			Enabled:  true,
		},
	})

	mw := NewAuthMiddleware(jwtVal, keyStore)

	// Helper downstream handler that inspects context
	downstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, hasID := GetIdentity(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if hasID && id != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authenticated": true,
				"tenant_id":     id.TenantID,
				"roles":         id.Roles,
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
		}
	})

	t.Run("public route allows unauthenticated traffic", func(t *testing.T) {
		publicRoute := config.Route{
			PathPrefix:   "/public",
			AuthRequired: false,
		}
		handler := mw.Wrap(publicRoute, downstreamHandler)

		req := httptest.NewRequest("GET", "/public/ping", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("public route attaches optional identity when provided", func(t *testing.T) {
		publicRoute := config.Route{
			PathPrefix:   "/public",
			AuthRequired: false,
		}
		handler := mw.Wrap(publicRoute, downstreamHandler)

		req := httptest.NewRequest("GET", "/public/ping", nil)
		req.Header.Set("X-API-Key", "valid_admin_key")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		var body map[string]any
		_ = json.NewDecoder(rec.Body).Decode(&body)
		if body["tenant_id"] != "tenant-corp" {
			t.Errorf("expected tenant_id 'tenant-corp', got %v", body["tenant_id"])
		}
	})

	t.Run("protected route rejects missing credentials with 401", func(t *testing.T) {
		protectedRoute := config.Route{
			PathPrefix:   "/secure",
			AuthRequired: true,
			AuthType:     "any",
		}
		handler := mw.Wrap(protectedRoute, downstreamHandler)

		req := httptest.NewRequest("GET", "/secure/data", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}

		var resp AuthResponse
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		if resp.Error != "UNAUTHORIZED" {
			t.Errorf("expected error 'UNAUTHORIZED', got %s", resp.Error)
		}
	})

	t.Run("protected route accepts valid API Key", func(t *testing.T) {
		protectedRoute := config.Route{
			PathPrefix:   "/secure",
			AuthRequired: true,
			AuthType:     "api_key",
		}
		handler := mw.Wrap(protectedRoute, downstreamHandler)

		req := httptest.NewRequest("GET", "/secure/data", nil)
		req.Header.Set("X-API-Key", "valid_user_key")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("protected route accepts valid Bearer JWT", func(t *testing.T) {
		token, err := jwtVal.GenerateToken(Claims{
			TenantID: "tenant-jwt",
			UserID:   "usr-jwt",
			Roles:    []string{"user"},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			},
		})
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		protectedRoute := config.Route{
			PathPrefix:   "/secure",
			AuthRequired: true,
			AuthType:     "jwt",
		}
		handler := mw.Wrap(protectedRoute, downstreamHandler)

		req := httptest.NewRequest("GET", "/secure/data", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("RBAC blocks user with insufficient role with 403", func(t *testing.T) {
		adminOnlyRoute := config.Route{
			PathPrefix:    "/admin",
			AuthRequired:  true,
			AuthType:      "any",
			RequiredRoles: []string{"admin"},
		}
		handler := mw.Wrap(adminOnlyRoute, downstreamHandler)

		req := httptest.NewRequest("GET", "/admin/settings", nil)
		req.Header.Set("X-API-Key", "valid_user_key") // only has 'user' role
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
		}

		var resp AuthResponse
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		if resp.Error != "FORBIDDEN" {
			t.Errorf("expected error 'FORBIDDEN', got %s", resp.Error)
		}
	})

	t.Run("RBAC permits user with matching role with 200", func(t *testing.T) {
		adminOnlyRoute := config.Route{
			PathPrefix:    "/admin",
			AuthRequired:  true,
			AuthType:      "any",
			RequiredRoles: []string{"admin"},
		}
		handler := mw.Wrap(adminOnlyRoute, downstreamHandler)

		req := httptest.NewRequest("GET", "/admin/settings", nil)
		req.Header.Set("X-API-Key", "valid_admin_key") // has 'admin' role
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
	})
}

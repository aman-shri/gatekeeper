package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aman-shri/gatekeeper/internal/config"
)

// AuthResponse defines structured JSON error payloads returned on 401/403.
type AuthResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
}

// AuthMiddleware manages token verification, API key lookups, and RBAC authorization.
type AuthMiddleware struct {
	jwtValidator *JWTValidator
	keyStore     KeyStore
}

// NewAuthMiddleware constructs a new authentication & authorization middleware.
func NewAuthMiddleware(jwtValidator *JWTValidator, keyStore KeyStore) *AuthMiddleware {
	return &AuthMiddleware{
		jwtValidator: jwtValidator,
		keyStore:     keyStore,
	}
}

// Wrap applies authentication and RBAC authorization rules to an upstream route.
func (m *AuthMiddleware) Wrap(route config.Route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := m.authenticate(r, route.AuthType)

		// 1. If authentication is mandatory for this route
		if route.AuthRequired {
			if err != nil || identity == nil {
				m.writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "Valid authentication credentials are required for this route")
				return
			}

			// 2. Check RBAC permissions if roles are required
			if len(route.RequiredRoles) > 0 && !identity.HasAnyRole(route.RequiredRoles) {
				m.writeError(w, r, http.StatusForbidden, "FORBIDDEN", "Insufficient permissions to access this route")
				return
			}
		}

		// 3. If identity was authenticated (even optionally), inject it into context
		ctx := r.Context()
		if identity != nil {
			ctx = WithIdentity(ctx, identity)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate attempts to resolve an identity using the configured auth schemes.
func (m *AuthMiddleware) authenticate(r *http.Request, allowedScheme string) (*Identity, error) {
	if allowedScheme == "" {
		allowedScheme = "any"
	}

	// 1. Try API Key if allowed
	if allowedScheme == "api_key" || allowedScheme == "any" {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}

		if apiKey != "" && m.keyStore != nil {
			if id, ok := m.keyStore.Lookup(apiKey); ok {
				return id, nil
			}
		}
	}

	// 2. Try Bearer JWT if allowed
	if allowedScheme == "jwt" || allowedScheme == "any" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			tokenString := strings.TrimSpace(authHeader[7:])
			if tokenString != "" && m.jwtValidator != nil {
				id, err := m.jwtValidator.Validate(tokenString)
				if err == nil && id != nil {
					return id, nil
				}
				// If bearer header was explicitly sent with an invalid token, return the error
				return nil, err
			}
		}
	}

	return nil, ErrMissingToken
}

func (m *AuthMiddleware) writeError(w http.ResponseWriter, r *http.Request, status int, errCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := AuthResponse{
		Error:   errCode,
		Message: message,
		Path:    r.URL.Path,
		Status:  status,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

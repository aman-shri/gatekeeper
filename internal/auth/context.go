package auth

import (
	"context"
	"strings"
)

type contextKey int

const (
	identityKey contextKey = iota
	requestIDKey
)

// Identity represents the authenticated caller context (tenant and/or individual user).
type Identity struct {
	// TenantID uniquely identifies the organization / account.
	TenantID string `json:"tenant_id"`
	// UserID uniquely identifies the individual user or client.
	UserID string `json:"user_id"`
	// Email is the optional user email associated with the token.
	Email string `json:"email,omitempty"`
	// Tier identifies the subscription tier (e.g. "free", "pro", "enterprise").
	Tier string `json:"tier"`
	// Roles contains security roles assigned to this identity (e.g. ["admin", "read", "write"]).
	Roles []string `json:"roles"`
	// AuthType indicates which mechanism authenticated this caller ("api_key" or "jwt").
	AuthType string `json:"auth_type"`
	// RateLimitOverride specifies a custom per-minute quota for this identity (0 means use route limit).
	RateLimitOverride int `json:"rate_limit_override,omitempty"`
}

// WithIdentity injects an authenticated Identity into the context.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// GetIdentity retrieves the authenticated Identity from the context, if present.
func GetIdentity(ctx context.Context) (*Identity, bool) {
	if ctx == nil {
		return nil, false
	}
	id, ok := ctx.Value(identityKey).(*Identity)
	return id, ok && id != nil
}

// WithRequestID injects a correlation request ID into the context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves the correlation request ID from the context.
func GetRequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if reqID, ok := ctx.Value(requestIDKey).(string); ok {
		return reqID
	}
	return ""
}

// HasRole checks whether the identity contains the specified role.
func (id *Identity) HasRole(role string) bool {
	if id == nil {
		return false
	}
	for _, r := range id.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// HasAnyRole checks whether the identity possesses at least one of the specified roles.
func (id *Identity) HasAnyRole(roles []string) bool {
	if len(roles) == 0 {
		return true
	}
	if id == nil {
		return false
	}
	for _, reqRole := range roles {
		if id.HasRole(reqRole) {
			return true
		}
	}
	return false
}

// HasAllRoles checks whether the identity possesses all of the specified roles.
func (id *Identity) HasAllRoles(roles []string) bool {
	if len(roles) == 0 {
		return true
	}
	if id == nil {
		return false
	}
	for _, reqRole := range roles {
		if !id.HasRole(reqRole) {
			return false
		}
	}
	return true
}

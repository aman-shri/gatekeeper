package auth

import (
	"context"
	"testing"
)

func TestIdentity_RoleChecks(t *testing.T) {
	id := &Identity{
		TenantID: "tenant-123",
		UserID:   "usr-456",
		Tier:     "pro",
		Roles:    []string{"admin", "billing:read"},
		AuthType: "jwt",
	}

	if !id.HasRole("admin") {
		t.Errorf("expected HasRole('admin') to be true")
	}
	if !id.HasRole("ADMIN") {
		t.Errorf("expected HasRole case-insensitivity to pass")
	}
	if id.HasRole("superadmin") {
		t.Errorf("expected HasRole('superadmin') to be false")
	}

	if !id.HasAnyRole([]string{"editor", "admin"}) {
		t.Errorf("expected HasAnyRole with admin to be true")
	}
	if id.HasAnyRole([]string{"editor", "viewer"}) {
		t.Errorf("expected HasAnyRole without match to be false")
	}

	if !id.HasAllRoles([]string{"admin", "billing:read"}) {
		t.Errorf("expected HasAllRoles to pass")
	}
	if id.HasAllRoles([]string{"admin", "editor"}) {
		t.Errorf("expected HasAllRoles with missing role to be false")
	}
}

func TestContext_IdentityAndRequestID(t *testing.T) {
	ctx := context.Background()

	// Initial empty context
	if _, ok := GetIdentity(ctx); ok {
		t.Errorf("expected no identity on clean context")
	}
	if reqID := GetRequestID(ctx); reqID != "" {
		t.Errorf("expected empty request ID on clean context, got %q", reqID)
	}

	// Inject and retrieve
	id := &Identity{TenantID: "org-1", UserID: "u-1"}
	ctxWithID := WithIdentity(ctx, id)
	retrievedID, ok := GetIdentity(ctxWithID)
	if !ok || retrievedID.TenantID != "org-1" {
		t.Errorf("failed to retrieve injected identity")
	}

	ctxWithAll := WithRequestID(ctxWithID, "req-xyz-123")
	if reqID := GetRequestID(ctxWithAll); reqID != "req-xyz-123" {
		t.Errorf("expected request ID 'req-xyz-123', got %q", reqID)
	}
}

package auth

import (
	"testing"

	"github.com/aman-shri/gatekeeper/internal/config"
)

func TestMemoryKeyStore_Operations(t *testing.T) {
	initialKeys := []config.APIKeyConfig{
		{
			Key:               "live_key_enterprise_123",
			TenantID:          "tenant-enterprise",
			Tier:              "enterprise",
			Roles:             []string{"admin", "write"},
			RateLimitOverride: 5000,
			Enabled:           true,
		},
		{
			Key:      "live_key_disabled_456",
			TenantID: "tenant-suspended",
			Tier:     "free",
			Enabled:  false,
		},
	}

	store := NewMemoryKeyStore(initialKeys)

	// 1. Verify count
	if count := store.Count(); count != 1 {
		t.Errorf("expected 1 active key, got %d", count)
	}

	// 2. Lookup active key
	id, ok := store.Lookup("live_key_enterprise_123")
	if !ok || id == nil {
		t.Fatalf("expected to find active enterprise key")
	}
	if id.TenantID != "tenant-enterprise" || id.Tier != "enterprise" {
		t.Errorf("unexpected identity attributes: %+v", id)
	}
	if id.RateLimitOverride != 5000 {
		t.Errorf("expected RateLimitOverride 5000, got %d", id.RateLimitOverride)
	}
	if !id.HasRole("admin") {
		t.Errorf("expected admin role on enterprise identity")
	}

	// 3. Lookup disabled key
	if _, ok := store.Lookup("live_key_disabled_456"); ok {
		t.Errorf("expected disabled key lookup to fail")
	}

	// 4. Lookup non-existent key
	if _, ok := store.Lookup("non_existent_key"); ok {
		t.Errorf("expected non-existent key lookup to fail")
	}

	// 5. Add dynamic key
	store.AddKey(config.APIKeyConfig{
		Key:      "dynamic_key_pro_789",
		TenantID: "tenant-dynamic",
		Tier:     "pro",
		Enabled:  true,
	})
	if count := store.Count(); count != 2 {
		t.Errorf("expected 2 active keys, got %d", count)
	}

	// 6. Revoke active key
	store.RevokeKey("live_key_enterprise_123")
	if _, ok := store.Lookup("live_key_enterprise_123"); ok {
		t.Errorf("expected revoked key lookup to fail")
	}
	if count := store.Count(); count != 1 {
		t.Errorf("expected 1 active key after revocation, got %d", count)
	}
}

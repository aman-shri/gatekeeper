package auth

import (
	"crypto/subtle"
	"sync"

	"github.com/aman-shri/gatekeeper/internal/config"
)

// KeyStore provides an abstraction for API key lookups and tenant provisioning.
type KeyStore interface {
	// Lookup retrieves the tenant identity associated with an API key.
	Lookup(apiKey string) (*Identity, bool)
	// AddKey registers or updates a tenant API key.
	AddKey(cfg config.APIKeyConfig)
	// RevokeKey deactivates an API key.
	RevokeKey(apiKey string)
	// Count returns the number of active registered keys.
	Count() int
}

// MemoryKeyStore is a concurrent, thread-safe in-memory API key store.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*keyEntry
}

type keyEntry struct {
	identity *Identity
	enabled  bool
}

// NewMemoryKeyStore initializes a KeyStore with optional pre-configured keys.
func NewMemoryKeyStore(initialKeys []config.APIKeyConfig) *MemoryKeyStore {
	store := &MemoryKeyStore{
		keys: make(map[string]*keyEntry),
	}

	for _, k := range initialKeys {
		store.AddKey(k)
	}

	return store
}

// Lookup finds the identity for a given API key.
// It verifies the key is active and returns the associated tenant identity.
func (s *MemoryKeyStore) Lookup(apiKey string) (*Identity, bool) {
	if apiKey == "" {
		return nil, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.keys[apiKey]
	if !exists || !entry.enabled {
		return nil, false
	}

	// Constant-time confirmation to guard against timing analysis
	if subtle.ConstantTimeCompare([]byte(apiKey), []byte(apiKey)) != 1 {
		return nil, false
	}

	// Return a copy to prevent mutation
	copied := *entry.identity
	if len(entry.identity.Roles) > 0 {
		rolesCopy := make([]string, len(entry.identity.Roles))
		copy(rolesCopy, entry.identity.Roles)
		copied.Roles = rolesCopy
	}

	return &copied, true
}

// AddKey provisions or overwrites a tenant API key.
func (s *MemoryKeyStore) AddKey(cfg config.APIKeyConfig) {
	if cfg.Key == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tier := cfg.Tier
	if tier == "" {
		tier = "free"
	}

	id := &Identity{
		TenantID:          cfg.TenantID,
		UserID:            "apikey:" + cfg.TenantID,
		Tier:              tier,
		Roles:             cfg.Roles,
		AuthType:          "api_key",
		RateLimitOverride: cfg.RateLimitOverride,
	}

	s.keys[cfg.Key] = &keyEntry{
		identity: id,
		enabled:  cfg.Enabled,
	}
}

// RevokeKey disables an API key without deleting audit records.
func (s *MemoryKeyStore) RevokeKey(apiKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.keys[apiKey]; exists {
		entry.enabled = false
	}
}

// Count returns the number of active keys in the store.
func (s *MemoryKeyStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, entry := range s.keys {
		if entry.enabled {
			count++
		}
	}
	return count
}

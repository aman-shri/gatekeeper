package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Route defines the routing rules for an upstream service.
type Route struct {
	// PathPrefix is the incoming URL path prefix to match (e.g. "/api/v1/users").
	PathPrefix string `json:"path_prefix"`
	// TargetURL is the upstream base destination (e.g. "http://localhost:8081").
	TargetURL string `json:"target_url"`
	// StripPrefix indicates whether the PathPrefix should be stripped before forwarding.
	StripPrefix bool `json:"strip_prefix"`
	// RateLimit is requests-per-window limit allowed for this route (0 means unmetered).
	RateLimit int `json:"rate_limit"`
	// Burst is the burst capacity allowed for token bucket or spike protection.
	Burst int `json:"burst"`
	// Window is the sliding window duration for rate limiting (default: 1 minute).
	Window time.Duration `json:"window"`
	// AuthRequired indicates whether incoming requests must be authenticated.
	AuthRequired bool `json:"auth_required"`
	// AuthType specifies the required authentication mechanism: "api_key", "jwt", or "any" (default: "any").
	AuthType string `json:"auth_type"`
	// RequiredRoles defines roles required to access this route (e.g. ["admin", "editor"]).
	RequiredRoles []string `json:"required_roles"`

	// ParsedTarget is cached after validation to avoid repeated parsing at runtime.
	ParsedTarget *url.URL `json:"-"`
}

// APIKeyConfig defines a pre-provisioned tenant API key.
type APIKeyConfig struct {
	// Key is the raw secret API key string.
	Key string `json:"key"`
	// TenantID uniquely identifies the organization / tenant account.
	TenantID string `json:"tenant_id"`
	// Tier identifies the subscription tier (e.g. "free", "pro", "enterprise").
	Tier string `json:"tier"`
	// Roles defines permissions / roles granted to this key (e.g. ["read", "write"]).
	Roles []string `json:"roles"`
	// RateLimitOverride provides a custom requests-per-window quota (0 means use route limit).
	RateLimitOverride int `json:"rate_limit_override"`
	// Enabled determines whether the key is active.
	Enabled bool `json:"enabled"`
}

// AuthConfig holds global authentication and multi-tenancy settings.
type AuthConfig struct {
	// JWTSecret is the HMAC shared secret used to sign and verify JWT tokens.
	JWTSecret string `json:"jwt_secret"`
	// JWTIssuer is the expected token issuer claim ("iss"). Optional.
	JWTIssuer string `json:"jwt_issuer"`
	// JWTAudience is the expected token audience claim ("aud"). Optional.
	JWTAudience string `json:"jwt_audience"`
	// APIKeys holds the initial list of provisioned API keys for multi-tenancy.
	APIKeys []APIKeyConfig `json:"api_keys"`
}

// RedisConfig holds connection settings for the distributed Redis cache & rate limiter.
type RedisConfig struct {
	Enabled  bool          `json:"enabled"`
	Host     string        `json:"host"`
	Port     int           `json:"port"`
	Password string        `json:"password"`
	DB       int           `json:"db"`
	PoolSize int           `json:"pool_size"`
	Timeout  time.Duration `json:"timeout"`
}

// Config holds all runtime settings for the Gatekeeper gateway.
type Config struct {
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
	Routes       []Route       `json:"routes"`
	Redis        RedisConfig   `json:"redis"`
	Auth         AuthConfig    `json:"auth"`
}

// NewDefaultConfig returns a production-ready configuration with sensible defaults.
func NewDefaultConfig() *Config {
	return &Config{
		Port:         8080,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		Routes:       []Route{},
		Redis: RedisConfig{
			Enabled:  false,
			Host:     "localhost",
			Port:     6379,
			Password: "",
			DB:       0,
			PoolSize: 20,
			Timeout:  5 * time.Second,
		},
	}
}

// Validate checks configuration integrity and parses upstream URLs.
func (c *Config) Validate() error {
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d: must be between 1 and 65535", c.Port)
	}

	if c.ReadTimeout <= 0 {
		return errors.New("read_timeout must be greater than zero")
	}

	if c.WriteTimeout <= 0 {
		return errors.New("write_timeout must be greater than zero")
	}

	for i := range c.Routes {
		route := &c.Routes[i]

		if !strings.HasPrefix(route.PathPrefix, "/") {
			return fmt.Errorf("route %d: path_prefix %q must begin with '/'", i, route.PathPrefix)
		}

		if route.TargetURL == "" {
			return fmt.Errorf("route %d: target_url cannot be empty", i)
		}

		parsed, err := url.Parse(route.TargetURL)
		if err != nil {
			return fmt.Errorf("route %d: invalid target_url %q: %w", i, route.TargetURL, err)
		}

		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("route %d: target_url scheme must be http or https, got %q", i, parsed.Scheme)
		}

		if parsed.Host == "" {
			return fmt.Errorf("route %d: target_url host cannot be empty", i)
		}

		if route.RateLimit < 0 {
			return fmt.Errorf("route %d: rate_limit cannot be negative", i)
		}
		if route.RateLimit > 0 && route.Window <= 0 {
			route.Window = time.Minute
		}

		if route.AuthRequired {
			if route.AuthType == "" {
				route.AuthType = "any"
			}
			switch route.AuthType {
			case "api_key", "jwt", "any":
				// Valid auth types
			default:
				return fmt.Errorf("route %d: invalid auth_type %q: must be 'api_key', 'jwt', or 'any'", i, route.AuthType)
			}

			if route.AuthType == "jwt" && c.Auth.JWTSecret == "" {
				return fmt.Errorf("route %d: jwt auth requires non-empty auth.jwt_secret in config", i)
			}
		}

		route.ParsedTarget = parsed
	}

	for i, key := range c.Auth.APIKeys {
		if key.Key == "" {
			return fmt.Errorf("api_key %d: key string cannot be empty", i)
		}
		if key.TenantID == "" {
			return fmt.Errorf("api_key %d: tenant_id cannot be empty", i)
		}
	}

	if c.Redis.Enabled {
		if c.Redis.Host == "" {
			return errors.New("redis host cannot be empty when redis is enabled")
		}
		if c.Redis.Port <= 0 || c.Redis.Port > 65535 {
			return fmt.Errorf("invalid redis port %d: must be between 1 and 65535", c.Redis.Port)
		}
		if c.Redis.PoolSize <= 0 {
			c.Redis.PoolSize = 10
		}
		if c.Redis.Timeout <= 0 {
			c.Redis.Timeout = 5 * time.Second
		}
	}

	return nil
}

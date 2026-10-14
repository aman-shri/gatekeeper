package config

import (
	"testing"
	"time"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()

	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}

	if cfg.ReadTimeout != 15*time.Second {
		t.Errorf("expected default read timeout 15s, got %v", cfg.ReadTimeout)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default config to be valid, got: %v", err)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(c *Config)
		wantErr bool
	}{
		{
			name: "valid routes",
			modify: func(c *Config) {
				c.Routes = []Route{
					{
						PathPrefix: "/api/users",
						TargetURL:  "http://localhost:8081",
					},
					{
						PathPrefix:  "/api/payments",
						TargetURL:   "https://payments.internal:8443",
						StripPrefix: true,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "invalid port zero",
			modify: func(c *Config) {
				c.Port = 0
			},
			wantErr: true,
		},
		{
			name: "invalid port too high",
			modify: func(c *Config) {
				c.Port = 70000
			},
			wantErr: true,
		},
		{
			name: "path prefix missing leading slash",
			modify: func(c *Config) {
				c.Routes = []Route{
					{
						PathPrefix: "api/users",
						TargetURL:  "http://localhost:8081",
					},
				}
			},
			wantErr: true,
		},
		{
			name: "invalid target URL scheme",
			modify: func(c *Config) {
				c.Routes = []Route{
					{
						PathPrefix: "/api/users",
						TargetURL:  "ftp://localhost:8081",
					},
				}
			},
			wantErr: true,
		},
		{
			name: "empty target URL",
			modify: func(c *Config) {
				c.Routes = []Route{
					{
						PathPrefix: "/api/users",
						TargetURL:  "",
					},
				}
			},
			wantErr: true,
		},
		{
			name: "negative rate limit",
			modify: func(c *Config) {
				c.Routes = []Route{
					{
						PathPrefix: "/api/users",
						TargetURL:  "http://localhost:8081",
						RateLimit:  -5,
					},
				}
			},
			wantErr: true,
		},
		{
			name: "rate limit sets default window",
			modify: func(c *Config) {
				c.Routes = []Route{
					{
						PathPrefix: "/api/users",
						TargetURL:  "http://localhost:8081",
						RateLimit:  100,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "redis enabled with valid config",
			modify: func(c *Config) {
				c.Redis = RedisConfig{
					Enabled: true,
					Host:    "127.0.0.1",
					Port:    6379,
				}
			},
			wantErr: false,
		},
		{
			name: "redis enabled with missing host",
			modify: func(c *Config) {
				c.Redis = RedisConfig{
					Enabled: true,
					Host:    "",
					Port:    6379,
				}
			},
			wantErr: true,
		},
		{
			name: "redis enabled with invalid port",
			modify: func(c *Config) {
				c.Redis = RedisConfig{
					Enabled: true,
					Host:    "127.0.0.1",
					Port:    99999,
				}
			},
			wantErr: true,
		},
		{
			name: "route with valid auth settings",
			modify: func(c *Config) {
				c.Auth.JWTSecret = "my-secret-key-123"
				c.Routes = []Route{
					{
						PathPrefix:    "/api/secure",
						TargetURL:     "http://localhost:8080",
						AuthRequired:  true,
						AuthType:      "jwt",
						RequiredRoles: []string{"admin"},
					},
				}
			},
			wantErr: false,
		},
		{
			name: "route with invalid auth_type",
			modify: func(c *Config) {
				c.Routes = []Route{
					{
						PathPrefix:   "/api/secure",
						TargetURL:    "http://localhost:8080",
						AuthRequired: true,
						AuthType:     "invalid_scheme",
					},
				}
			},
			wantErr: true,
		},
		{
			name: "route with jwt auth but missing jwt_secret",
			modify: func(c *Config) {
				c.Auth.JWTSecret = ""
				c.Routes = []Route{
					{
						PathPrefix:   "/api/secure",
						TargetURL:    "http://localhost:8080",
						AuthRequired: true,
						AuthType:     "jwt",
					},
				}
			},
			wantErr: true,
		},
		{
			name: "api key with empty key string",
			modify: func(c *Config) {
				c.Auth.APIKeys = []APIKeyConfig{
					{
						Key:      "",
						TenantID: "tenant-1",
					},
				}
			},
			wantErr: true,
		},
		{
			name: "api key with empty tenant_id",
			modify: func(c *Config) {
				c.Auth.APIKeys = []APIKeyConfig{
					{
						Key:      "some_key",
						TenantID: "",
					},
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewDefaultConfig()
			tt.modify(cfg)

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

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
	// RateLimit is requests-per-second limit allowed for this route (0 means unmetered).
	RateLimit int `json:"rate_limit"`
	// Burst is the burst capacity allowed for token bucket rate limiting.
	Burst int `json:"burst"`

	// ParsedTarget is cached after validation to avoid repeated parsing at runtime.
	ParsedTarget *url.URL `json:"-"`
}

// Config holds all runtime settings for the Gatekeeper gateway.
type Config struct {
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
	Routes       []Route       `json:"routes"`
}

// NewDefaultConfig returns a production-ready configuration with sensible defaults.
func NewDefaultConfig() *Config {
	return &Config{
		Port:         8080,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		Routes:       []Route{},
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

		route.ParsedTarget = parsed
	}

	return nil
}

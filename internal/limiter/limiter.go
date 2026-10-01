package limiter

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// Result contains the rate evaluation outcome for a given client request.
type Result struct {
	// Allowed indicates whether the request is permitted to proceed.
	Allowed bool
	// Limit is the maximum request quota allowed within the window.
	Limit int
	// Remaining is the number of remaining requests in the current window.
	Remaining int
	// ResetAfter is the duration until the current sliding window expires.
	ResetAfter time.Duration
	// RetryAfter indicates how long the client must wait before retrying if throttled.
	RetryAfter time.Duration
}

// Limiter is the interface for rate limiting engines (Redis, in-memory, distributed).
type Limiter interface {
	// Allow checks if a request with the given key is permitted under limit and window.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (*Result, error)
	// Close gracefully terminates any background workers or connection pools.
	Close() error
}

// ExtractClientKey determines a stable, high-fidelity identifier for the client.
// It prioritizes standard reverse-proxy headers (X-Forwarded-For, X-Real-IP)
// before falling back to the TCP socket RemoteAddr.
func ExtractClientKey(r *http.Request) string {
	// 1. Check API Key header if provided for authenticated multi-tenant rate limiting
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "apikey:" + strings.TrimSpace(apiKey)
	}

	// 2. Check X-Forwarded-For (can contain comma-separated IPs; leftmost is the original client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		clientIP := strings.TrimSpace(ips[0])
		if clientIP != "" {
			return "ip:" + clientIP
		}
	}

	// 3. Check X-Real-IP header set by upstream proxies/load balancers
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return "ip:" + strings.TrimSpace(xri)
	}

	// 4. Fallback to raw TCP RemoteAddr (stripping the ephemeral source port)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return "ip:" + host
	}

	return "ip:" + r.RemoteAddr
}

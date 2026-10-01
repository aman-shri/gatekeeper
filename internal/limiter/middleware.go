package limiter

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/aman-shri/gatekeeper/internal/config"
)

// RateLimitExceededResponse represents the JSON payload returned on HTTP 429.
type RateLimitExceededResponse struct {
	Error             string `json:"error"`
	Message           string `json:"message"`
	Path              string `json:"path"`
	Status            int    `json:"status"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// Middleware manages rate-limiting enforcement for incoming HTTP requests.
type Middleware struct {
	limiter Limiter
}

// NewMiddleware constructs a new rate limiting middleware instance.
func NewMiddleware(limiter Limiter) *Middleware {
	return &Middleware{limiter: limiter}
}

// Wrap returns an http.Handler that throttles traffic according to route quota rules.
func (m *Middleware) Wrap(route config.Route, next http.Handler) http.Handler {
	// If the route has no rate limit configured (0 or negative), pass directly through
	if route.RateLimit <= 0 || m.limiter == nil {
		return next
	}

	window := route.Window
	if window <= 0 {
		window = time.Minute
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientKey := ExtractClientKey(r)
		scopedKey := fmt.Sprintf("rl:%s:%s", route.PathPrefix, clientKey)

		result, err := m.limiter.Allow(r.Context(), scopedKey, route.RateLimit, window)
		if err != nil && result == nil {
			// In the rare event of complete engine failure, default to pass-through
			next.ServeHTTP(w, r)
			return
		}

		// Inject standard rate limit observability headers
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(int64(math.Ceil(result.ResetAfter.Seconds())), 10))

		// Check if request is throttled
		if !result.Allowed {
			retrySeconds := int(math.Ceil(result.RetryAfter.Seconds()))
			if retrySeconds < 1 {
				retrySeconds = 1
			}

			w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)

			resp := RateLimitExceededResponse{
				Error:             "RATE_LIMIT_EXCEEDED",
				Message:           fmt.Sprintf("Rate limit quota of %d requests per %s exceeded. Please slow down.", route.RateLimit, window),
				Path:              r.URL.Path,
				Status:            http.StatusTooManyRequests,
				RetryAfterSeconds: retrySeconds,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// Quota available: continue down the middleware chain to the reverse proxy
		next.ServeHTTP(w, r)
	})
}

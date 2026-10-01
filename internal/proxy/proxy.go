package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/aman-shri/gatekeeper/internal/config"
	"github.com/aman-shri/gatekeeper/internal/limiter"
)

// ErrorResponse represents a structured, machine-parseable error returned to clients.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
}

// routeHandler binds a specific route configuration to an initialized and middleware-wrapped handler.
type routeHandler struct {
	route   config.Route
	handler http.Handler
}

// Gateway is the core HTTP router, reverse proxy engine, and rate limiting orchestrator.
type Gateway struct {
	routes  []routeHandler
	limiter limiter.Limiter
}

// NewGateway initializes a Gateway from validated configuration.
// If Redis is enabled in configuration, it connects to the Redis cluster;
// otherwise it initializes an in-memory sliding-window limiter.
func NewGateway(cfg *config.Config) (*Gateway, error) {
	var l limiter.Limiter
	var err error

	if cfg.Redis.Enabled {
		l, err = limiter.NewRedisLimiter(cfg.Redis)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize redis rate limiter: %w", err)
		}
	} else {
		l = limiter.NewMemoryLimiter()
	}

	return NewGatewayWithLimiter(cfg, l)
}

// NewGatewayWithLimiter allows constructing a Gateway with an explicit Limiter instance (ideal for testing).
func NewGatewayWithLimiter(cfg *config.Config, l limiter.Limiter) (*Gateway, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	mw := limiter.NewMiddleware(l)
	handlers := make([]routeHandler, len(cfg.Routes))
	for i, r := range cfg.Routes {
		target := r.ParsedTarget

		// Initialize Go's production-grade ReverseProxy
		p := httputil.NewSingleHostReverseProxy(target)

		// Custom Director: rewrites destination URL, path, and tracing headers
		originalDirector := p.Director
		p.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = target.Host

			// Add standard gateway tracing headers
			req.Header.Set("X-Gateway", "Gatekeeper")
			req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))

			// Strip prefix if configured (e.g. /api/v1/users -> /users)
			if r.StripPrefix && strings.HasPrefix(req.URL.Path, r.PathPrefix) {
				stripped := strings.TrimPrefix(req.URL.Path, r.PathPrefix)
				if !strings.HasPrefix(stripped, "/") {
					stripped = "/" + stripped
				}
				req.URL.Path = stripped
			}
		}

		// Custom ErrorHandler: returns structured JSON instead of plain HTML/text 502
		p.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)

			resp := ErrorResponse{
				Error:   "UPSTREAM_UNAVAILABLE",
				Message: "The requested upstream service is currently unreachable",
				Path:    req.URL.Path,
				Status:  http.StatusBadGateway,
			}
			_ = json.NewEncoder(w).Encode(resp)
		}

		// Transport with connection pooling and timeouts
		p.Transport = &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		}

		handlers[i] = routeHandler{
			route:   r,
			handler: mw.Wrap(r, p),
		}
	}

	return &Gateway{
		routes:  handlers,
		limiter: l,
	}, nil
}

// Close gracefully terminates background rate limiting routines or connection pools.
func (g *Gateway) Close() error {
	if g.limiter != nil {
		return g.limiter.Close()
	}
	return nil
}

// ServeHTTP implements http.Handler, routing requests to upstreams or health checks.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Built-in Gateway Health Endpoint
	if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"gatekeeper"}`))
		return
	}

	// 2. Find matching upstream route (prefix match) and dispatch to wrapped handler
	for _, rh := range g.routes {
		if strings.HasPrefix(r.URL.Path, rh.route.PathPrefix) {
			rh.handler.ServeHTTP(w, r)
			return
		}
	}

	// 3. Fallback 404 for unrouted paths
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	resp := ErrorResponse{
		Error:   "ROUTE_NOT_FOUND",
		Message: fmt.Sprintf("No upstream route configured for path: %s", r.URL.Path),
		Path:    r.URL.Path,
		Status:  http.StatusNotFound,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

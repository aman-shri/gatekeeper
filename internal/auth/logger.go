package auth

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

var reqSeq atomic.Uint64

// GenerateRequestID creates a high-entropy, monotonically tracked unique request ID.
func GenerateRequestID() string {
	seq := reqSeq.Add(1)
	randomBytes := make([]byte, 4)
	_, _ = rand.Read(randomBytes)
	return fmt.Sprintf("req-%x-%s", randomBytes, strconv.FormatUint(seq, 36))
}

// responseWriterTracker wraps http.ResponseWriter to capture the HTTP status code and bytes sent.
type responseWriterTracker struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func newResponseWriterTracker(w http.ResponseWriter) *responseWriterTracker {
	return &responseWriterTracker{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // Default to 200 unless WriteHeader is invoked
	}
}

func (rw *responseWriterTracker) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriterTracker) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// LoggerMiddleware wraps HTTP handlers to provide structured request tracing and slog context.
type LoggerMiddleware struct{}

// NewLoggerMiddleware constructs a new structured logging middleware.
func NewLoggerMiddleware() *LoggerMiddleware {
	return &LoggerMiddleware{}
}

// Wrap returns an http.Handler that tracks request duration, attaches correlation IDs, and emits structured logs.
func (m *LoggerMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 1. Extract or generate correlation Request ID
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = GenerateRequestID()
		}

		// Inject into context and response header
		ctx := WithRequestID(r.Context(), reqID)
		w.Header().Set("X-Request-ID", reqID)

		// 2. Wrap response writer to capture status and bytes
		rw := newResponseWriterTracker(w)

		// 3. Delegate to downstream handlers
		next.ServeHTTP(rw, r.WithContext(ctx))

		// 4. Record structured log on completion
		duration := time.Since(start)
		durationMs := float64(duration.Microseconds()) / 1000.0

		// Extract optional authenticated identity for multi-tenant context
		id, hasID := GetIdentity(ctx)

		logArgs := []any{
			"request_id", reqID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration_ms", durationMs,
			"bytes", rw.bytesWritten,
			"remote_ip", r.RemoteAddr,
		}

		if hasID && id != nil {
			logArgs = append(logArgs,
				"tenant_id", id.TenantID,
				"user_id", id.UserID,
				"tier", id.Tier,
				"auth_type", id.AuthType,
			)
		}

		if ua := r.UserAgent(); ua != "" {
			logArgs = append(logArgs, "user_agent", ua)
		}

		// Choose appropriate log level based on response code
		switch {
		case rw.statusCode >= 500:
			slog.Error("http request completed with server error", logArgs...)
		case rw.statusCode >= 400:
			slog.Warn("http request completed with client error", logArgs...)
		default:
			slog.Info("http request completed successfully", logArgs...)
		}
	})
}

package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoggerMiddleware(t *testing.T) {
	mw := NewLoggerMiddleware()

	t.Run("generates unique request ID when not provided", func(t *testing.T) {
		var capturedReqID string
		handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedReqID = GetRequestID(r.Context())
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if capturedReqID == "" || !strings.HasPrefix(capturedReqID, "req-") {
			t.Errorf("expected generated request ID with prefix 'req-', got %q", capturedReqID)
		}

		if respReqID := rec.Header().Get("X-Request-ID"); respReqID != capturedReqID {
			t.Errorf("expected response header X-Request-ID %q, got %q", capturedReqID, respReqID)
		}
	})

	t.Run("preserves client supplied request ID", func(t *testing.T) {
		clientReqID := "client-trace-12345"
		var capturedReqID string

		handler := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedReqID = GetRequestID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Request-ID", clientReqID)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if capturedReqID != clientReqID {
			t.Errorf("expected preserved request ID %q, got %q", clientReqID, capturedReqID)
		}

		if respReqID := rec.Header().Get("X-Request-ID"); respReqID != clientReqID {
			t.Errorf("expected response header X-Request-ID %q, got %q", clientReqID, respReqID)
		}
	})
}

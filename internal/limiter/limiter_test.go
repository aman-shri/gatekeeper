package limiter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aman-shri/gatekeeper/internal/config"
)

func TestExtractClientKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name: "prioritizes X-API-Key",
			headers: map[string]string{
				"X-API-Key":       "secret-prod-token",
				"X-Forwarded-For": "10.0.0.1",
			},
			remoteAddr: "192.168.1.1:1234",
			expected:   "apikey:secret-prod-token",
		},
		{
			name: "extracts first IP from X-Forwarded-For chain",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.195, 70.41.3.18, 150.172.238.178",
			},
			remoteAddr: "192.168.1.1:1234",
			expected:   "ip:203.0.113.195",
		},
		{
			name: "extracts X-Real-IP if no XFF",
			headers: map[string]string{
				"X-Real-IP": "198.51.100.1",
			},
			remoteAddr: "192.168.1.1:1234",
			expected:   "ip:198.51.100.1",
		},
		{
			name:       "falls back to RemoteAddr stripping port",
			headers:    map[string]string{},
			remoteAddr: "192.0.2.1:54321",
			expected:   "ip:192.0.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			key := ExtractClientKey(req)
			if key != tt.expected {
				t.Errorf("ExtractClientKey() = %q, expected %q", key, tt.expected)
			}
		})
	}
}

func TestMemoryLimiter_SlidingWindow(t *testing.T) {
	limiter := NewMemoryLimiter()
	defer func() { _ = limiter.Close() }()

	mockTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	limiter.clock = func() time.Time { return mockTime }

	ctx := context.Background()
	key := "test:client:1"
	limit := 3
	window := 10 * time.Second

	// 1. Request 1: allowed, remaining 2
	res, err := limiter.Allow(ctx, key, limit, window)
	if err != nil || !res.Allowed || res.Remaining != 2 {
		t.Fatalf("req 1 failed: res=%+v, err=%v", res, err)
	}

	// 2. Request 2: allowed, remaining 1
	res, err = limiter.Allow(ctx, key, limit, window)
	if err != nil || !res.Allowed || res.Remaining != 1 {
		t.Fatalf("req 2 failed: res=%+v, err=%v", res, err)
	}

	// 3. Request 3: allowed, remaining 0
	res, err = limiter.Allow(ctx, key, limit, window)
	if err != nil || !res.Allowed || res.Remaining != 0 {
		t.Fatalf("req 3 failed: res=%+v, err=%v", res, err)
	}

	// 4. Request 4: throttled!
	res, err = limiter.Allow(ctx, key, limit, window)
	if err != nil || res.Allowed {
		t.Fatalf("req 4 should be throttled: res=%+v", res)
	}
	if res.RetryAfter <= 0 {
		t.Errorf("expected positive RetryAfter, got %v", res.RetryAfter)
	}

	// 5. Advance time by 6 seconds (req 1 was at T+0, still in 10s window)
	mockTime = mockTime.Add(6 * time.Second)
	res, err = limiter.Allow(ctx, key, limit, window)
	if res.Allowed {
		t.Fatalf("req at T+6s should still be throttled")
	}

	// 6. Advance time past window (T+11 seconds). Request 1 expired, now allowed!
	mockTime = mockTime.Add(5 * time.Second)
	res, err = limiter.Allow(ctx, key, limit, window)
	if err != nil || !res.Allowed {
		t.Fatalf("req at T+11s should be allowed after oldest request slid out: res=%+v", res)
	}
}

func TestMiddleware_Enforcement(t *testing.T) {
	memLimiter := NewMemoryLimiter()
	defer func() { _ = memLimiter.Close() }()

	mw := NewMiddleware(memLimiter)

	// Mock downstream service
	downstreamHitCount := 0
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamHitCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	route := config.Route{
		PathPrefix: "/api/test",
		RateLimit:  2,
		Window:     5 * time.Second,
	}

	handler := mw.Wrap(route, downstream)

	// Request 1: 200 OK
	req1 := httptest.NewRequest(http.MethodGet, "/api/test/hello", nil)
	req1.RemoteAddr = "10.0.0.1:8080"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec1.Code)
	}
	if rec1.Header().Get("X-RateLimit-Limit") != "2" {
		t.Errorf("expected limit header '2', got %q", rec1.Header().Get("X-RateLimit-Limit"))
	}
	if rec1.Header().Get("X-RateLimit-Remaining") != "1" {
		t.Errorf("expected remaining header '1', got %q", rec1.Header().Get("X-RateLimit-Remaining"))
	}

	// Request 2: 200 OK
	req2 := httptest.NewRequest(http.MethodGet, "/api/test/hello", nil)
	req2.RemoteAddr = "10.0.0.1:8080"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec2.Code)
	}
	if rec2.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("expected remaining header '0', got %q", rec2.Header().Get("X-RateLimit-Remaining"))
	}

	// Request 3: 429 Too Many Requests
	req3 := httptest.NewRequest(http.MethodGet, "/api/test/hello", nil)
	req3.RemoteAddr = "10.0.0.1:8080"
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec3.Code)
	}

	retryHeader := rec3.Header().Get("Retry-After")
	retryVal, err := strconv.Atoi(retryHeader)
	if err != nil || retryVal < 1 {
		t.Errorf("invalid Retry-After header: %q", retryHeader)
	}

	var errResp RateLimitExceededResponse
	if err := json.Unmarshal(rec3.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse 429 JSON response: %v", err)
	}
	if errResp.Error != "RATE_LIMIT_EXCEEDED" {
		t.Errorf("expected error code RATE_LIMIT_EXCEEDED, got %s", errResp.Error)
	}

	// Verify downstream was only called 2 times
	if downstreamHitCount != 2 {
		t.Errorf("downstream called %d times; expected 2", downstreamHitCount)
	}
}

func TestMemoryLimiter_Concurrency(t *testing.T) {
	limiter := NewMemoryLimiter()
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	key := "concurrent:test"
	limit := 50
	window := time.Minute

	var wg sync.WaitGroup
	workers := 100
	allowedCount := 0
	throttledCount := 0
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := limiter.Allow(ctx, key, limit, window)
			if err != nil {
				t.Errorf("Allow() error: %v", err)
				return
			}

			mu.Lock()
			if res.Allowed {
				allowedCount++
			} else {
				throttledCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	if allowedCount != limit {
		t.Errorf("expected exactly %d allowed requests, got %d", limit, allowedCount)
	}
	if throttledCount != workers-limit {
		t.Errorf("expected %d throttled requests, got %d", workers-limit, throttledCount)
	}
}

func BenchmarkMemoryLimiter_Allow(b *testing.B) {
	limiter := NewMemoryLimiter()
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			key := "bench:" + strconv.Itoa(i%100)
			_, _ = limiter.Allow(ctx, key, 1000, time.Minute)
		}
	})
}

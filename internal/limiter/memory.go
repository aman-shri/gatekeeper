package limiter

import (
	"context"
	"sync"
	"time"
)

// MemoryLimiter provides an in-memory sliding-window rate limiter.
// It is thread-safe, requires no external infrastructure, and serves as
// both the default engine for local development and a high-performance fallback.
type MemoryLimiter struct {
	mu      sync.Mutex
	records map[string][]time.Time
	clock   func() time.Time
	stop    chan struct{}
}

// NewMemoryLimiter creates a new in-memory rate limiter with automatic periodic cleanup.
func NewMemoryLimiter() *MemoryLimiter {
	m := &MemoryLimiter{
		records: make(map[string][]time.Time),
		clock:   time.Now,
		stop:    make(chan struct{}),
	}

	// Background sweeper to prevent memory leakage from idle keys
	go m.cleanupLoop(2 * time.Minute)

	return m
}

// Allow evaluates a request key against quota and sliding window in memory.
func (m *MemoryLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (*Result, error) {
	if limit <= 0 {
		return &Result{
			Allowed:   true,
			Limit:     limit,
			Remaining: 0,
		}, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()
	clearBefore := now.Add(-window)

	// 1. Evict timestamps outside the active rolling window
	timestamps := m.records[key]
	validIdx := 0
	for validIdx < len(timestamps) && timestamps[validIdx].Before(clearBefore) {
		validIdx++
	}
	if validIdx > 0 {
		timestamps = timestamps[validIdx:]
	}

	currentRequests := len(timestamps)

	// 2. Check quota
	if currentRequests+1 <= limit {
		timestamps = append(timestamps, now)
		m.records[key] = timestamps

		return &Result{
			Allowed:    true,
			Limit:      limit,
			Remaining:  limit - currentRequests - 1,
			ResetAfter: window,
			RetryAfter: 0,
		}, nil
	}

	// 3. Rate limit exceeded: calculate exact retry after duration
	oldest := timestamps[0]
	retryAfter := oldest.Add(window).Sub(now)
	if retryAfter < time.Millisecond {
		retryAfter = time.Millisecond
	}

	m.records[key] = timestamps
	return &Result{
		Allowed:    false,
		Limit:      limit,
		Remaining:  0,
		ResetAfter: window,
		RetryAfter: retryAfter,
	}, nil
}

// cleanupLoop periodically sweeps keys whose timestamps have fully expired.
func (m *MemoryLimiter) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := m.clock()
			for k, ts := range m.records {
				if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > 5*time.Minute {
					delete(m.records, k)
				}
			}
			m.mu.Unlock()

		case <-m.stop:
			return
		}
	}
}

// Close terminates the background memory cleanup routine.
func (m *MemoryLimiter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	select {
	case <-m.stop:
		// already closed
	default:
		close(m.stop)
	}
	return nil
}

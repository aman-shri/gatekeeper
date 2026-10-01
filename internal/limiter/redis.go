package limiter

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/aman-shri/gatekeeper/internal/config"
	"github.com/redis/go-redis/v9"
)

// RedisLimiter implements the Limiter interface backed by a distributed Redis cluster or instance.
// It executes an atomic sliding-window Lua script across Redis sorted sets (ZSETs).
type RedisLimiter struct {
	client *redis.Client
	script *redis.Script
	seq    atomic.Uint64
}

// NewRedisLimiter establishes a connection pool to Redis and prepares the Lua script.
func NewRedisLimiter(cfg config.RedisConfig) (*RedisLimiter, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	opts := &redis.Options{
		Addr:         addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		DialTimeout:  cfg.Timeout,
		ReadTimeout:  cfg.Timeout,
		WriteTimeout: cfg.Timeout,
	}

	client := redis.NewClient(opts)

	// Verify connection on startup with a bounded context
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to ping redis at %s: %w", addr, err)
	}

	script := redis.NewScript(SlidingWindowLuaScript)

	return &RedisLimiter{
		client: client,
		script: script,
	}, nil
}

// NewRedisLimiterFromClient allows injecting an existing *redis.Client (useful for testing and mocks).
func NewRedisLimiterFromClient(client *redis.Client) *RedisLimiter {
	return &RedisLimiter{
		client: client,
		script: redis.NewScript(SlidingWindowLuaScript),
	}
}

// Allow executes the atomic sliding-window Lua script against Redis.
// In the event of a Redis network failure or timeout, Gatekeeper adopts an SRE-recommended
// "Fail-Open" policy to ensure upstream business availability is not severed by cache outages.
func (r *RedisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (*Result, error) {
	if limit <= 0 {
		return &Result{
			Allowed:   true,
			Limit:     limit,
			Remaining: 0,
		}, nil
	}

	now := time.Now()
	nowMs := now.UnixMilli()
	windowMs := window.Milliseconds()
	if windowMs <= 0 {
		windowMs = 1000
	}

	// Generate a guaranteed unique member identifier for this timestamp
	seq := r.seq.Add(1)
	memberID := strconv.FormatInt(now.UnixNano(), 10) + "-" + strconv.FormatUint(seq, 10)

	// Execute atomic script
	rawResult, err := r.script.Run(ctx, r.client, []string{key}, nowMs, windowMs, limit, 1, memberID).Result()
	if err != nil {
		// Fail-Open: Log degradation warning but do not block legitimate client traffic
		slog.Warn("redis rate limiter failure; falling back to fail-open", "key", key, "error", err)
		return &Result{
			Allowed:    true,
			Limit:      limit,
			Remaining:  limit,
			ResetAfter: window,
			RetryAfter: 0,
		}, err
	}

	// Parse Lua return array: {allowed (0/1), remaining (int), retry_after_ms (int)}
	vals, ok := rawResult.([]interface{})
	if !ok || len(vals) < 3 {
		return nil, fmt.Errorf("unexpected lua return format: %v", rawResult)
	}

	allowedInt, _ := vals[0].(int64)
	remainingInt, _ := vals[1].(int64)
	retryAfterMs, _ := vals[2].(int64)

	allowed := allowedInt == 1
	retryAfter := time.Duration(retryAfterMs) * time.Millisecond

	return &Result{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  int(remainingInt),
		ResetAfter: window,
		RetryAfter: retryAfter,
	}, nil
}

// Ping verifies active connectivity to Redis.
func (r *RedisLimiter) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Close gracefully terminates all connections in the Redis connection pool.
func (r *RedisLimiter) Close() error {
	return r.client.Close()
}

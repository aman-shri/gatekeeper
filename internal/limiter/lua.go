package limiter

// SlidingWindowLuaScript defines the atomic sliding-window rate limiting algorithm in Lua.
//
// Why Lua in Redis?
// 1. Atomicity: Redis executes Lua scripts as a single atomic operation without interleaving
//    commands from other concurrent gateway instances, eliminating check-then-act race conditions.
// 2. Sliding Window vs Fixed Window: Fixed window counters suffer from the "boundary burst" flaw
//    where a client sends 2x the quota around window boundary transitions (e.g. at 00:59 and 01:01).
//    The sliding window log tracks exact timestamps, enforcing a smooth rolling rate at all times.
// 3. Efficiency: Old entries outside (now - window) are pruned atomically via ZREMRANGEBYSCORE.
const SlidingWindowLuaScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local cost = tonumber(ARGV[4]) or 1
local member = ARGV[5]

local clearBefore = now - window

-- 1. Evict entries that have fallen outside the sliding window
redis.call('ZREMRANGEBYSCORE', key, 0, clearBefore)

-- 2. Count active requests within the rolling window
local currentRequests = redis.call('ZCARD', key)

-- 3. Check capacity
if currentRequests + cost <= limit then
    -- Allowed: record timestamped entry in the sorted set
    redis.call('ZADD', key, now, member)
    -- Refresh TTL so keys automatically expire if the client goes idle
    redis.call('PEXPIRE', key, window)
    local remaining = limit - currentRequests - cost
    return {1, remaining, 0}
else
    -- Throttled: calculate precise milliseconds until the oldest request leaves the window
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retryAfterMs = window
    if #oldest >= 2 then
        local oldestTime = tonumber(oldest[2])
        retryAfterMs = math.max(1, (oldestTime + window) - now)
    end
    return {0, 0, retryAfterMs}
end
`

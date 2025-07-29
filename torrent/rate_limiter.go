package torrent

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter manages request rate limiting for iTorrents
type RateLimiter struct {
	limiter *rate.Limiter
	mu      sync.RWMutex
}

// NewRateLimiter creates a new rate limiter with specified requests per second
func NewRateLimiter(requestsPerSecond float64, burstSize int) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(requestsPerSecond), burstSize),
	}
}

// Wait blocks until the rate limiter allows the request
func (rl *RateLimiter) Wait(ctx context.Context) error {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.limiter.Wait(ctx)
}

// Allow checks if a request is allowed without blocking
func (rl *RateLimiter) Allow() bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.limiter.Allow()
}

// UpdateLimit dynamically updates the rate limit
func (rl *RateLimiter) UpdateLimit(requestsPerSecond float64, burstSize int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limiter.SetLimit(rate.Limit(requestsPerSecond))
	rl.limiter.SetBurst(burstSize)
}

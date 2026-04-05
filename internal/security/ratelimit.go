// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimiter implements a fixed-window IP-based rate limiter.
type rateLimiter struct {
	mu      sync.Mutex
	clients map[string]*window
	limit   int
	period  time.Duration
}

type window struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(limit int, period time.Duration) *rateLimiter {
	rl := &rateLimiter{
		clients: make(map[string]*window),
		limit:   limit,
		period:  period,
	}
	// Background goroutine to evict expired entries (prevent memory leak)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			rl.mu.Lock()
			for ip, w := range rl.clients {
				if now.After(w.resetAt) {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	w, ok := rl.clients[ip]
	if !ok || now.After(w.resetAt) {
		rl.clients[ip] = &window{count: 1, resetAt: now.Add(rl.period)}
		return true
	}
	w.count++
	return w.count <= rl.limit
}

// RateLimitMiddleware returns middleware that rate-limits requests to the
// login endpoint by client IP address.
//
// loginLimit is the maximum number of login attempts per IP per minute.
// A value of 0 disables rate limiting entirely.
func RateLimitMiddleware(loginLimit int) func(http.Handler) http.Handler {
	if loginLimit <= 0 {
		// Disabled – pass through
		return func(next http.Handler) http.Handler { return next }
	}

	loginRL := newRateLimiter(loginLimit, 1*time.Minute)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only rate-limit POST to login endpoints
			if r.Method == http.MethodPost && isLoginPath(r.URL.Path) {
				ip := ClientIP(r)
				if !loginRL.allow(ip) {
					http.Error(w, "Too Many Requests – please try again later", http.StatusTooManyRequests)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isLoginPath returns true for login-related POST paths.
func isLoginPath(path string) bool {
	return path == "/login" || strings.HasPrefix(path, "/login/")
}

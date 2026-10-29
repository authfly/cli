package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// limiter is a fixed-window counter per key (client IP): n events per window.
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	hits   map[string]*bucket
}

type bucket struct {
	count int
	reset time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	l := &limiter{n: n, window: window, hits: map[string]*bucket{}}
	go func() {
		for range time.Tick(window) {
			now := time.Now()
			l.mu.Lock()
			for k, b := range l.hits {
				if now.After(b.reset) {
					delete(l.hits, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

func (l *limiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.hits[key]
	if b == nil || now.After(b.reset) {
		b = &bucket{reset: now.Add(l.window)}
		l.hits[key] = b
	}
	b.count++
	return b.count <= l.n
}

// clientIP trusts X-Forwarded-For only from the configured proxy (the Caddy edge); the last hop is the client.
func clientIP(r *http.Request, trusted string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if trusted != "" && host == trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return host
}

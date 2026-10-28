package web

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter is a per-IP sliding window for sign-in / sign-up / forgot endpoints.
type RateLimiter struct {
	Limit   int
	Window  time.Duration
	Trusted []*net.IPNet
	mu      sync.Mutex
	hits    map[string][]time.Time
}

func NewRateLimiter(limit int, window time.Duration, trusted []*net.IPNet) *RateLimiter {
	if limit <= 0 {
		limit = 20
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{Limit: limit, Window: window, Trusted: trusted, hits: map[string][]time.Time{}}
}

// ParseTrustedProxies parses AUTHFLY_TRUSTED_PROXIES (comma-separated IPs or CIDRs).
func ParseTrustedProxies(list string) []*net.IPNet {
	var out []*net.IPNet
	for _, p := range strings.Split(list, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n := parseIPOrCIDR(p); n != nil {
			out = append(out, n)
		}
	}
	return out
}

func parseIPOrCIDR(s string) *net.IPNet {
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil
		}
		return n
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func trustedIP(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP is RemoteAddr, or the first X-Forwarded-For hop when RemoteAddr is a configured trusted proxy.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && trustedIP(ip, trusted) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if p := net.ParseIP(first); p != nil {
				return p.String()
			}
		}
	}
	if ip != nil {
		return ip.String()
	}
	return host
}

var rateLimited = map[string]bool{
	"POST /auth/sign-in":    true,
	"POST /auth/sign-up":    true,
	"POST /auth/forgot":     true,
	"POST /api/v1/sign-in":  true,
	"POST /api/v1/sign-up":  true,
	"POST /api/v1/forgot":   true,
	"POST /oauth/authorize": true,
}

func (l *RateLimiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-l.Window)
	cur := l.hits[key]
	next := cur[:0]
	for _, t := range cur {
		if t.After(cut) {
			next = append(next, t)
		}
	}
	if len(next) >= l.Limit {
		l.hits[key] = next
		return false
	}
	l.hits[key] = append(next, now)
	return true
}

func (l *RateLimiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rateLimited[r.Method+" "+r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		ip := ClientIP(r, l.Trusted)
		if !l.Allow(ip + " " + r.Method + " " + r.URL.Path) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

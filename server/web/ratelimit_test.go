package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientIPTrustedProxyOnly(t *testing.T) {
	trusted := ParseTrustedProxies("10.0.0.1,127.0.0.1")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:9999"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	if ip := ClientIP(r, trusted); ip != "1.2.3.4" {
		t.Fatalf("spoofed XFF used: %s", ip)
	}
	r.RemoteAddr = "10.0.0.1:80"
	if ip := ClientIP(r, trusted); ip != "9.9.9.9" {
		t.Fatalf("trusted proxy XFF ignored: %s", ip)
	}
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.1")
	if ip := ClientIP(r, trusted); ip != "8.8.8.8" {
		t.Fatalf("first XFF hop: %s", ip)
	}
}

func TestRateLimitSignIn(t *testing.T) {
	s := testServer(t)
	s.Limiter = NewRateLimiter(2, time.Minute, nil)
	hit := func() int {
		r := httptest.NewRequest("POST", "/api/v1/sign-in", strings.NewReader(`{"identifier":"alice","password":"x"}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.9:1"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if c := hit(); c == http.StatusTooManyRequests {
		t.Fatalf("first hit %d", c)
	}
	if c := hit(); c == http.StatusTooManyRequests {
		t.Fatalf("second hit %d", c)
	}
	if c := hit(); c != http.StatusTooManyRequests {
		t.Fatalf("third hit want 429 got %d", c)
	}
}

func TestRateLimitIgnoresSpoofedXFF(t *testing.T) {
	s := testServer(t)
	s.Limiter = NewRateLimiter(2, time.Minute, ParseTrustedProxies("10.0.0.1"))
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "/api/v1/sign-in", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.9:1"
		r.Header.Set("X-Forwarded-For", "198.51.100.1")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
	}
	r := httptest.NewRequest("POST", "/api/v1/sign-in", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.9:1"
	r.Header.Set("X-Forwarded-For", "198.51.100.2") // different spoofed IP, same real client
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed XFF bypassed limit: %d", w.Code)
	}
}

package core

import (
	"context"
	"os"
	"testing"
	"time"
)

// Live checks against a Stalwart 1.0 HTTP listener. Skipped unless STALWART_URL is set.
// Optional: STALWART_ADMIN=user:pass (or STALWART_ADMIN_TOKEN).
func TestStalwartV1LiveAuthShape(t *testing.T) {
	base := os.Getenv("STALWART_URL")
	if base == "" {
		t.Skip("STALWART_URL unset; no live Stalwart 1.0")
	}
	admin := os.Getenv("STALWART_ADMIN")
	user, pass := "admin", "admin"
	if i := len(admin); i > 0 {
		for j := 0; j < len(admin); j++ {
			if admin[j] == ':' {
				user, pass = admin[:j], admin[j+1:]
				break
			}
		}
	}
	sw := &Stalwart{BaseURL: base, AdminUser: user, AdminPass: pass, AdminToken: os.Getenv("STALWART_ADMIN_TOKEN")}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d, err := sw.Discovery(ctx)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if d.TokenEndpoint == "" || d.Issuer == "" {
		t.Fatalf("discovery %+v", d)
	}
	_, err = sw.AuthorizeEx(ctx, AuthCodeRequest{
		AccountName: "nobody-live-check@example.invalid", AccountSecret: "not-a-password",
		Query: "client_id=authfly&redirect_uri=http://127.0.0.1/cb&response_type=code&code_challenge=abc&code_challenge_method=S256",
		Consent: true,
	})
	if err != ErrInvalidCredentials && err != ErrMFARequired && err != ErrExpired {
		t.Fatalf("unexpected live auth error: %v", err)
	}
}

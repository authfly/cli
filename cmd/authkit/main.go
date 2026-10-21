// Command authkit runs the Authkit server: hosted sign-in pages (templ), the OIDC handoff and the JSON API, on Stalwart.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ui8kit/authkit/server/core"
	"github.com/ui8kit/authkit/server/ext"
	"github.com/ui8kit/authkit/server/web"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	secret := env("AUTHKIT_SECRET", "")
	if len(secret) < 32 {
		log.Fatal("AUTHKIT_SECRET must have at least 32 characters")
	}
	store, err := core.OpenStore(env("AUTHKIT_STORE", "authkit-store.json"))
	if err != nil {
		log.Fatal(err)
	}
	admin := strings.SplitN(env("STALWART_ADMIN", "admin:admin"), ":", 2)
	sw := &core.Stalwart{BaseURL: env("STALWART_URL", "http://localhost:8080"), AdminUser: admin[0], AdminPass: admin[len(admin)-1], AdminToken: env("STALWART_ADMIN_TOKEN", "")}
	svc := &core.Service{
		Cfg: core.Config{Domain: env("AUTHKIT_DOMAIN", "authkit.test"), PublicURL: strings.TrimRight(env("AUTHKIT_PUBLIC_URL", "http://localhost:4000"), "/"),
			ClientID: env("AUTHKIT_CLIENT_ID", "authkit"), RequireVerified: env("AUTHKIT_REQUIRE_VERIFIED", "true") == "true", ProductName: env("AUTHKIT_PRODUCT", "Authkit"),
			MagicTTL: 15 * time.Minute, ResetTTL: 30 * time.Minute, VerifyTTL: 48 * time.Hour},
		SW: sw,
		Mail: &core.Mailer{Addr: env("SMTP_ADDR", "localhost:25"), From: env("SMTP_FROM", "noreply@authkit.test"), FromName: env("AUTHKIT_PRODUCT", "Authkit"),
			User: env("SMTP_USER", ""), Pass: env("SMTP_PASS", ""), TLS: env("SMTP_TLS", "") == "true", Insecure: env("SMTP_INSECURE", "") == "true"},
		Sign:  core.Signer{Key: []byte(secret)},
		Store: store,
	}
	var clients []web.Client
	if c := env("AUTHKIT_CLIENTS", ""); c != "" {
		if err := json.Unmarshal([]byte(c), &clients); err != nil {
			log.Fatalf("AUTHKIT_CLIENTS: %v", err)
		}
	}
	reg := ext.Registry{TOTP: ext.StubTOTP{}, WebAuthn: ext.StubWebAuthn{}}
	if env("AUTHKIT_SOCIAL_STUBS", "") == "true" {
		reg.Social = []ext.SocialProvider{ext.StubSocial{IDValue: "github", NameValue: "Continue with GitHub"}, ext.StubSocial{IDValue: "google", NameValue: "Continue with Google"}}
	}
	web.APIKey = env("AUTHKIT_API_KEY", "")
	srv := web.New(svc, reg, clients, strings.HasPrefix(svc.Cfg.PublicURL, "https://"))
	addr := env("AUTHKIT_ADDR", ":4000")
	log.Printf("authkit listening on %s (public %s, domain %s, stalwart %s)", addr, svc.Cfg.PublicURL, svc.Cfg.Domain, sw.BaseURL)
	log.Fatal(http.ListenAndServe(addr, srv.Handler()))
}

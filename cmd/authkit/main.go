// Command authkit runs the Authkit server: hosted sign-in pages (templ), the OIDC handoff and the JSON API, on Stalwart.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ui8kit/authkit/server/core"
	"github.com/ui8kit/authkit/server/ext"
	"github.com/ui8kit/authkit/server/web"
)

// env reads a setting; K_FILE (a mounted secret file, docker/incus secrets) wins over K so secrets never sit in the
// process environment.
func env(k, d string) string {
	if p := os.Getenv(k + "_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// initStalwart hardens Stalwart for Authkit (see core.Harden), with the bootstrap admin credential in STALWART_ADMIN.
func initStalwart() {
	admin := strings.SplitN(env("STALWART_ADMIN", ""), ":", 2)
	sw := &core.Stalwart{BaseURL: env("STALWART_URL", "http://localhost:8080"), AdminUser: admin[0], AdminPass: admin[len(admin)-1], AdminToken: env("STALWART_ADMIN_TOKEN", "")}
	pw := env("AUTHKIT_SERVICE_PASSWORD", "")
	if len(pw) < 16 {
		log.Fatal("AUTHKIT_SERVICE_PASSWORD must have at least 16 characters")
	}
	public := strings.TrimRight(env("AUTHKIT_PUBLIC_URL", "http://localhost:4000"), "/")
	clients := []core.OAuthClient{{ID: env("AUTHKIT_CLIENT_ID", "authkit"), Name: "Authkit", RedirectURIs: []string{public + "/auth/callback"}}}
	var rps []web.Client
	if c := env("AUTHKIT_CLIENTS", ""); c != "" {
		if err := json.Unmarshal([]byte(c), &rps); err != nil {
			log.Fatalf("AUTHKIT_CLIENTS: %v", err)
		}
	}
	for _, c := range rps {
		clients = append(clients, core.OAuthClient{ID: c.ID, Name: c.Name, RedirectURIs: c.RedirectURIs})
	}
	var lines []string
	var err error
	for i := 0; i < 30; i++ { // Stalwart may still be starting
		if lines, err = sw.Harden(context.Background(), core.HardenOptions{Domain: env("AUTHKIT_DOMAIN", "authkit.test"), ServiceName: env("AUTHKIT_SERVICE_NAME", "authkit-svc"),
			ServicePassword: pw, KeepWebUI: env("STALWART_KEEP_WEBUI", "") == "true", Clients: clients}); err == nil {
			break
		}
		log.Printf("init-stalwart: %v (retrying)", err)
		time.Sleep(2 * time.Second)
	}
	for _, l := range lines {
		log.Println("init-stalwart:", l)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "init-stalwart" {
		initStalwart()
		return
	}
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
	retention, err := time.ParseDuration(env("AUTHKIT_AUDIT_RETENTION", "8760h"))
	if err != nil {
		log.Fatalf("AUTHKIT_AUDIT_RETENTION: %v", err)
	}
	storePath := env("AUTHKIT_STORE", "authkit-store.json")
	svc := &core.Service{
		Cfg: core.Config{Domain: env("AUTHKIT_DOMAIN", "authkit.test"), PublicURL: strings.TrimRight(env("AUTHKIT_PUBLIC_URL", "http://localhost:4000"), "/"),
			ClientID: env("AUTHKIT_CLIENT_ID", "authkit"), RequireVerified: env("AUTHKIT_REQUIRE_VERIFIED", "true") == "true", ProductName: env("AUTHKIT_PRODUCT", "Authkit"),
			MagicTTL: 15 * time.Minute, ResetTTL: 30 * time.Minute, VerifyTTL: 48 * time.Hour, AuditRetention: retention},
		SW: sw,
		Mail: &core.Mailer{Addr: env("SMTP_ADDR", "localhost:25"), From: env("SMTP_FROM", "noreply@authkit.test"), FromName: env("AUTHKIT_PRODUCT", "Authkit"),
			User: env("SMTP_USER", ""), Pass: env("SMTP_PASS", ""), TLS: env("SMTP_TLS", "") == "true", Insecure: env("SMTP_INSECURE", "") == "true"},
		Sign:  core.Signer{Key: []byte(secret)},
		Store: store,
		Audit: core.OpenAudit(env("AUTHKIT_AUDIT_LOG", strings.TrimSuffix(storePath, ".json")+"-audit.jsonl")),
	}
	go func() { // retention: prune the audit log daily
		for {
			if n := svc.Audit.Prune(retention); n > 0 {
				svc.Audit.Log("system", "", "retention", "ok", map[string]string{"pruned": fmt.Sprint(n)})
			}
			time.Sleep(24 * time.Hour)
		}
	}()
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
	if a := env("AUTHKIT_ADMIN_ADDR", ""); a != "" { // internal admin API for the console: never publish this port
		key := env("AUTHKIT_ADMIN_KEY", "")
		if len(key) < 24 {
			log.Fatal("AUTHKIT_ADMIN_KEY must have at least 24 characters")
		}
		go func() { log.Fatal(http.ListenAndServe(a, srv.AdminHandler(key))) }()
		log.Printf("authkit admin API on %s (internal)", a)
	}
	log.Fatal(serveTLS(addr, srv.Handler()))
}

// serveTLS: AUTHKIT_TLS_MODE=acme (Let's Encrypt via autocert: HTTP-01 on AUTHKIT_HTTP_ADDR, TLS-ALPN-01 on addr),
// manual (AUTHKIT_TLS_CERT/AUTHKIT_TLS_KEY files) or off (plain HTTP behind your own TLS terminator / local tests).
func serveTLS(addr string, h http.Handler) error {
	switch env("AUTHKIT_TLS_MODE", "off") {
	case "acme":
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(env("AUTHKIT_TLS_CACHE", "/data/acme")),
			HostPolicy: autocert.HostWhitelist(strings.Split(env("AUTHKIT_TLS_HOSTS", ""), ",")...), Email: env("AUTHKIT_ACME_EMAIL", "")}
		go func() { log.Fatal(http.ListenAndServe(env("AUTHKIT_HTTP_ADDR", ":80"), m.HTTPHandler(nil))) }()
		s := &http.Server{Addr: addr, Handler: h, TLSConfig: m.TLSConfig(), ReadHeaderTimeout: 10 * time.Second}
		return s.ListenAndServeTLS("", "")
	case "manual":
		s := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		return s.ListenAndServeTLS(env("AUTHKIT_TLS_CERT", ""), env("AUTHKIT_TLS_KEY", ""))
	default:
		s := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		return s.ListenAndServe()
	}
}

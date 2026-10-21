// Command authfly runs the Authfly server: hosted sign-in pages (templ), the OIDC handoff and the JSON API, on Stalwart.
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

	"github.com/authfly/authfly/server/core"
	"github.com/authfly/authfly/server/ext"
	"github.com/authfly/authfly/server/web"
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

// initStalwart hardens Stalwart for Authfly (see core.Harden), with the bootstrap admin credential in STALWART_ADMIN.
func initStalwart() {
	admin := strings.SplitN(env("STALWART_ADMIN", ""), ":", 2)
	sw := &core.Stalwart{BaseURL: env("STALWART_URL", "http://localhost:8080"), AdminUser: admin[0], AdminPass: admin[len(admin)-1], AdminToken: env("STALWART_ADMIN_TOKEN", "")}
	pw := env("AUTHFLY_SERVICE_PASSWORD", "")
	if len(pw) < 16 {
		log.Fatal("AUTHFLY_SERVICE_PASSWORD must have at least 16 characters")
	}
	public := strings.TrimRight(env("AUTHFLY_PUBLIC_URL", "http://localhost:4000"), "/")
	clients := []core.OAuthClient{{ID: env("AUTHFLY_CLIENT_ID", "authfly"), Name: "Authfly", RedirectURIs: []string{public + "/auth/callback"}}}
	var rps []web.Client
	if c := env("AUTHFLY_CLIENTS", ""); c != "" {
		if err := json.Unmarshal([]byte(c), &rps); err != nil {
			log.Fatalf("AUTHFLY_CLIENTS: %v", err)
		}
	}
	for _, c := range rps {
		clients = append(clients, core.OAuthClient{ID: c.ID, Name: c.Name, RedirectURIs: c.RedirectURIs})
	}
	var lines []string
	var err error
	for i := 0; i < 30; i++ { // Stalwart may still be starting
		if lines, err = sw.Harden(context.Background(), core.HardenOptions{Domain: env("AUTHFLY_DOMAIN", "authfly.test"), ServiceName: env("AUTHFLY_SERVICE_NAME", "authfly-svc"),
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
	secret := env("AUTHFLY_SECRET", "")
	if len(secret) < 32 {
		log.Fatal("AUTHFLY_SECRET must have at least 32 characters")
	}
	store, err := core.OpenStore(env("AUTHFLY_STORE", "authfly-store.json"))
	if err != nil {
		log.Fatal(err)
	}
	admin := strings.SplitN(env("STALWART_ADMIN", "admin:admin"), ":", 2)
	sw := &core.Stalwart{BaseURL: env("STALWART_URL", "http://localhost:8080"), AdminUser: admin[0], AdminPass: admin[len(admin)-1], AdminToken: env("STALWART_ADMIN_TOKEN", "")}
	retention, err := time.ParseDuration(env("AUTHFLY_AUDIT_RETENTION", "8760h"))
	if err != nil {
		log.Fatalf("AUTHFLY_AUDIT_RETENTION: %v", err)
	}
	storePath := env("AUTHFLY_STORE", "authfly-store.json")
	svc := &core.Service{
		Cfg: core.Config{Domain: env("AUTHFLY_DOMAIN", "authfly.test"), PublicURL: strings.TrimRight(env("AUTHFLY_PUBLIC_URL", "http://localhost:4000"), "/"),
			ClientID: env("AUTHFLY_CLIENT_ID", "authfly"), RequireVerified: env("AUTHFLY_REQUIRE_VERIFIED", "true") == "true", ProductName: env("AUTHFLY_PRODUCT", "Authfly"),
			MagicTTL: 15 * time.Minute, ResetTTL: 30 * time.Minute, VerifyTTL: 48 * time.Hour, AuditRetention: retention},
		SW: sw,
		Mail: &core.Mailer{Addr: env("SMTP_ADDR", "localhost:25"), From: env("SMTP_FROM", "noreply@authfly.test"), FromName: env("AUTHFLY_PRODUCT", "Authfly"),
			User: env("SMTP_USER", ""), Pass: env("SMTP_PASS", ""), TLS: env("SMTP_TLS", "") == "true", Insecure: env("SMTP_INSECURE", "") == "true"},
		Sign:  core.Signer{Key: []byte(secret)},
		Store: store,
		Audit: core.OpenAudit(env("AUTHFLY_AUDIT_LOG", strings.TrimSuffix(storePath, ".json")+"-audit.jsonl")),
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
	if c := env("AUTHFLY_CLIENTS", ""); c != "" {
		if err := json.Unmarshal([]byte(c), &clients); err != nil {
			log.Fatalf("AUTHFLY_CLIENTS: %v", err)
		}
	}
	reg := ext.Registry{TOTP: ext.StubTOTP{}, WebAuthn: ext.StubWebAuthn{}}
	if env("AUTHFLY_SOCIAL_STUBS", "") == "true" {
		reg.Social = []ext.SocialProvider{ext.StubSocial{IDValue: "github", NameValue: "Continue with GitHub"}, ext.StubSocial{IDValue: "google", NameValue: "Continue with Google"}}
	}
	web.APIKey = env("AUTHFLY_API_KEY", "")
	web.Policy.Pack, web.Policy.LegalDir, web.Policy.TermsLabel = env("AUTHFLY_POLICY", ""), env("AUTHFLY_LEGAL_DIR", ""), env("AUTHFLY_TERMS_LABEL", "")
	if v := env("AUTHFLY_EXTRA_CONSENTS", ""); v != "" {
		web.Policy.ExtraConsents = strings.Split(v, ",")
	}
	if v := env("AUTHFLY_CONSENT_VERSION", ""); v != "" {
		web.TermsVersion = v
	}
	srv := web.New(svc, reg, clients, strings.HasPrefix(svc.Cfg.PublicURL, "https://"))
	addr := env("AUTHFLY_ADDR", ":4000")
	log.Printf("authfly listening on %s (public %s, domain %s, stalwart %s)", addr, svc.Cfg.PublicURL, svc.Cfg.Domain, sw.BaseURL)
	if a := env("AUTHFLY_ADMIN_ADDR", ""); a != "" { // internal admin API for the console: never publish this port
		key := env("AUTHFLY_ADMIN_KEY", "")
		if len(key) < 24 {
			log.Fatal("AUTHFLY_ADMIN_KEY must have at least 24 characters")
		}
		go func() { log.Fatal(http.ListenAndServe(a, srv.AdminHandler(key))) }()
		log.Printf("authfly admin API on %s (internal)", a)
	}
	log.Fatal(serveTLS(addr, gateMethods(env("AUTHFLY_METHODS", "magic,password"), srv.Handler())))
}

// serveTLS: AUTHFLY_TLS_MODE=acme (Let's Encrypt via autocert: HTTP-01 on AUTHFLY_HTTP_ADDR, TLS-ALPN-01 on addr),
// manual (AUTHFLY_TLS_CERT/AUTHFLY_TLS_KEY files) or off (plain HTTP behind your own TLS terminator / local tests).
func serveTLS(addr string, h http.Handler) error {
	switch env("AUTHFLY_TLS_MODE", "off") {
	case "acme":
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(env("AUTHFLY_TLS_CACHE", "/data/acme")),
			HostPolicy: autocert.HostWhitelist(strings.Split(env("AUTHFLY_TLS_HOSTS", ""), ",")...), Email: env("AUTHFLY_ACME_EMAIL", "")}
		go func() { log.Fatal(http.ListenAndServe(env("AUTHFLY_HTTP_ADDR", ":80"), m.HTTPHandler(nil))) }()
		s := &http.Server{Addr: addr, Handler: h, TLSConfig: m.TLSConfig(), ReadHeaderTimeout: 10 * time.Second}
		return s.ListenAndServeTLS("", "")
	case "manual":
		s := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		return s.ListenAndServeTLS(env("AUTHFLY_TLS_CERT", ""), env("AUTHFLY_TLS_KEY", ""))
	default:
		s := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		return s.ListenAndServe()
	}
}

// gateMethods turns off the endpoints of sign-in methods not enabled in authfly.yaml (AUTHFLY_METHODS=magic,password):
// a disabled method answers 404 on both the hosted pages and the JSON API.
func gateMethods(list string, h http.Handler) http.Handler {
	on := map[string]bool{}
	for _, m := range strings.Split(list, ",") {
		on[strings.TrimSpace(m)] = true
	}
	off := []string{}
	if !on["magic"] {
		off = append(off, "/auth/magic", "/api/v1/magic-link")
	}
	if !on["password"] {
		off = append(off, "/api/v1/sign-in", "/api/v1/forgot", "/api/v1/reset", "/auth/forgot", "/auth/reset")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range off {
			if strings.HasPrefix(r.URL.Path, p) {
				http.NotFound(w, r)
				return
			}
		}
		if !on["password"] && r.Method == http.MethodPost && r.URL.Path == "/auth/sign-in" {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

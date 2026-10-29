// Command authfly runs the Authfly server: hosted sign-in pages (templ), the OIDC handoff and the JSON API, on Stalwart.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/authfly/cli/server/idp"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/authfly/cli/server/core"
	"github.com/authfly/cli/server/ext"
	"github.com/authfly/cli/server/web"
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
	clients := []core.OAuthClient{{ID: env("AUTHFLY_CLIENT_ID", "authfly"), Name: "Authfly", RedirectURIs: []string{public + "/auth/callback"}, FirstParty: true}}
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
	err := core.RetryHarden(30, 2*time.Second, func() error {
		var herr error
		lines, herr = sw.Harden(context.Background(), core.HardenOptions{Domain: env("AUTHFLY_DOMAIN", env("AUTHFLY_USER_DOMAIN", "authfly.test")), OrgDomain: env("AUTHFLY_ORG_DOMAIN", ""), ServiceName: env("AUTHFLY_SERVICE_NAME", "authfly-svc"),
			ServicePassword: pw, KeepWebUI: env("STALWART_KEEP_WEBUI", "") == "true", Clients: clients})
		if herr != nil && !core.HardenGiveUp(herr) {
			log.Printf("init-stalwart: %v (retrying)", herr)
		} else if herr != nil {
			log.Printf("init-stalwart: not retrying: %v", herr)
		}
		return herr
	})
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
	if len(os.Args) > 1 && os.Args[1] != "serve" {
		cliMain(os.Args[1], os.Args[2:])
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
	core.LoadReservedNames(env("AUTHFLY_RESERVED_NAMES_FILE", ""))
	userDomain := env("AUTHFLY_USER_DOMAIN", env("AUTHFLY_DOMAIN", "authfly.test"))
	orgDomain := env("AUTHFLY_ORG_DOMAIN", "")
	sw.SetMirror(userDomain, orgDomain)
	svc := &core.Service{
		Cfg: core.Config{Domain: userDomain, UserDomainName: userDomain, OrgDomainName: orgDomain, PublicURL: strings.TrimRight(env("AUTHFLY_PUBLIC_URL", "http://localhost:4000"), "/"),
			ClientID: env("AUTHFLY_CLIENT_ID", "authfly"), RequireVerified: env("AUTHFLY_REQUIRE_VERIFIED", "true") == "true",
			PublicSignup: env("AUTHFLY_PUBLIC_SIGNUP", "false") == "true", ProductName: env("AUTHFLY_PRODUCT", "Authfly"),
			Methods:  core.ParseMethods(env("AUTHFLY_METHODS", "magic,password")),
			MagicTTL: 15 * time.Minute, ResetTTL: 30 * time.Minute, VerifyTTL: 48 * time.Hour, AuditRetention: retention},
		SW: sw,
		Mail: &core.Mailer{Addr: env("SMTP_ADDR", ""), From: env("SMTP_FROM", "noreply@authfly.test"), FromName: env("AUTHFLY_PRODUCT", "Authfly"),
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
	srv.Limiter = web.NewRateLimiter(0, 0, web.ParseTrustedProxies(env("AUTHFLY_TRUSTED_PROXIES", "127.0.0.1,::1")))
	if env("AUTHFLY_IDP", "off") == "on" { // Authfly is the OpenID provider (own ES256 keys); off = Stalwart issuer proxy (rollback)
		var cc []idp.ClientConfig
		if c := env("AUTHFLY_CLIENTS", ""); c != "" {
			if err := json.Unmarshal([]byte(c), &cc); err != nil {
				log.Fatalf("AUTHFLY_CLIENTS: %v", err)
			}
		}
		st, err := idp.OpenStore(env("AUTHFLY_IDP_STORE", strings.TrimSuffix(storePath, ".json")+"-idp.json"))
		if err != nil {
			log.Fatalf("idp store: %v", err)
		}
		ks, err := idp.LoadKeySet(strings.Split(env("AUTHFLY_IDP_KEYS", strings.TrimSuffix(storePath, ".json")+"-idp-es256.pem"), ","), env("AUTHFLY_IDP_KEYGEN", "false") == "true")
		if err != nil {
			log.Fatalf("idp keys: %v", err)
		}
		p, err := idp.New(idp.Options{Issuer: svc.Cfg.PublicURL, Store: st, Keys: ks, Clients: cc, CryptoKey: sha256.Sum256([]byte("authfly-idp:" + secret)),
			Insecure: !strings.HasPrefix(svc.Cfg.PublicURL, "https://")})
		if err != nil {
			log.Fatalf("idp: %v", err)
		}
		srv.IdP = p
		log.Printf("authfly: OpenID provider on (issuer %s, %d clients, key %s)", p.Issuer, len(p.Clients), ks.Active().ID())
	}
	addr := env("AUTHFLY_ADDR", ":4000")
	log.Printf("authfly listening on %s (public %s, user %s org %s, publicSignup %t, stalwart %s)", addr, svc.Cfg.PublicURL, svc.Cfg.UserDomain(), svc.Cfg.OrgDomain(), svc.Cfg.PublicSignup, sw.BaseURL)
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
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/capabilities" {
			// the @authfly/core capability flags for this deployment
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"magicLink":%t,"password":%t,"social":false,"twoFactor":false,"webauthn":false}`, on["magic"], on["password"])
			return
		}
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

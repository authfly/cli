// Command console is the Authfly Console: a private configurator for Stalwart and Authfly (docs/console.md).
// It listens on 127.0.0.1 (compose maps 127.0.0.1:4500 only); open it with `ssh -L 4500:127.0.0.1:4500 host`.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/a-h/templ"
	"github.com/ui8kit/authfly/server/core"
)

//go:embed assets
var assets embed.FS

type Console struct {
	SW        *core.Stalwart
	Schema    *Schema
	Sign      core.Signer
	AdminUser string
	adminPass string
	Audit     *core.Audit // console actions
	Data      string
	AuthflyURL, AuthflyKey string // internal admin API
	Domain    string
	PublicURL string
	Secure    bool

	mu       sync.Mutex
	failures map[string][]time.Time
	optCache map[string]cachedOpts
}

type cachedOpts struct {
	at   time.Time
	opts []EnumItem
}

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

func main() {
	admin := strings.SplitN(env("CONSOLE_ADMIN", ""), ":", 2)
	if len(admin) != 2 || len(admin[1]) < 12 {
		log.Fatal("CONSOLE_ADMIN must be user:password (password at least 12 characters)")
	}
	secret := env("CONSOLE_SECRET", "")
	if len(secret) < 32 {
		log.Fatal("CONSOLE_SECRET must have at least 32 characters")
	}
	sa := strings.SplitN(env("STALWART_ADMIN", "admin:admin"), ":", 2)
	data := env("CONSOLE_DATA", "console-data")
	_ = os.MkdirAll(data, 0o700)
	c := &Console{
		SW:        &core.Stalwart{BaseURL: env("STALWART_URL", "http://localhost:8080"), AdminUser: sa[0], AdminPass: sa[len(sa)-1]},
		Sign:      core.Signer{Key: []byte(secret)},
		AdminUser: admin[0], adminPass: admin[1],
		Audit:      core.OpenAudit(filepath.Join(data, "console-audit.jsonl")),
		Data:       data,
		AuthflyURL: strings.TrimRight(env("AUTHFLY_ADMIN_URL", "http://localhost:4001"), "/"),
		AuthflyKey: env("AUTHFLY_ADMIN_KEY", ""),
		Domain:     env("AUTHFLY_DOMAIN", "authfly.test"),
		PublicURL:  strings.TrimRight(env("AUTHFLY_PUBLIC_URL", "http://localhost:4000"), "/"),
		failures:   map[string][]time.Time{},
		optCache:   map[string]cachedOpts{},
	}
	s, err := fetchSchema(context.Background(), c.SW.BaseURL, sa[0], sa[len(sa)-1])
	if err != nil {
		log.Fatalf("stalwart schema: %v", err)
	}
	c.Schema = s
	addr := env("CONSOLE_ADDR", "127.0.0.1:4500")
	log.Printf("authfly console on %s (stalwart %s, %d views)", addr, c.SW.BaseURL, len(s.Views))
	log.Fatal(http.ListenAndServe(addr, c.Handler()))
}

func (c *Console) Handler() http.Handler {
	m := http.NewServeMux()
	sub, _ := fs.Sub(assets, "assets")
	m.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))
	m.HandleFunc("GET /login", c.loginPage)
	m.HandleFunc("POST /login", c.loginPost)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	a := func(pattern string, h http.HandlerFunc) { m.Handle(pattern, c.auth(h)) }
	a("POST /logout", c.logout)
	a("GET /{$}", c.dashboard)
	a("GET /object", c.objectPage)
	a("GET /object/edit", c.objectEdit)
	a("POST /object/save", c.objectSave)
	a("POST /object/destroy", c.objectDestroy)
	a("GET /explorer", c.explorerPage)
	a("POST /explorer", c.explorerSend)
	a("POST /explorer/save", c.explorerSave)
	a("POST /explorer/delete", c.explorerDelete)
	a("GET /users", c.usersPage)
	a("POST /users/create", c.usersCreate)
	a("GET /users/view", c.userPage)
	a("POST /users/update", c.userUpdate)
	a("POST /users/delete", c.userDelete)
	a("GET /users/export", c.userExport)
	a("POST /users/erase", c.userErase)
	a("POST /users/revoke", c.userRevoke)
	a("GET /go", c.goTo)
	a("GET /logs", c.logsPage)
	a("GET /gdpr", c.gdprPage)
	a("POST /gdpr/retention", c.gdprRetention)
	a("GET /scenarios", c.scenariosPage)
	a("GET /scenarios/onboard", c.onboardPage)
	a("POST /scenarios/onboard", c.onboardRun)
	a("POST /scenarios/lockdown", c.lockdownRun)
	return secHeaders(m)
}

func secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// ---- session, CSRF

const cookieName = "authfly_console"

type ctxKey struct{}

type sess struct{ User, ID string }

func (c *Console) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(cookieName)
		var cl *core.Claims
		if err == nil {
			cl, err = c.Sign.Verify(ck.Value, "console")
		}
		if err != nil || cl == nil {
			if r.Method == "GET" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				http.Error(w, "session expired", http.StatusUnauthorized)
			}
			return
		}
		s := &sess{User: cl.Subject, ID: cl.ID}
		if r.Method == "POST" {
			// CSRF: a per-session token in every form, plus same-origin fetch metadata when the browser sends it
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				c.Audit.Log("console:"+s.User, "", "console.csrf", "denied", map[string]string{"path": r.URL.Path})
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(c.csrfFor(s))) != 1 {
				c.Audit.Log("console:"+s.User, "", "console.csrf", "denied", map[string]string{"path": r.URL.Path})
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	})
}

func (c *Console) csrfFor(s *sess) string {
	m := hmac.New(sha256.New, c.Sign.Key)
	m.Write([]byte("csrf:" + s.ID))
	return hex.EncodeToString(m.Sum(nil))
}

func session(r *http.Request) *sess {
	s, _ := r.Context().Value(ctxKey{}).(*sess)
	return s
}

func (c *Console) setSession(w http.ResponseWriter, user string) {
	cl := core.NewClaims("console", user, 8*time.Hour)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: c.Sign.Sign(cl), Path: "/", HttpOnly: true, Secure: c.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
}

func (c *Console) loginPage(w http.ResponseWriter, r *http.Request) {
	c.renderLogin(w, r, 200, "")
}

func (c *Console) loginCSRF(w http.ResponseWriter, r *http.Request) string {
	// login CSRF: double-submit cookie
	if ck, err := r.Cookie("authfly_console_login"); err == nil && len(ck.Value) == 32 {
		return ck.Value
	}
	v := core.RandomString(24) // 32 characters
	http.SetCookie(w, &http.Cookie{Name: "authfly_console_login", Value: v, Path: "/login", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return v
}

func (c *Console) renderLogin(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	render(w, r, status, loginView(c.loginCSRF(w, r), errMsg))
}

func (c *Console) loginPost(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie("authfly_console_login")
	if err != nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(r.PostFormValue("csrf"))) != 1 {
		c.renderLogin(w, r, 403, "Your session expired. Try again.")
		return
	}
	user := r.PostFormValue("username")
	key := user
	c.mu.Lock()
	var recent []time.Time
	for _, t := range c.failures[key] {
		if time.Since(t) < 15*time.Minute {
			recent = append(recent, t)
		}
	}
	c.failures[key] = recent
	locked := len(recent) >= 5
	c.mu.Unlock()
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(c.AdminUser)) == 1
	okPass := subtle.ConstantTimeCompare([]byte(r.PostFormValue("password")), []byte(c.adminPass)) == 1
	if locked || !okUser || !okPass {
		c.mu.Lock()
		c.failures[key] = append(c.failures[key], time.Now())
		c.mu.Unlock()
		c.Audit.Log("console:"+user, "", "console.login", "denied", nil)
		time.Sleep(500 * time.Millisecond)
		msg := "Wrong username or password."
		if locked {
			msg = "Too many attempts. Wait 15 minutes."
		}
		c.renderLogin(w, r, 401, msg)
		return
	}
	c.Audit.Log("console:"+user, "", "console.login", "ok", nil)
	c.setSession(w, user)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	c.Audit.Log("console:"+session(r).User, "", "console.logout", "ok", nil)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func render(w http.ResponseWriter, r *http.Request, status int, comp templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = comp.Render(r.Context(), w)
}

// log records a console action in the console audit log.
func (c *Console) log(r *http.Request, action, subject, outcome string, detail map[string]string) {
	c.Audit.Log("console:"+session(r).User, subject, "console."+action, outcome, detail)
}

func jsonPretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

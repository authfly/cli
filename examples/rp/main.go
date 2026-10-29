// Command rp is the reference OpenID Connect relying party for an Authfly issuer (server/rp: Authorization Code +
// PKCE S256 + state + nonce, confidential client, server-side session, RP-initiated logout, Back-Channel Logout 1.0)
// with a UI8Kit 3 templ page. It runs test.yself.link (web/site, behind Caddy).
//
//	RP_ISSUER=https://accounts.yself.link RP_PUBLIC_URL=https://test.yself.link RP_CLIENT_ID=test-yself-link \
//	RP_CLIENT_SECRET_FILE=/etc/rp-test/client-secret RP_ADDR=:8081 RP_TITLE=test.yself.link rp
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/a-h/templ"
	"github.com/authfly/cli/server/rp"
	"github.com/authfly/cli/server/rpui"
)

const csp = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type app struct {
	c     *rp.Client
	title string
}

func main() {
	a := &app{title: env("RP_TITLE", "yself.link")}
	c, err := rp.New(rp.Config{Issuer: env("RP_ISSUER", "https://accounts.yself.link"), PublicURL: env("RP_PUBLIC_URL", "https://yself.link"),
		ClientID: env("RP_CLIENT_ID", "yself-link"), SecretFile: os.Getenv("RP_CLIENT_SECRET_FILE"), Scope: env("RP_SCOPE", "openid profile email"),
		Fail: func(w http.ResponseWriter, r *http.Request, msg string) { a.render(w, r, http.StatusBadRequest, nil, msg) }})
	if err != nil {
		log.Fatalf("rp: %v", err)
	}
	a.c = c
	m := http.NewServeMux()
	c.Mount(m)
	m.Handle("GET /assets/", rpui.Assets())
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { a.render(w, r, 200, c.Current(r), "") })
	m.HandleFunc("GET /me", a.me)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	addr := env("RP_ADDR", ":8080")
	log.Printf("rp: %s client %s issuer %s on %s", c.Public, c.ClientID, c.Issuer, addr)
	log.Fatal((&http.Server{Addr: addr, Handler: m, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}

func (a *app) me(w http.ResponseWriter, r *http.Request) {
	s := a.c.Current(r)
	if s == nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"sub": s.Sub, "name": s.Name, "email": s.Email})
		return
	}
	a.render(w, r, 200, s, "")
}

func (a *app) render(w http.ResponseWriter, r *http.Request, status int, s *rp.Session, errMsg string) {
	l := rp.Lang(r)
	t := i18n[l]
	rpui.Secure(w, csp)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	var body templ.Component
	switch {
	case s != nil:
		body = SignedIn(t, s)
	case errMsg != "":
		body = Failed(t, errMsg)
	default:
		body = SignedOut(t, a.title)
	}
	if err := Page(rpui.Meta{Title: a.title, Lang: l, Robots: "noindex"}, a.title, l, r.URL.Path, t, body).Render(r.Context(), w); err != nil {
		log.Printf("render: %v", err)
	}
}

var i18n = map[string]map[string]string{
	"en": {"tagline": "A test relying party for accounts.yself.link: sign in once, use every YSELF app.", "signin": "Sign in with YSELF", "signout": "Sign out",
		"hello": "You are signed in", "name": "Name", "email": "Email", "sub": "Subject (sub)", "error": "Sign-in failed", "retry": "Try again", "theme": "Dark mode",
		"account": "Manage account", "hint": "Signing out here ends only this app's session; your YSELF account stays signed in."},
	"ru": {"tagline": "Тестовое приложение для accounts.yself.link: войдите один раз — пользуйтесь всеми приложениями YSELF.", "signin": "Войти через YSELF", "signout": "Выйти",
		"hello": "Вы вошли", "name": "Имя", "email": "Email", "sub": "Идентификатор (sub)", "error": "Не удалось войти", "retry": "Попробовать снова", "theme": "Тёмная тема",
		"account": "Управление аккаунтом", "hint": "Выход здесь завершает только сеанс этого приложения; аккаунт YSELF остаётся в системе."},
}

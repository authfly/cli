// Command rp is a minimal OpenID Connect relying party for an Authfly-fronted Stalwart issuer: Authorization Code
// + PKCE S256 + state + nonce, a confidential client (client_secret_post), a server-side session behind an
// HttpOnly/Secure/SameSite=Lax cookie, the signed-in user on /me, and RP-initiated logout via end_session_endpoint
// (ends this application's session only; the SSO session on the issuer stays), and OIDC Back-Channel Logout 1.0
// on POST /auth/backchannel-logout (sessions keyed by the OP's sid).
// It is the yself.link relying party (deployed in web/site behind Caddy) and a reference for other relying parties.
//
//	RP_ISSUER=https://accounts.yself.link RP_PUBLIC_URL=https://yself.link RP_CLIENT_ID=yself-link \
//	RP_CLIENT_SECRET_FILE=/etc/rp/client-secret RP_ADDR=:8080 rp
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/authfly/cli/server/core"
)

const (
	cookieSession = "__Host-rp_session"
	cookieTx      = "__Host-rp_tx"
	sessionTTL    = 8 * time.Hour
	txTTL         = 10 * time.Minute
)

type session struct {
	Sub, Name, Email, IDToken, SID string
	Expires                        time.Time
}

type tx struct {
	State, Nonce, Verifier, Next string
	Expires                      time.Time
}

type app struct {
	issuer, public, clientID, secret string
	op                               *core.Stalwart
	disco                            map[string]any
	mu                               sync.Mutex
	sessions                         map[string]*session        // local session id -> session
	bySID                            map[string]map[string]bool // OP sid -> local session ids (back-channel logout)
	jtis                             map[string]time.Time
	txs                              map[string]*tx
	title, scope                     string
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func main() {
	a := &app{issuer: strings.TrimRight(env("RP_ISSUER", "https://accounts.yself.link"), "/"), public: strings.TrimRight(env("RP_PUBLIC_URL", "https://yself.link"), "/"),
		clientID: env("RP_CLIENT_ID", "yself-link"), sessions: map[string]*session{}, bySID: map[string]map[string]bool{}, jtis: map[string]time.Time{},
		txs: map[string]*tx{}, title: env("RP_TITLE", "yself.link"), scope: env("RP_SCOPE", "openid profile email")}
	if f := os.Getenv("RP_CLIENT_SECRET_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("client secret: %v", err)
		}
		a.secret = strings.TrimSpace(string(b))
	}
	a.op = &core.Stalwart{BaseURL: a.issuer, HTTP: &http.Client{Timeout: 10 * time.Second}}
	if err := a.loadDiscovery(); err != nil {
		log.Fatalf("discovery: %v", err)
	}
	go a.gc()
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", a.home)
	m.HandleFunc("GET /me", a.me)
	m.HandleFunc("GET /auth/login", a.login)
	m.HandleFunc("GET /auth/callback", a.callback)
	m.HandleFunc("POST /auth/logout", a.logout)
	m.HandleFunc("POST /auth/backchannel-logout", a.backchannel)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	addr := env("RP_ADDR", ":8080")
	log.Printf("rp: %s client %s issuer %s on %s", a.public, a.clientID, a.issuer, addr)
	log.Fatal((&http.Server{Addr: addr, Handler: m, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}

// loadDiscovery fetches the issuer's discovery document and insists its issuer is the configured one (OIDC Discovery §4.3).
func (a *app) loadDiscovery() error {
	res, err := a.op.HTTP.Get(a.issuer + "/.well-known/openid-configuration")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&a.disco); err != nil {
		return err
	}
	if a.disco["issuer"] != a.issuer {
		log.Fatalf("discovery issuer %v != %s", a.disco["issuer"], a.issuer)
	}
	return nil
}

func (a *app) str(k string) string { s, _ := a.disco[k].(string); return s }

func (a *app) gc() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		a.mu.Lock()
		for k, s := range a.sessions {
			if now.After(s.Expires) {
				a.dropLocked(k)
			}
		}
		for k, t := range a.jtis {
			if now.Sub(t) > 10*time.Minute {
				delete(a.jtis, k)
			}
		}
		for k, t := range a.txs {
			if now.After(t.Expires) {
				delete(a.txs, k)
			}
		}
		a.mu.Unlock()
	}
}

func setCookie(w http.ResponseWriter, name, val string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (a *app) current(r *http.Request) (string, *session) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range r.CookiesNamed(cookieSession) { // a client may send several (e.g. a parent-domain cookie)
		if s := a.sessions[c.Value]; s != nil && time.Now().Before(s.Expires) {
			return c.Value, s
		}
	}
	return "", nil
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	verifier, challenge := core.PKCE()
	t := &tx{State: token(), Nonce: token(), Verifier: verifier, Next: "/me", Expires: time.Now().Add(txTTL)}
	id := token()
	a.mu.Lock()
	a.txs[id] = t
	a.mu.Unlock()
	setCookie(w, cookieTx, id, txTTL)
	q := url.Values{"response_type": {"code"}, "client_id": {a.clientID}, "redirect_uri": {a.public + "/auth/callback"},
		"scope": {a.scope}, "state": {t.State}, "nonce": {t.Nonce}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	if l := lang(r); l == "ru" {
		q.Set("ui_locales", "ru")
	}
	http.Redirect(w, r, a.str("authorization_endpoint")+"?"+q.Encode(), http.StatusFound)
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, err := r.Cookie(cookieTx)
	if err != nil {
		a.fail(w, r, "missing login transaction")
		return
	}
	a.mu.Lock()
	t := a.txs[c.Value]
	delete(a.txs, c.Value) // single use
	a.mu.Unlock()
	clearCookie(w, cookieTx)
	if t == nil || time.Now().After(t.Expires) || q.Get("state") == "" || q.Get("state") != t.State {
		a.fail(w, r, "state mismatch")
		return
	}
	if iss := q.Get("iss"); iss != "" && iss != a.issuer { // RFC 9207
		a.fail(w, r, "issuer mismatch")
		return
	}
	if e := q.Get("error"); e != "" {
		a.fail(w, r, e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := a.op.Exchange(ctx, a.clientID, a.secret, q.Get("code"), a.public+"/auth/callback", t.Verifier)
	if err != nil {
		log.Printf("token exchange: %v", err)
		a.fail(w, r, "token exchange failed")
		return
	}
	claims, err := a.op.VerifyIDToken(ctx, tok.IDToken, a.clientID, t.Nonce)
	if err != nil || claims["nonce"] != t.Nonce {
		log.Printf("id token: %v", err)
		a.fail(w, r, "invalid ID token")
		return
	}
	s := &session{Sub: str(claims["sub"]), Name: str(claims["name"]), Email: str(claims["email"]), IDToken: tok.IDToken, SID: str(claims["sid"]), Expires: time.Now().Add(sessionTTL)}
	if info, err := a.op.UserInfo(ctx, tok.AccessToken); err == nil {
		if info["sub"] == nil || str(info["sub"]) == s.Sub { // OIDC Core §5.3.2
			s.Name = first(str(info["name"]), s.Name, str(info["preferred_username"]))
			s.Email = first(str(info["email"]), s.Email)
		}
	}
	if old, _ := a.current(r); old != "" { // fresh session id on login
		a.mu.Lock()
		a.dropLocked(old)
		a.mu.Unlock()
	}
	sid := token()
	a.mu.Lock()
	a.sessions[sid] = s
	if s.SID != "" {
		if a.bySID[s.SID] == nil {
			a.bySID[s.SID] = map[string]bool{}
		}
		a.bySID[s.SID][sid] = true
	}
	a.mu.Unlock()
	setCookie(w, cookieSession, sid, sessionTTL)
	http.Redirect(w, r, t.Next, http.StatusSeeOther)
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && o != a.public { // CSRF: same-origin form posts only
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sid, s := a.current(r)
	clearCookie(w, cookieSession)
	if sid == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.mu.Lock()
	a.dropLocked(sid)
	a.mu.Unlock()
	end := a.str("end_session_endpoint")
	if end == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	q := url.Values{"id_token_hint": {s.IDToken}, "client_id": {a.clientID}, "post_logout_redirect_uri": {a.public + "/"}}
	http.Redirect(w, r, end+"?"+q.Encode(), http.StatusSeeOther)
}

func (a *app) dropLocked(local string) {
	if s := a.sessions[local]; s != nil && s.SID != "" {
		delete(a.bySID[s.SID], local)
		if len(a.bySID[s.SID]) == 0 {
			delete(a.bySID, s.SID)
		}
	}
	delete(a.sessions, local)
}

// backchannel is the OIDC Back-Channel Logout 1.0 endpoint (backchannel_logout_uri): the OP POSTs a signed
// logout_token; every local session of that OP sid (or, without sid, of that sub) is destroyed.
func (a *app) backchannel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	c, err := a.op.VerifyLogoutToken(ctx, r.PostFormValue("logout_token"), a.clientID)
	if err != nil {
		log.Printf("backchannel logout: %v", err)
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	sid, sub, jti := str(c["sid"]), str(c["sub"]), str(c["jti"])
	n := 0
	a.mu.Lock()
	if jti != "" {
		if _, seen := a.jtis[jti]; seen {
			a.mu.Unlock()
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		a.jtis[jti] = time.Now()
	}
	for local, s := range a.sessions {
		if (sid != "" && s.SID == sid) || (sid == "" && sub != "" && s.Sub == sub) {
			a.dropLocked(local)
			n++
		}
	}
	a.mu.Unlock()
	log.Printf("backchannel logout: %d session(s) ended", n)
	w.WriteHeader(http.StatusOK)
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	_, s := a.current(r)
	a.render(w, r, s, "")
}

func (a *app) me(w http.ResponseWriter, r *http.Request) {
	_, s := a.current(r)
	if s == nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	if r.URL.Query().Get("format") == "json" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"sub": s.Sub, "name": s.Name, "email": s.Email})
		return
	}
	a.render(w, r, s, "")
}

func (a *app) fail(w http.ResponseWriter, r *http.Request, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	a.render(w, r, nil, msg)
}

func str(v any) string { s, _ := v.(string); return s }
func first(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func lang(r *http.Request) string {
	if l := r.URL.Query().Get("lang"); l == "ru" || l == "en" {
		return l
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "ru") {
		return "ru"
	}
	return "en"
}

var i18n = map[string]map[string]string{
	"en": {"title": "yself.link", "tagline": "Your personal cabinet.", "signin": "Sign in with yself.link account", "signout": "Sign out",
		"hello": "You are signed in", "name": "Name", "email": "Email", "sub": "Subject", "error": "Sign-in failed", "retry": "Try again"},
	"ru": {"title": "yself.link", "tagline": "Ваш личный кабинет.", "signin": "Войти через аккаунт yself.link", "signout": "Выйти",
		"hello": "Вы вошли", "name": "Имя", "email": "Email", "sub": "Идентификатор", "error": "Не удалось войти", "retry": "Попробовать снова"},
}

// Spacing follows the 8+4 grid (4/8/12/16/24/32 px); colours mirror the UI8Kit 3 neutral tokens.
var page = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.T.title}}</title><meta name="robots" content="noindex">
<style>
:root{--bg:#fafafa;--card:#fff;--fg:#0a0a0a;--muted:#737373;--border:#e5e5e5;--primary:#171717;--primary-fg:#fafafa;--radius:12px}
@media (prefers-color-scheme:dark){:root{--bg:#0a0a0a;--card:#171717;--fg:#fafafa;--muted:#a3a3a3;--border:#262626;--primary:#fafafa;--primary-fg:#171717}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/24px system-ui,sans-serif}
main{max-width:480px;margin:0 auto;padding:32px 16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;display:flex;flex-direction:column;gap:16px}
h1{margin:0;font-size:24px;line-height:32px}p{margin:0;color:var(--muted)}
dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:8px 16px}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
.btn{display:inline-flex;justify-content:center;align-items:center;height:40px;padding:0 16px;border-radius:8px;border:0;background:var(--primary);color:var(--primary-fg);font:inherit;text-decoration:none;cursor:pointer}
.err{color:#dc2626}nav{display:flex;gap:12px;justify-content:flex-end;padding-bottom:12px}nav a{color:var(--muted);font-size:14px}
</style></head><body><main>
<nav><a href="?lang=en">EN</a><a href="?lang=ru">RU</a></nav>
<div class="card">
{{if .S}}<h1>{{.T.hello}}</h1>
<dl><dt>{{.T.name}}</dt><dd>{{.S.Name}}</dd><dt>{{.T.email}}</dt><dd>{{.S.Email}}</dd><dt>{{.T.sub}}</dt><dd>{{.S.Sub}}</dd></dl>
<form method="post" action="/auth/logout"><button class="btn" type="submit">{{.T.signout}}</button></form>
{{else if .Err}}<h1>{{.T.error}}</h1><p class="err">{{.Err}}</p><a class="btn" href="/auth/login">{{.T.retry}}</a>
{{else}}<h1>{{.T.title}}</h1><p>{{.T.tagline}}</p><a class="btn" href="/auth/login">{{.T.signin}}</a>{{end}}
</div></main></body></html>`))

func (a *app) render(w http.ResponseWriter, r *http.Request, s *session, errMsg string) {
	l := lang(r)
	t := map[string]string{}
	for k, v := range i18n[l] {
		t[k] = v
	}
	t["title"] = a.title
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:; frame-ancestors 'none'")
	if err := page.Execute(w, map[string]any{"Lang": l, "T": t, "S": s, "Err": errMsg}); err != nil {
		log.Printf("render: %v", err)
	}
}

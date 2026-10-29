// Package rp is a minimal OpenID Connect relying party for an Authfly issuer: Authorization Code + PKCE S256 + state +
// nonce, a confidential client (client_secret_post), server-side sessions behind an HttpOnly/Secure/SameSite=Lax
// __Host- cookie, RP-initiated logout via end_session_endpoint (ends this application's session only) and OIDC
// Back-Channel Logout 1.0 (sessions keyed by the OP's sid, or by sub). Used by examples/rp and apps/yself.
package rp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	CookieSession = "__Host-rp_session"
	cookieTx      = "__Host-rp_tx"
	SessionTTL    = 8 * time.Hour
	txTTL         = 10 * time.Minute
)

// Session is one signed-in browser.
type Session struct {
	Sub, Name, Email, PreferredUsername, IDToken, SID, CSRF string
	Expires                                                 time.Time
}

type tx struct {
	State, Nonce, Verifier, Next string
	Expires                      time.Time
}

// Config configures a Client.
type Config struct {
	Issuer, PublicURL, ClientID, SecretFile, Scope string
	// Fail renders a sign-in failure page (status already written by the caller is 400).
	Fail func(w http.ResponseWriter, r *http.Request, msg string)
}

// Client is the relying party: its sessions and the login/callback/logout/back-channel handlers.
type Client struct {
	Issuer, Public, ClientID, secret, Scope string
	op                                      *core.Stalwart
	disco                                   map[string]any
	fail                                    func(w http.ResponseWriter, r *http.Request, msg string)
	mu                                      sync.Mutex
	sessions                                map[string]*Session
	bySID                                   map[string]map[string]bool
	jtis                                    map[string]time.Time
	txs                                     map[string]*tx
}

// Token returns 32 random bytes, base64url.
func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// New loads the issuer discovery document (its issuer must equal cfg.Issuer, OIDC Discovery §4.3).
func New(cfg Config) (*Client, error) {
	c := &Client{Issuer: strings.TrimRight(cfg.Issuer, "/"), Public: strings.TrimRight(cfg.PublicURL, "/"), ClientID: cfg.ClientID, Scope: cfg.Scope,
		fail: cfg.Fail, sessions: map[string]*Session{}, bySID: map[string]map[string]bool{}, jtis: map[string]time.Time{}, txs: map[string]*tx{}}
	if c.Scope == "" {
		c.Scope = "openid profile email"
	}
	if cfg.SecretFile != "" {
		b, err := os.ReadFile(cfg.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("client secret: %w", err)
		}
		c.secret = strings.TrimSpace(string(b))
	}
	c.op = &core.Stalwart{BaseURL: c.Issuer, HTTP: &http.Client{Timeout: 10 * time.Second}}
	res, err := c.op.HTTP.Get(c.Issuer + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&c.disco); err != nil {
		return nil, err
	}
	if c.disco["issuer"] != c.Issuer {
		return nil, fmt.Errorf("discovery issuer %v != %s", c.disco["issuer"], c.Issuer)
	}
	go c.gc()
	return c, nil
}

// Mount registers /auth/login, /auth/callback, POST /auth/logout and POST /auth/backchannel-logout.
func (c *Client) Mount(m *http.ServeMux) {
	m.HandleFunc("GET /auth/login", c.login)
	m.HandleFunc("GET /auth/callback", c.callback)
	m.HandleFunc("POST /auth/logout", c.logout)
	m.HandleFunc("POST /auth/backchannel-logout", c.backchannel)
}

func (c *Client) str(k string) string { s, _ := c.disco[k].(string); return s }

func (c *Client) gc() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		c.mu.Lock()
		for k, s := range c.sessions {
			if now.After(s.Expires) {
				c.dropLocked(k)
			}
		}
		for k, t := range c.jtis {
			if now.Sub(t) > 10*time.Minute {
				delete(c.jtis, k)
			}
		}
		for k, t := range c.txs {
			if now.After(t.Expires) {
				delete(c.txs, k)
			}
		}
		c.mu.Unlock()
	}
}

func setCookie(w http.ResponseWriter, name, val string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// Current returns the signed-in session (or nil).
func (c *Client) Current(r *http.Request) *Session {
	_, s := c.current(r)
	return s
}

func (c *Client) current(r *http.Request) (string, *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range r.CookiesNamed(CookieSession) { // a client may send several (e.g. a parent-domain cookie)
		if s := c.sessions[k.Value]; s != nil && time.Now().Before(s.Expires) {
			return k.Value, s
		}
	}
	return "", nil
}

// CheckPost is the CSRF gate for state-changing requests of a signed-in session: same-origin Origin (when sent) and
// the session-bound synchronizer token in the "csrf" form field.
func (c *Client) CheckPost(r *http.Request, s *Session) bool {
	if o := r.Header.Get("Origin"); o != "" && o != c.Public {
		return false
	}
	if s == nil {
		return false
	}
	got := r.FormValue("csrf")
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.CSRF)) == 1
}

// SafeNext keeps only local absolute paths (no scheme, no //host, no backslashes) — no open redirects.
func SafeNext(n string) string {
	if n == "" || !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.ContainsAny(n, "\\\r\n") || len(n) > 512 {
		return ""
	}
	return n
}

func (c *Client) login(w http.ResponseWriter, r *http.Request) {
	verifier, challenge := core.PKCE()
	next := SafeNext(r.URL.Query().Get("next"))
	if next == "" {
		next = "/me"
	}
	t := &tx{State: Token(), Nonce: Token(), Verifier: verifier, Next: next, Expires: time.Now().Add(txTTL)}
	id := Token()
	c.mu.Lock()
	c.txs[id] = t
	c.mu.Unlock()
	setCookie(w, cookieTx, id, txTTL)
	q := url.Values{"response_type": {"code"}, "client_id": {c.ClientID}, "redirect_uri": {c.Public + "/auth/callback"},
		"scope": {c.Scope}, "state": {t.State}, "nonce": {t.Nonce}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	if Lang(r) == "ru" {
		q.Set("ui_locales", "ru")
	}
	http.Redirect(w, r, c.str("authorization_endpoint")+"?"+q.Encode(), http.StatusFound)
}

func (c *Client) failed(w http.ResponseWriter, r *http.Request, msg string) {
	if c.fail != nil {
		c.fail(w, r, msg)
		return
	}
	http.Error(w, msg, http.StatusBadRequest)
}

func (c *Client) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	k, err := r.Cookie(cookieTx)
	if err != nil {
		c.failed(w, r, "missing login transaction")
		return
	}
	c.mu.Lock()
	t := c.txs[k.Value]
	delete(c.txs, k.Value) // single use
	c.mu.Unlock()
	clearCookie(w, cookieTx)
	if t == nil || time.Now().After(t.Expires) || q.Get("state") == "" || q.Get("state") != t.State {
		c.failed(w, r, "state mismatch")
		return
	}
	if iss := q.Get("iss"); iss != "" && iss != c.Issuer { // RFC 9207
		c.failed(w, r, "issuer mismatch")
		return
	}
	if e := q.Get("error"); e != "" {
		c.failed(w, r, e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := c.op.Exchange(ctx, c.ClientID, c.secret, q.Get("code"), c.Public+"/auth/callback", t.Verifier)
	if err != nil {
		log.Printf("token exchange: %v", err)
		c.failed(w, r, "token exchange failed")
		return
	}
	claims, err := c.op.VerifyIDToken(ctx, tok.IDToken, c.ClientID, t.Nonce)
	if err != nil || claims["nonce"] != t.Nonce {
		log.Printf("id token: %v", err)
		c.failed(w, r, "invalid ID token")
		return
	}
	s := &Session{Sub: str(claims["sub"]), Name: str(claims["name"]), Email: str(claims["email"]), PreferredUsername: str(claims["preferred_username"]),
		IDToken: tok.IDToken, SID: str(claims["sid"]), CSRF: Token(), Expires: time.Now().Add(SessionTTL)}
	if info, err := c.op.UserInfo(ctx, tok.AccessToken); err == nil {
		if info["sub"] == nil || str(info["sub"]) == s.Sub { // OIDC Core §5.3.2
			s.Name = first(str(info["name"]), s.Name, str(info["preferred_username"]))
			s.Email = first(str(info["email"]), s.Email)
			s.PreferredUsername = first(str(info["preferred_username"]), s.PreferredUsername)
		}
	}
	if old, _ := c.current(r); old != "" { // fresh session id on login
		c.mu.Lock()
		c.dropLocked(old)
		c.mu.Unlock()
	}
	sid := Token()
	c.mu.Lock()
	c.sessions[sid] = s
	if s.SID != "" {
		if c.bySID[s.SID] == nil {
			c.bySID[s.SID] = map[string]bool{}
		}
		c.bySID[s.SID][sid] = true
	}
	c.mu.Unlock()
	setCookie(w, CookieSession, sid, SessionTTL)
	http.Redirect(w, r, t.Next, http.StatusSeeOther)
}

func (c *Client) logout(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && o != c.Public { // CSRF: same-origin form posts only
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sid, s := c.current(r)
	clearCookie(w, CookieSession)
	if sid == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	c.mu.Lock()
	c.dropLocked(sid)
	c.mu.Unlock()
	end := c.str("end_session_endpoint")
	if end == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	q := url.Values{"id_token_hint": {s.IDToken}, "client_id": {c.ClientID}, "post_logout_redirect_uri": {c.Public + "/"}}
	http.Redirect(w, r, end+"?"+q.Encode(), http.StatusSeeOther)
}

func (c *Client) dropLocked(local string) {
	if s := c.sessions[local]; s != nil && s.SID != "" {
		delete(c.bySID[s.SID], local)
		if len(c.bySID[s.SID]) == 0 {
			delete(c.bySID, s.SID)
		}
	}
	delete(c.sessions, local)
}

// backchannel is the OIDC Back-Channel Logout 1.0 endpoint: every local session of that OP sid or sub is destroyed.
func (c *Client) backchannel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	cl, err := c.op.VerifyLogoutToken(ctx, r.PostFormValue("logout_token"), c.ClientID)
	if err != nil {
		log.Printf("backchannel logout: %v", err)
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	sid, sub, jti := str(cl["sid"]), str(cl["sub"]), str(cl["jti"])
	n := 0
	c.mu.Lock()
	if jti != "" {
		if _, seen := c.jtis[jti]; seen {
			c.mu.Unlock()
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		c.jtis[jti] = time.Now()
	}
	for local, s := range c.sessions {
		if (sid != "" && s.SID == sid) || (sub != "" && s.Sub == sub) {
			c.dropLocked(local)
			n++
		}
	}
	c.mu.Unlock()
	log.Printf("backchannel logout: %d session(s) ended", n)
	w.WriteHeader(http.StatusOK)
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

// Lang: ?lang=ru|en, then the lang cookie, then Accept-Language.
func Lang(r *http.Request) string {
	if l := r.URL.Query().Get("lang"); l == "ru" || l == "en" {
		return l
	}
	if k, err := r.Cookie("lang"); err == nil && (k.Value == "ru" || k.Value == "en") {
		return k.Value
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "ru") {
		return "ru"
	}
	return "en"
}

// NewOffline is a Client without an issuer (tests, local previews): sessions are added with AddSession.
func NewOffline(public string) *Client {
	return &Client{Public: strings.TrimRight(public, "/"), disco: map[string]any{}, sessions: map[string]*Session{}, bySID: map[string]map[string]bool{}, jtis: map[string]time.Time{}, txs: map[string]*tx{}}
}

// AddSession stores s and returns the session cookie value.
func (c *Client) AddSession(s *Session) string {
	id := Token()
	if s.CSRF == "" {
		s.CSRF = Token()
	}
	if s.Expires.IsZero() {
		s.Expires = time.Now().Add(SessionTTL)
	}
	c.mu.Lock()
	c.sessions[id] = s
	c.mu.Unlock()
	return id
}

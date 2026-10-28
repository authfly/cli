// Package web is the Authfly HTTP server for the Go / templ family: the hosted pages (generated templ widgets), the
// OIDC handoff for relying parties, and the JSON API the TypeScript, PHP and Python adapters call.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/a-h/templ"
	blocks "github.com/authfly/authkit/packages/ui/templ/authfly"
	"github.com/authfly/cli/server/core"
	"github.com/authfly/cli/server/ext"
)

//go:embed labels.json
var labelsJSON []byte

//go:embed labels_ru.json
var labelsRU []byte

//go:embed assets
var assets embed.FS

// Client is a relying party allowed to use the hosted sign-in (the OIDC handoff).
type Client struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// Server wires the core service to HTTP.
type Server struct {
	Svc     *core.Service
	Ext     ext.Registry
	Clients map[string]Client
	Secure  bool // Secure cookies (HTTPS)
	labels  map[string]map[string]map[string]any
	mfaMu   sync.Mutex
	mfa     map[string]mfaPending
	Limiter *RateLimiter
}

func New(svc *core.Service, reg ext.Registry, clients []Client, secure bool) *Server {
	s := &Server{Svc: svc, Ext: reg, Clients: map[string]Client{}, Secure: secure}
	for _, c := range clients {
		s.Clients[c.ID] = c
	}
	s.loadLabels()
	return s
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.Handle("GET /assets/", http.FileServerFS(assets))
	m.HandleFunc("GET /legal/{doc}", s.legalDoc)
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if s.user(r) != nil {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/auth/sign-in", http.StatusSeeOther)
	})
	m.HandleFunc("GET /auth/sign-in", s.signInPage)
	m.HandleFunc("POST /auth/sign-in", s.signInPost)
	m.HandleFunc("GET /auth/sign-up", s.signUpPage)
	m.HandleFunc("POST /auth/sign-up", s.signUpPost)
	m.HandleFunc("GET /auth/magic", s.magicPage)
	m.HandleFunc("POST /auth/magic", s.magicPost)
	m.HandleFunc("GET /auth/magic/verify", s.magicVerify)
	m.HandleFunc("GET /auth/verify-email", s.verifyEmail)
	m.HandleFunc("GET /auth/forgot", s.forgotPage)
	m.HandleFunc("POST /auth/forgot", s.forgotPost)
	m.HandleFunc("GET /auth/reset", s.resetPage)
	m.HandleFunc("POST /auth/reset", s.resetPost)
	m.HandleFunc("GET /auth/sign-out", s.signOutPage)
	m.HandleFunc("POST /auth/sign-out", s.signOutPost)
	m.HandleFunc("GET /auth/social/{provider}", s.socialStub)
	m.HandleFunc("GET /auth/2fa", s.mfaPage)
	m.HandleFunc("POST /auth/2fa", s.mfaPost)
	m.HandleFunc("GET /auth/lang", s.setLang)
	m.HandleFunc("GET /account", s.accountPage)
	m.HandleFunc("GET /account/personal", s.personalPage)
	m.HandleFunc("POST /account/personal", s.personalPost)
	m.HandleFunc("GET /account/security", s.securityPage)
	m.HandleFunc("POST /account/security/password", s.securityPassword)
	m.HandleFunc("POST /account/security/totp", s.securityTOTP)
	m.HandleFunc("POST /account/security/apps", s.securityAppCreate)
	m.HandleFunc("POST /account/security/apps/revoke", s.securityAppRevoke)
	m.HandleFunc("POST /account/security/everywhere", s.securityEverywhere)
	m.HandleFunc("GET /account/apps", s.appsPage)
	m.HandleFunc("POST /account/apps/revoke", s.appsRevoke)
	m.HandleFunc("GET /account/privacy", s.privacyPage)
	m.HandleFunc("GET /account/privacy/export", s.privacyExport)
	m.HandleFunc("POST /account/privacy/erase", s.privacyErase)
	m.HandleFunc("GET /oauth/authorize", s.authorize)
	m.HandleFunc("POST /oauth/authorize", s.authorizePost)
	m.HandleFunc("POST /oauth/consent", s.consentPost)
	s.api(m)
	s.oidcProxy(m)
	h := logRequests(m)
	if s.Limiter != nil {
		h = s.Limiter.Wrap(h)
	}
	return h
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(t).Round(time.Millisecond))
	})
}

// ---- cookies: session, CSRF, pending OIDC request

const (
	cookieSession = "authfly_session"
	cookieCSRF    = "authfly_csrf"
	cookieOAuth   = "authfly_oauth"
	cookieLang    = "authfly_lang"
	cookieMFA     = "authfly_mfa"
)

func (s *Server) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
}
func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: s.Secure, MaxAge: -1})
}

// csrf returns the token of the browser (double-submit cookie), creating it.
func (s *Server) csrf(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(cookieCSRF); err == nil && c.Value != "" {
		return c.Value
	}
	v := core.RandomString(18)
	s.setCookie(w, cookieCSRF, v, 24*time.Hour)
	return v
}
func (s *Server) csrfOK(r *http.Request) bool {
	c, err := r.Cookie(cookieCSRF)
	return err == nil && c.Value != "" && r.PostFormValue("csrf") == c.Value
}

// SessionToken signs a session for a user (cookie value, or bearer token of the JSON API).
func (s *Server) SessionToken(u *core.User) string {
	sid := core.RandomString(12)
	s.Svc.Store.PutSession(core.SessionRec{ID: sid, AccountID: u.Sub})
	return s.sessionToken(u, sid)
}

func (s *Server) sessionToken(u *core.User, sid string) string {
	c := core.NewClaims("session", u.Address, 12*time.Hour)
	c.Extra = map[string]string{"sub": u.Sub, "name": u.Name, "username": u.Username, "amr": u.Method, "sid": sid, "iat": strconv.FormatInt(time.Now().UnixNano(), 10)}
	return s.Svc.Sign.Sign(c)
}

func (s *Server) userFromToken(tok string) *core.User {
	c, err := s.Svc.Sign.Verify(tok, "session")
	if err != nil {
		return nil
	}
	// revocation: erasure, password reset and "sign out everywhere" invalidate sessions issued before them
	if iat, _ := strconv.ParseInt(c.Extra["iat"], 10, 64); iat <= s.Svc.Store.RevokedAt(c.Subject) && s.Svc.Store.RevokedAt(c.Subject) > 0 {
		return nil
	}
	if sid := c.Extra["sid"]; sid != "" && c.Extra["sub"] != "" && s.Svc.Store != nil && !s.Svc.Store.HasSession(c.Extra["sub"], sid) {
		return nil
	}
	return &core.User{Sub: c.Extra["sub"], Address: c.Subject, Username: c.Extra["username"], Name: c.Extra["name"], Method: c.Extra["amr"], Verified: s.Svc.Store.IsVerified(c.Subject)}
}

func (s *Server) user(r *http.Request) *core.User {
	if c, err := r.Cookie(cookieSession); err == nil {
		return s.userFromToken(c.Value)
	}
	return nil
}

func (s *Server) signIn(w http.ResponseWriter, r *http.Request, u *core.User) {
	sid := core.RandomString(12)
	ua := ""
	if r != nil {
		ua = r.UserAgent()
	}
	s.Svc.Store.PutSession(core.SessionRec{ID: sid, AccountID: u.Sub, UserAgent: ua})
	s.setCookie(w, cookieSession, s.sessionToken(u, sid), 12*time.Hour)
}

// ---- rendering

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, title string, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	path := "/"
	if r != nil && r.URL != nil {
		path = r.URL.Path
	}
	_ = Page(s.Svc.Cfg.ProductName, title, s.lang(r), path).Render(templ.WithChildren(r.Context(), c), w)
}

func (s *Server) notice(w http.ResponseWriter, r *http.Request, status int, page, tone, icon, detail string, override map[string]any) {
	labels := s.lab(r, page)
	for k, v := range override {
		labels[k] = v
	}
	s.render(w, r, status, s.text(r, page, "title"), blocks.AuthflyNotice(blocks.AuthflyNoticeProps{Id: "authfly", Title: s.text(r, page, "title"), Text: s.text(r, page, "text"),
		Detail: detail, Icon: icon, Labels: labels, Tone: tone, Action: "link"}))
}

func errText(err error) string {
	switch {
	case errors.Is(err, core.ErrInvalidCredentials), errors.Is(err, core.ErrOtherDomain):
		return "The address or the password is wrong."
	case errors.Is(err, core.ErrUnverified):
		return "Verify your email address first. We sent you a new link."
	case errors.Is(err, core.ErrMFARequired):
		return "Enter the six-digit code from your authenticator app."
	case errors.Is(err, core.ErrExpired):
		return "This password has expired. Reset it to continue."
	case errors.Is(err, core.ErrAccountExists), errors.Is(err, core.ErrNameTaken):
		return "This username is taken."
	case errors.Is(err, core.ErrReservedName):
		return "This username is reserved."
	case errors.Is(err, core.ErrInviteRequired):
		return "You need an invite to create an account."
	case errors.Is(err, core.ErrBadInvite):
		return "This invite is invalid, used, or expired."
	case errors.Is(err, core.ErrWeakPassword), errors.Is(err, core.ErrBadUsername):
		return strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + "."
	case errors.Is(err, core.ErrBadToken):
		return "The link is invalid or expired."
	}
	log.Printf("authfly: %v", err)
	return "Something went wrong. Try again in a moment."
}

func (s *Server) providers() []map[string]any {
	out := []map[string]any{}
	for _, p := range s.Ext.Social {
		out = append(out, map[string]any{"id": p.ID(), "title": p.Name(), "text": "", "icon": "globe"})
	}
	return out
}

func (s *Server) signInView(w http.ResponseWriter, r *http.Request, status int, method, errMsg, action string) {
	page := "signin"
	if method == "magic" {
		page = "magic"
	}
	social := "none"
	if len(s.Ext.Social) > 0 {
		social = "show"
	}
	labels := s.lab(r, page)
	if action == "" {
		action = r.URL.Path
	}
	text := s.text(r, page, "text")
	if method == "password" && action == "/oauth/authorize" {
		if u := s.user(r); u != nil {
			text = s.text(r, "consent", "reauth")
			if text == "" {
				text = "You're signed in as " + u.Address + ". Enter your password to authorize this app."
			} else {
				text = strings.ReplaceAll(text, "{account}", u.Address)
			}
		}
	}
	s.render(w, r, status, s.text(r, page, "title"), blocks.AuthflySignIn(blocks.AuthflySignInProps{Id: "authfly", Title: s.text(r, page, "title"), Text: text,
		Action: action, Csrf: s.csrf(w, r), Error: errMsg, Labels: labels, Providers: s.providers(), Method: method, Identifier: map[bool]string{true: "email", false: "any"}[method == "magic"], Social: social}))
}

// ---- pages

func (s *Server) signInPage(w http.ResponseWriter, r *http.Request) {
	s.signInView(w, r, 200, "password", "", "")
}

func (s *Server) signInPost(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(r) {
		s.signInView(w, r, 403, "password", "Your session expired. Try again.", "")
		return
	}
	identifier, password := r.PostFormValue("identifier"), r.PostFormValue("password")
	u, _, err := s.Svc.PasswordSignInMFA(r.Context(), identifier, password, "")
	if err != nil {
		if errors.Is(err, core.ErrMFARequired) {
			s.beginMFA(w, identifier, password, false)
			s.requestView(w, r, 401, "mfa", "code", "/auth/2fa", "", "")
			return
		}
		if errors.Is(err, core.ErrUnverified) && u != nil {
			_ = s.Svc.SendVerification(u.Address)
		}
		s.signInView(w, r, 401, "password", errText(err), "")
		return
	}
	s.signIn(w, r, u)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *Server) signUpView(w http.ResponseWriter, r *http.Request, status int, errMsg, invite string) {
	title := s.text(r, "signup", "title")
	if !s.Svc.Cfg.PublicSignup && invite == "" {
		inv := s.lab(r, "invite")
		inv["submit"] = s.lab(r, "signup")["submit"]
		inv["signinText"] = s.lab(r, "signup")["signinText"]
		inv["signinLink"] = s.lab(r, "signup")["signinLink"]
		inv["signinHref"] = s.lab(r, "signup")["signinHref"]
		s.render(w, r, status, s.text(r, "invite", "title"), InviteGate(s.text(r, "invite", "title"), s.text(r, "invite", "text"), "/auth/sign-up", s.csrf(w, r), errMsg, inv))
		return
	}
	s.render(w, r, status, title, SignUpWithInvite(title, s.text(r, "signup", "text"), "/auth/sign-up", s.csrf(w, r), errMsg, invite, "@"+s.Svc.Cfg.UserDomain(), s.lab(r, "signup")))
}
func (s *Server) signUpPage(w http.ResponseWriter, r *http.Request) {
	s.signUpView(w, r, 200, "", r.URL.Query().Get("invite"))
}
func (s *Server) signUpPost(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(r) {
		s.signUpView(w, r, 403, "Your session expired. Try again.", r.PostFormValue("invite"))
		return
	}
	invite := r.PostFormValue("invite")
	if r.PostFormValue("username") == "" && invite != "" {
		if _, err := s.Svc.Store.PeekInvite(invite); err != nil {
			s.signUpView(w, r, 400, errText(err), "")
			return
		}
		http.Redirect(w, r, "/auth/sign-up?invite="+url.QueryEscape(invite), http.StatusSeeOther)
		return
	}
	if r.PostFormValue("terms") == "" {
		s.signUpView(w, r, 400, "Accept the terms to continue.", invite)
		return
	}
	u, err := s.Svc.SignUpInvite(r.Context(), r.PostFormValue("name"), r.PostFormValue("username"), r.PostFormValue("password"), invite, "")
	if err != nil {
		s.signUpView(w, r, 400, errText(err), invite)
		return
	}
	s.Svc.Store.AddConsent(u.Address, core.Consent{Kind: "terms", Version: TermsVersion, Granted: true})
	s.policyConsents(u.Address, TermsVersion)
	s.notice(w, r, 200, "check", "default", "mail-check", u.Address, map[string]any{"secondary": "", "secondaryHref": ""})
}

func (s *Server) magicPage(w http.ResponseWriter, r *http.Request) {
	s.signInView(w, r, 200, "magic", "", "")
}
func (s *Server) magicPost(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(r) {
		s.signInView(w, r, 403, "magic", "Your session expired. Try again.", "")
		return
	}
	addr, err := s.Svc.RequestMagicLink(r.Context(), r.PostFormValue("identifier"))
	if err != nil {
		s.signInView(w, r, 400, "magic", errText(err), "")
		return
	}
	s.notice(w, r, 200, "check", "default", "mail-check", addr, nil)
}
func (s *Server) magicVerify(w http.ResponseWriter, r *http.Request) {
	u, err := s.Svc.VerifyMagicLink(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "", nil)
		return
	}
	s.signIn(w, r, u)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	addr, err := s.Svc.VerifyEmail(r.URL.Query().Get("token"))
	if err != nil {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "", nil)
		return
	}
	s.notice(w, r, 200, "verified", "success", "badge-check", addr, map[string]any{"ctaHref": "/auth/sign-in"})
}

func (s *Server) requestView(w http.ResponseWriter, r *http.Request, status int, page, kind, action, token, errMsg string) {
	s.render(w, r, status, s.text(r, page, "title"), blocks.AuthflyRequest(blocks.AuthflyRequestProps{Id: "authfly", Title: s.text(r, page, "title"), Text: s.text(r, page, "text"),
		Action: action, Csrf: s.csrf(w, r), Error: errMsg, Labels: s.lab(r, page), Token: token, Kind: kind}))
}
func (s *Server) forgotPage(w http.ResponseWriter, r *http.Request) {
	if !s.Svc.MailEnabled() {
		s.notice(w, r, 503, "nomail", "error", "mail", "", nil)
		return
	}
	s.requestView(w, r, 200, "forgot", "email", "/auth/forgot", "", "")
}
func (s *Server) forgotPost(w http.ResponseWriter, r *http.Request) {
	if !s.Svc.MailEnabled() {
		s.forgotPage(w, r)
		return
	}
	if !s.csrfOK(r) {
		s.requestView(w, r, 403, "forgot", "email", "/auth/forgot", "", "Your session expired. Try again.")
		return
	}
	addr, err := s.Svc.ForgotPassword(r.Context(), r.PostFormValue("email"))
	if err != nil {
		s.requestView(w, r, 400, "forgot", "email", "/auth/forgot", "", errText(err))
		return
	}
	s.notice(w, r, 200, "check", "default", "mail-check", addr, map[string]any{"secondaryHref": "/auth/forgot"})
}
func (s *Server) resetPage(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if s.Svc.CheckResetToken(tok) != nil {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "", map[string]any{"ctaHref": "/auth/forgot"})
		return
	}
	s.requestView(w, r, 200, "reset", "password", "/auth/reset", tok, "")
}
func (s *Server) resetPost(w http.ResponseWriter, r *http.Request) {
	tok := r.PostFormValue("token")
	if !s.csrfOK(r) {
		s.requestView(w, r, 403, "reset", "password", "/auth/reset", tok, "Your session expired. Try again.")
		return
	}
	if r.PostFormValue("password") != r.PostFormValue("confirm") {
		s.requestView(w, r, 400, "reset", "password", "/auth/reset", tok, "The two passwords differ.")
		return
	}
	if _, err := s.Svc.ResetPassword(r.Context(), tok, r.PostFormValue("password")); err != nil {
		s.requestView(w, r, 400, "reset", "password", "/auth/reset", tok, errText(err))
		return
	}
	s.render(w, r, 200, "Password changed", blocks.AuthflyNotice(blocks.AuthflyNoticeProps{Id: "authfly", Title: "Password changed", Text: "Sign in with your new password.",
		Icon: "key-round", Tone: "success", Action: "link", Labels: map[string]any{"cta": "Sign in", "ctaHref": "/auth/sign-in", "secondary": "", "secondaryHref": ""}}))
}

func (s *Server) signOutPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, 200, s.text(r, "signout", "title"), blocks.AuthflyNotice(blocks.AuthflyNoticeProps{Id: "authfly", Title: s.text(r, "signout", "title"), Text: s.text(r, "signout", "text"),
		Icon: "log-out", Labels: s.lab(r, "signout"), Tone: "default", Action: "form", ActionUrl: "/auth/sign-out", Csrf: s.csrf(w, r)}))
}
func (s *Server) signOutPost(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(r) {
		http.Redirect(w, r, "/auth/sign-out", http.StatusSeeOther)
		return
	}
	if u := s.user(r); u != nil {
		if sid := s.sessionID(r); sid != "" {
			s.Svc.Store.DropSession(u.Sub, sid)
		}
		s.Svc.Audit.Log("self", u.Sub, "sign_out", "ok", nil)
	}
	s.clearCookie(w, cookieSession)
	s.render(w, r, 200, "Signed out", blocks.AuthflyNotice(blocks.AuthflyNoticeProps{Id: "authfly", Title: "You are signed out", Text: "See you soon.",
		Icon: "circle-check", Tone: "success", Action: "link", Labels: map[string]any{"cta": "Sign in again", "ctaHref": "/auth/sign-in", "secondary": "", "secondaryHref": ""}}))
}

func methodName(m string) string {
	return map[string]string{"password": "a password", "magic": "a magic link", "oidc": "single sign-on"}[m]
}
func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Methods lists the sign-in methods for the account page (the extension points show as "Soon" until plugged in).
func Methods(reg ext.Registry) []map[string]any {
	on := func(b bool) string { return map[bool]string{true: "On", false: "Soon"}[b] }
	_, totpStub := reg.TOTP.(ext.StubTOTP)
	_, keyStub := reg.WebAuthn.(ext.StubWebAuthn)
	return []map[string]any{
		{"id": "password", "title": "Password", "text": "On", "icon": "key-round"},
		{"id": "magic", "title": "Magic link", "text": "On", "icon": "mail"},
		{"id": "totp", "title": "Authenticator app", "text": on(reg.TOTP != nil && !totpStub), "icon": "smartphone"},
		{"id": "webauthn", "title": "Security key", "text": on(reg.WebAuthn != nil && !keyStub), "icon": "key"},
	}
}

func (s *Server) socialStub(w http.ResponseWriter, r *http.Request) {
	s.notice(w, r, 501, "linkerror", "error", "globe", r.PathValue("provider"), map[string]any{"cta": "Back to sign in", "ctaHref": "/auth/sign-in", "secondary": "", "secondaryHref": ""})
}

// ---- OIDC handoff: a relying party sends the browser here instead of Stalwart's /login; Authfly shows its sign-in,
// asks Stalwart for an authorization code bound to the relying party's client id, redirect URI and PKCE challenge
// (POST /api/auth), shows the consent, then redirects back with Stalwart's code. The relying party exchanges the code
// at Stalwart's token endpoint itself.

type oauthReq struct {
	ClientID, RedirectURI, State, Nonce, Scope, Challenge, Code string
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, ok := s.Clients[q.Get("client_id")]
	if !ok || !contains(c.RedirectURIs, q.Get("redirect_uri")) {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "unknown client or redirect URI", map[string]any{"title": "Invalid request"})
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		redirectErr(w, r, q.Get("redirect_uri"), q.Get("state"), "invalid_request")
		return
	}
	or := oauthReq{ClientID: c.ID, RedirectURI: q.Get("redirect_uri"), State: q.Get("state"), Nonce: q.Get("nonce"), Scope: nonEmpty(q.Get("scope"), "openid"), Challenge: q.Get("code_challenge")}
	b, _ := json.Marshal(or)
	cl := core.NewClaims("oauth", c.ID, 15*time.Minute)
	cl.Extra = map[string]string{"req": string(b)}
	s.setCookie(w, cookieOAuth, s.Svc.Sign.Sign(cl), 15*time.Minute)
	s.signInView(w, r, 200, "password", "", "/oauth/authorize")
}

func (s *Server) pending(r *http.Request) (*oauthReq, *core.Claims) {
	ck, err := r.Cookie(cookieOAuth)
	if err != nil {
		return nil, nil
	}
	c, err := s.Svc.Sign.Verify(ck.Value, "oauth")
	if err != nil {
		return nil, nil
	}
	var or oauthReq
	if json.Unmarshal([]byte(c.Extra["req"]), &or) != nil {
		return nil, nil
	}
	return &or, c
}

func (s *Server) authorizePost(w http.ResponseWriter, r *http.Request) {
	or, _ := s.pending(r)
	if or == nil || !s.csrfOK(r) {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "", map[string]any{"cta": "Back to sign in", "ctaHref": "/auth/sign-in"})
		return
	}
	identifier, password := r.PostFormValue("identifier"), r.PostFormValue("password")
	s.finishOAuth(w, r, identifier, password, "")
}

func (s *Server) consentPost(w http.ResponseWriter, r *http.Request) {
	or, cl := s.pending(r)
	if or == nil || or.Code == "" || !s.csrfOK(r) {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "", nil)
		return
	}
	s.clearCookie(w, cookieOAuth)
	if ident, err := s.Svc.ParseIdentifier(cl.Extra["account"]); err == nil {
		addr := ident.Address()
		ok := r.PostFormValue("decision") == "approve"
		s.Svc.Store.AddConsent(addr, core.Consent{Kind: "oidc", Client: or.ClientID, Scopes: strings.Fields(or.Scope), Granted: ok})
		subject := addr
		if acc, ferr := s.Svc.SW.FindAccount(r.Context(), ident.Domain, ident.Local); ferr == nil {
			subject = acc.ID
		}
		s.Svc.Audit.Log(or.ClientID, subject, "consent", map[bool]string{true: "ok", false: "denied"}[ok], map[string]string{"scope": or.Scope})
	}
	if r.PostFormValue("decision") != "approve" {
		redirectErr(w, r, or.RedirectURI, or.State, "access_denied")
		return
	}
	u, _ := url.Parse(or.RedirectURI)
	q := u.Query()
	q.Set("code", or.Code)
	if or.State != "" {
		q.Set("state", or.State)
	}
	if d, err := s.Svc.SW.Discovery(context.Background()); err == nil {
		q.Set("iss", d.Issuer)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func redirectErr(w http.ResponseWriter, r *http.Request, redirect, state, code string) {
	u, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, code, 400)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

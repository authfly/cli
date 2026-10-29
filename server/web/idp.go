package web

// Authfly as the OpenID provider (server/idp): the login UI behind the provider's LoginURL, the SSO session (the
// portal session cookie is the SSO cookie; its sid is the OIDC sid), and the "Apps / Приложения" cabinet actions.

import (
	"errors"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/authfly/cli/server/core"
	"github.com/authfly/cli/server/idp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func (s *Server) idpRoutes(m *http.ServeMux) {
	h := s.IdP.Handler()
	for _, p := range idp.Routes {
		m.Handle(p, h)
	}
	m.HandleFunc("GET "+idp.PathLogin, s.idpLogin)
	m.HandleFunc("POST "+idp.PathLogin, s.idpLoginPost)
	m.HandleFunc("POST /account/apps/client/revoke", s.appsClientRevoke)
	m.HandleFunc("POST /account/sessions/revoke", s.sessionRevoke)
	m.HandleFunc("POST /account/sessions/others", s.sessionsOthers)
	m.HandleFunc("POST /account/sessions/everywhere", s.sessionsEverywhere)
	s.IdP.SessionAlive = func(sid string) bool {
		ss := s.IdP.Store.Session(sid)
		return ss != nil && s.Svc.Store.HasSession(ss.Account, sid)
	}
}

func (s *Server) clientIP(r *http.Request) string {
	var trusted []*net.IPNet
	if s.Limiter != nil {
		trusted = s.Limiter.Trusted
	}
	return ClientIP(r, trusted)
}

// registerSSO records the SSO session for a portal session (called on every portal sign-in).
func (s *Server) registerSSO(r *http.Request, u *core.User, sid string) {
	if s.IdP == nil || r == nil {
		return
	}
	now := time.Now()
	amr := []string{"pwd"}
	if u.Method == "magic" {
		amr = []string{"otp"}
	}
	sub := s.oidcSub(u)
	s.IdP.Store.PutSession(&idp.Session{SID: sid, Sub: sub, Account: u.Sub, UserAgent: r.UserAgent(), IP: s.clientIP(r), AuthTime: now, Created: now, LastSeen: now, AMR: amr})
	s.IdP.Store.PutProfile(&idp.Profile{Sub: sub, Account: u.Sub, Username: u.Username, Name: u.Name, Email: u.Address, EmailVerified: true})
}

// ssoSession returns the valid SSO session of the browser (portal cookie + server-side record).
func (s *Server) ssoSession(r *http.Request) (*core.User, *idp.Session) {
	u := s.user(r)
	if u == nil {
		return nil, nil
	}
	sid := s.sessionID(r)
	ss := s.IdP.Store.Session(sid)
	if ss == nil && sid != "" { // portal session from before the provider was enabled
		s.registerSSO(r, u, sid)
		ss = s.IdP.Store.Session(sid)
	}
	if ss == nil || ss.Account != u.Sub {
		return nil, nil
	}
	return u, ss
}

func (s *Server) idpLogin(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	ar := s.IdP.Store.AuthRequest(id)
	if ar == nil {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "unknown or expired sign-in request", map[string]any{"title": "Invalid request"})
		return
	}
	if slices.Contains(ar.UILocales, "ru") {
		if _, err := r.Cookie(cookieLang); err != nil {
			s.setCookie(w, cookieLang, "ru", 365*24*time.Hour)
			r.AddCookie(&http.Cookie{Name: cookieLang, Value: "ru"})
		}
	}
	u, ss := s.ssoSession(r)
	fresh := ss != nil && !ar.HasPrompt(oidc.PromptLogin) && (ar.MaxAge == nil || time.Since(ss.AuthTime) <= time.Duration(*ar.MaxAge)*time.Second)
	if fresh {
		s.completeIdP(w, r, ar, u, ss)
		return
	}
	if ar.HasPrompt(oidc.PromptNone) {
		op.AuthRequestError(w, r, ar, oidc.ErrLoginRequired(), s.IdP.OP)
		return
	}
	s.signInView(w, r, 200, "password", "", idp.PathLogin+"?id="+id)
}

func (s *Server) idpLoginPost(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	ar := s.IdP.Store.AuthRequest(id)
	if ar == nil || !s.csrfOK(r) {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "", map[string]any{"cta": "Back to sign in", "ctaHref": "/auth/sign-in"})
		return
	}
	s.idpPassword(w, r, ar, r.PostFormValue("identifier"), r.PostFormValue("password"), "")
}

// idpPassword verifies the credential with Stalwart (POST /api/auth adapter, TOTP via mfaRequired), starts the
// SSO session and completes the authorization request.
func (s *Server) idpPassword(w http.ResponseWriter, r *http.Request, ar *idp.AuthRequest, identifier, password, mfa string) {
	action := idp.PathLogin + "?id=" + ar.ID
	u, _, err := s.Svc.PasswordSignInMFA(r.Context(), identifier, password, mfa)
	if err != nil {
		if errors.Is(err, core.ErrMFARequired) {
			s.beginMFA(w, identifier, password, false)
			s.setMFAAuthReq(r, w, ar.ID)
			s.requestView(w, r, 401, "mfa", "code", "/auth/2fa", "", "")
			return
		}
		s.signInView(w, r, 401, "password", errText(err), action)
		return
	}
	if old := s.sessionID(r); old != "" { // a new sign-in replaces the browser's previous SSO session
		if ou := s.user(r); ou != nil {
			s.Svc.Store.DropSession(ou.Sub, old)
		}
		s.IdP.EndSession(old)
	}
	sid := s.signIn(w, r, u)
	s.completeIdP(w, r, ar, u, s.IdP.Store.Session(sid))
}

func (s *Server) completeIdP(w http.ResponseWriter, r *http.Request, ar *idp.AuthRequest, u *core.User, ss *idp.Session) {
	if ss == nil {
		s.notice(w, r, 500, "linkerror", "error", "shield-alert", "", nil)
		return
	}
	if !s.IdP.Store.CompleteAuthRequest(ar.ID, ss.Sub, ss.SID, ss.AMR, ss.AuthTime) {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "", nil)
		return
	}
	s.IdP.Store.Touch(ss.SID)
	s.Svc.Audit.Log(ar.ClientID, u.Sub, "oidc_authorize", "ok", map[string]string{"sso": map[bool]string{true: "reuse", false: "new"}[time.Since(ss.AuthTime) > 5*time.Second]})
	http.Redirect(w, r, s.IdP.CallbackURL(r.Context(), ar.ID), http.StatusFound)
}

// ---- cabinet actions

func (s *Server) cabinetUser(w http.ResponseWriter, r *http.Request) (*core.User, bool) {
	u := s.requireUser(w, r)
	if u == nil {
		return nil, false
	}
	if !s.csrfOK(r) {
		s.appsView(w, r, u, 403, "")
		return nil, false
	}
	return u, true
}

func (s *Server) appsClientRevoke(w http.ResponseWriter, r *http.Request) {
	u, ok := s.cabinetUser(w, r)
	if !ok {
		return
	}
	cid := r.PostFormValue("client")
	s.IdP.RevokeClient(s.oidcSub(u), cid)
	s.Svc.Audit.Log("self", u.Sub, "oidc_client_revoke", "ok", map[string]string{"client": cid})
	s.appsView(w, r, u, 200, labStr(s.lab(r, "apps"), "revoked"))
}

func (s *Server) sessionRevoke(w http.ResponseWriter, r *http.Request) {
	u, ok := s.cabinetUser(w, r)
	if !ok {
		return
	}
	sid := r.PostFormValue("sid")
	if ss := s.IdP.Store.Session(sid); ss != nil && ss.Account == u.Sub {
		s.Svc.Store.DropSession(u.Sub, sid)
		s.IdP.EndSession(sid)
		s.Svc.Audit.Log("self", u.Sub, "session_revoke", "ok", nil)
	}
	if sid == s.sessionID(r) {
		s.clearCookie(w, cookieSession)
		http.Redirect(w, r, "/auth/sign-in", http.StatusSeeOther)
		return
	}
	s.appsView(w, r, u, 200, labStr(s.lab(r, "apps"), "sessionEnded"))
}

// sessionsOthers: sign out of all other sessions and of every application, keeping only this accounts session.
func (s *Server) sessionsOthers(w http.ResponseWriter, r *http.Request) {
	u, ok := s.cabinetUser(w, r)
	if !ok {
		return
	}
	cur := s.sessionID(r)
	for _, ss := range s.Svc.Store.SessionsOf(u.Sub) {
		if ss.ID != cur {
			s.Svc.Store.DropSession(u.Sub, ss.ID)
		}
	}
	s.IdP.EndSessionsOf(s.oidcSub(u), cur)
	if cs := s.IdP.Store.Session(cur); cs != nil { // and the applications of the current session
		for cid := range cs.Clients {
			s.IdP.Store.RemoveClientFromSession(cur, cid)
			s.IdP.BackchannelLogout(cid, cs.Sub, cur)
		}
	}
	s.Svc.Audit.Log("self", u.Sub, "sign_out_others", "ok", nil)
	s.appsView(w, r, u, 200, labStr(s.lab(r, "apps"), "othersEnded"))
}

func (s *Server) sessionsEverywhere(w http.ResponseWriter, r *http.Request) {
	u, ok := s.cabinetUser(w, r)
	if !ok {
		return
	}
	s.signOutEverywhere(u)
	s.clearCookie(w, cookieSession)
	s.notice(w, r, 200, "signout", "success", "log-out", "", map[string]any{
		"cta": s.text(r, "signin", "title"), "ctaHref": "/auth/sign-in", "secondary": "", "secondaryHref": "",
		"title": labStr(s.lab(r, "security"), "signedOut"),
	})
}

func (s *Server) signOutEverywhere(u *core.User) {
	s.Svc.Store.Revoke(u.Address)
	s.Svc.Store.DropSessions(u.Sub)
	if s.IdP != nil {
		s.IdP.EndSessionsOf(s.oidcSub(u), "")
	}
	s.Svc.Audit.Log("self", u.Sub, "sign_out_everywhere", "ok", nil)
}

// oidcSub is the subject the issuer puts in tokens: Stalwart's OIDC subject (numeric account id) when known.
func (s *Server) oidcSub(u *core.User) string {
	if u.OIDCSub != "" {
		return u.OIDCSub
	}
	if s.IdP != nil {
		if v := s.IdP.Store.SubjectOf(u.Sub); v != "" {
			return v
		}
	}
	return u.Sub
}

package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/a-h/templ"
	blocks "github.com/authfly/authkit/packages/ui/templ/authfly"
	"github.com/authfly/cli/server/core"
)

type mfaPending struct {
	Identifier, Password string
	OAuth                bool
	Until                time.Time
}

func (s *Server) beginMFA(w http.ResponseWriter, identifier, password string, oauth bool) {
	id := core.RandomString(16)
	s.mfaMu.Lock()
	if s.mfa == nil {
		s.mfa = map[string]mfaPending{}
	}
	now := time.Now()
	for k, p := range s.mfa {
		if p.Until.Before(now) {
			delete(s.mfa, k)
		}
	}
	s.mfa[id] = mfaPending{Identifier: identifier, Password: password, OAuth: oauth, Until: now.Add(5 * time.Minute)}
	s.mfaMu.Unlock()
	s.setCookie(w, cookieMFA, id, 5*time.Minute)
}

func (s *Server) takeMFA(r *http.Request) (mfaPending, bool) {
	c, err := r.Cookie(cookieMFA)
	if err != nil || c.Value == "" {
		return mfaPending{}, false
	}
	s.mfaMu.Lock()
	defer s.mfaMu.Unlock()
	p, ok := s.mfa[c.Value]
	if !ok || p.Until.Before(time.Now()) {
		delete(s.mfa, c.Value)
		return mfaPending{}, false
	}
	delete(s.mfa, c.Value)
	return p, true
}

func (s *Server) renderPortal(w http.ResponseWriter, r *http.Request, status int, title, nav string, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	loc := s.lang(r)
	_ = PortalShell(
		s.Svc.Cfg.ProductName, title, loc, r.URL.Path, nav,
		s.textLang(loc, "nav", "home"),
		s.textLang(loc, "nav", "personal"),
		s.textLang(loc, "nav", "security"),
		s.textLang(loc, "nav", "apps"),
		s.textLang(loc, "nav", "privacy"),
		s.textLang(loc, "nav", "signout"),
	).Render(templ.WithChildren(r.Context(), c), w)
}

func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) *core.User {
	u := s.user(r)
	if u == nil {
		http.Redirect(w, r, "/auth/sign-in", http.StatusSeeOther)
	}
	return u
}

func (s *Server) sessionID(r *http.Request) string {
	c, err := r.Cookie(cookieSession)
	if err != nil {
		return ""
	}
	cl, err := s.Svc.Sign.Verify(c.Value, "session")
	if err != nil {
		return ""
	}
	return cl.Extra["sid"]
}

func (s *Server) identOf(u *core.User) core.Identity {
	id, err := s.Svc.ParseIdentifier(u.Address)
	if err != nil {
		return core.Identity{Local: u.Username, Domain: s.Svc.Cfg.UserDomain(), Kind: core.KindUser}
	}
	return id
}

func (s *Server) homeLinks(r *http.Request) [][2]string {
	return [][2]string{
		{"/account/personal", s.text(r, "nav", "personal")},
		{"/account/security", s.text(r, "nav", "security")},
		{"/account/apps", s.text(r, "nav", "apps")},
		{"/account/privacy", s.text(r, "nav", "privacy")},
	}
}

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	s.renderPortal(w, r, 200, s.text(r, "home", "title"), "/account",
		PortalHome(s.text(r, "home", "title"), s.text(r, "home", "text"), nonEmpty(u.Name, u.Username), u.Address, s.homeLinks(r)))
}

func (s *Server) personalPage(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	s.personalView(w, r, u, 200, "", "")
}

func (s *Server) personalView(w http.ResponseWriter, r *http.Request, u *core.User, status int, info, errMsg string) {
	id := s.identOf(u)
	kl := s.lab(r, "personal")
	kindLabel := labStr(kl, "user")
	if id.Kind == core.KindOrg {
		kindLabel = labStr(kl, "org")
	}
	s.renderPortal(w, r, status, s.text(r, "personal", "title"), "/account/personal",
		PortalPersonal(s.text(r, "personal", "title"), s.text(r, "personal", "text"), s.csrf(w, r),
			u.Name, u.Address, u.Username, kindLabel, info, errMsg, kl))
}

func (s *Server) personalPost(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.csrfOK(r) {
		s.personalView(w, r, u, 403, "", "Your session expired. Try again.")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if err := s.Svc.SW.UpdateProfile(r.Context(), u.Sub, name); err != nil {
		s.personalView(w, r, u, 400, "", errText(err))
		return
	}
	u.Name = name
	if sid := s.sessionID(r); sid != "" {
		s.Svc.Store.DropSession(u.Sub, sid)
	}
	s.signIn(w, r, u) // refresh name in the session cookie
	s.Svc.Audit.Log("self", u.Sub, "profile_update", "ok", nil)
	s.personalView(w, r, u, 200, labStr(s.lab(r, "personal"), "saved"), "")
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	s.securityView(w, r, u, 200, "", "")
}

func (s *Server) securityView(w http.ResponseWriter, r *http.Request, u *core.User, status int, info, errMsg string) {
	totpOn := false
	if st, err := s.Svc.SW.PasswordStatus(r.Context(), u.Sub); err == nil {
		totpOn = st.TOTPEnabled
	}
	apps, _ := s.Svc.SW.ListAppPasswords(r.Context(), u.Sub)
	s.renderPortal(w, r, status, s.text(r, "security", "title"), "/account/security",
		PortalSecurity(s.text(r, "security", "title"), s.text(r, "security", "text"), s.csrf(w, r),
			info, errMsg, "", totpOn, apps, s.Svc.Store.SessionsOf(u.Sub), s.sessionID(r), s.lab(r, "security")))
}

func (s *Server) securityPassword(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.csrfOK(r) {
		s.securityView(w, r, u, 403, "", "Your session expired. Try again.")
		return
	}
	next, confirm := r.PostFormValue("next"), r.PostFormValue("confirm")
	if next != confirm {
		s.securityView(w, r, u, 400, "", "The two passwords differ.")
		return
	}
	if len(next) < 10 {
		s.securityView(w, r, u, 400, "", errText(core.ErrWeakPassword))
		return
	}
	if err := s.Svc.SW.ChangePassword(r.Context(), u.Sub, r.PostFormValue("current"), next, r.PostFormValue("code")); err != nil {
		s.securityView(w, r, u, 400, "", errText(err))
		return
	}
	s.Svc.Store.Revoke(u.Address)
	s.Svc.Store.DropSessions(u.Sub)
	s.signIn(w, r, u)
	s.Svc.Audit.Log("self", u.Sub, "password_change", "ok", nil)
	s.securityView(w, r, u, 200, labStr(s.lab(r, "security"), "changed"), "")
}

func (s *Server) securityTOTP(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.csrfOK(r) {
		s.securityView(w, r, u, 403, "", "Your session expired. Try again.")
		return
	}
	pw, code, op := r.PostFormValue("password"), r.PostFormValue("code"), r.PostFormValue("op")
	if op == "disable" {
		if err := s.Svc.SW.DisableTOTP(r.Context(), u.Sub, pw, code); err != nil {
			s.securityView(w, r, u, 400, "", errText(err))
			return
		}
		s.Svc.Audit.Log("self", u.Sub, "totp_disable", "ok", nil)
		s.securityView(w, r, u, 200, labStr(s.lab(r, "security"), "totpOff"), "")
		return
	}
	otpauth, err := s.Svc.SW.EnableTOTP(r.Context(), u.Sub, u.Address, pw, code)
	if err != nil {
		s.securityView(w, r, u, 400, "", errText(err))
		return
	}
	s.Svc.Audit.Log("self", u.Sub, "totp_enable", "ok", nil)
	totpOn := true
	apps, _ := s.Svc.SW.ListAppPasswords(r.Context(), u.Sub)
	s.renderPortal(w, r, 200, s.text(r, "security", "title"), "/account/security",
		PortalSecurity(s.text(r, "security", "title"), s.text(r, "security", "text"), s.csrf(w, r),
			labStr(s.lab(r, "security"), "totpHint"), "", otpauth, totpOn, apps, s.Svc.Store.SessionsOf(u.Sub), s.sessionID(r), s.lab(r, "security")))
}

func (s *Server) securityAppCreate(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.csrfOK(r) {
		s.securityView(w, r, u, 403, "", "Your session expired. Try again.")
		return
	}
	ap, err := s.Svc.SW.CreateAppPassword(r.Context(), u.Sub, r.PostFormValue("label"))
	if err != nil {
		s.securityView(w, r, u, 400, "", errText(err))
		return
	}
	s.Svc.Audit.Log("self", u.Sub, "app_password_create", "ok", nil)
	info := labStr(s.lab(r, "security"), "appCreated") + " " + ap.Secret
	s.securityView(w, r, u, 200, info, "")
}

func (s *Server) securityAppRevoke(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.csrfOK(r) {
		s.securityView(w, r, u, 403, "", "Your session expired. Try again.")
		return
	}
	if err := s.Svc.SW.DestroyAppPassword(r.Context(), u.Sub, r.PostFormValue("id")); err != nil {
		s.securityView(w, r, u, 400, "", errText(err))
		return
	}
	s.Svc.Audit.Log("self", u.Sub, "app_password_revoke", "ok", nil)
	s.securityView(w, r, u, 200, labStr(s.lab(r, "security"), "revoke"), "")
}

func (s *Server) securityEverywhere(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.csrfOK(r) {
		s.securityView(w, r, u, 403, "", "Your session expired. Try again.")
		return
	}
	s.Svc.Store.Revoke(u.Address)
	s.Svc.Store.DropSessions(u.Sub)
	s.clearCookie(w, cookieSession)
	s.Svc.Audit.Log("self", u.Sub, "sign_out_everywhere", "ok", nil)
	s.notice(w, r, 200, "signout", "success", "log-out", "", map[string]any{
		"cta": s.text(r, "signin", "title"), "ctaHref": "/auth/sign-in", "secondary": "", "secondaryHref": "",
		"title": labStr(s.lab(r, "security"), "signedOut"),
	})
}

func (s *Server) appsPage(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	s.appsView(w, r, u, 200, "")
}

func (s *Server) appsView(w http.ResponseWriter, r *http.Request, u *core.User, status int, info string) {
	grants, _ := s.Svc.SW.ListOAuthGrants(r.Context(), u.Sub)
	lab := s.lab(r, "apps")
	s.renderPortal(w, r, status, s.text(r, "apps", "title"), "/account/apps",
		PortalApps(s.text(r, "apps", "title"), s.text(r, "apps", "text"), s.csrf(w, r), info, labStr(lab, "empty"), grants, labStr(lab, "revoke")))
}

func (s *Server) appsRevoke(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.csrfOK(r) {
		s.appsView(w, r, u, 403, "")
		return
	}
	if err := s.Svc.SW.DestroyOAuthGrant(r.Context(), u.Sub, r.PostFormValue("id")); err != nil {
		s.appsView(w, r, u, 400, errText(err))
		return
	}
	s.Svc.Audit.Log("self", u.Sub, "oauth_grant_revoke", "ok", nil)
	s.appsView(w, r, u, 200, labStr(s.lab(r, "apps"), "revoked"))
}

func (s *Server) privacyPage(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	s.privacyView(w, r, u, 200, "", "")
}

func (s *Server) privacyView(w http.ResponseWriter, r *http.Request, u *core.User, status int, info, errMsg string) {
	s.renderPortal(w, r, status, s.text(r, "privacy", "title"), "/account/privacy",
		PortalPrivacy(s.text(r, "privacy", "title"), s.text(r, "privacy", "text"), s.csrf(w, r),
			info, errMsg, s.Svc.Audit.Query(u.Sub, 50), s.lab(r, "privacy")))
}

func (s *Server) privacyExport(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	out, err := s.Svc.Export(r.Context(), u.Address, "self")
	if err != nil {
		s.privacyView(w, r, u, 500, "", errText(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"authfly-export.json\"")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) privacyErase(w http.ResponseWriter, r *http.Request) {
	u := s.requireUser(w, r)
	if u == nil {
		return
	}
	if !s.csrfOK(r) {
		s.privacyView(w, r, u, 403, "", "Your session expired. Try again.")
		return
	}
	if _, _, err := s.Svc.PasswordSignIn(r.Context(), u.Address, r.PostFormValue("password")); err != nil && !errors.Is(err, core.ErrUnverified) && !errors.Is(err, core.ErrMFARequired) {
		s.privacyView(w, r, u, 401, "", errText(core.ErrInvalidCredentials))
		return
	}
	if _, err := s.Svc.Erase(r.Context(), u.Address, "self"); err != nil {
		s.privacyView(w, r, u, 500, "", errText(err))
		return
	}
	s.clearCookie(w, cookieSession)
	s.notice(w, r, 200, "signout", "success", "circle-check", "", map[string]any{
		"title": labStr(s.lab(r, "privacy"), "deleted"), "cta": s.text(r, "signin", "title"), "ctaHref": "/auth/sign-in", "secondary": "", "secondaryHref": "",
	})
}

func (s *Server) mfaPage(w http.ResponseWriter, r *http.Request) {
	s.requestView(w, r, 200, "mfa", "code", "/auth/2fa", "", "")
}

func (s *Server) mfaPost(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(r) {
		s.requestView(w, r, 403, "mfa", "code", "/auth/2fa", "", "Your session expired. Try again.")
		return
	}
	p, ok := s.takeMFA(r)
	if !ok {
		s.signInView(w, r, 401, "password", errText(core.ErrInvalidCredentials), "")
		return
	}
	s.clearCookie(w, cookieMFA)
	code := r.PostFormValue("code")
	if p.OAuth {
		s.finishOAuth(w, r, p.Identifier, p.Password, code)
		return
	}
	u, _, err := s.Svc.PasswordSignInMFA(r.Context(), p.Identifier, p.Password, code)
	if err != nil {
		s.signInView(w, r, 401, "password", errText(err), "")
		return
	}
	s.signIn(w, r, u)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *Server) finishOAuth(w http.ResponseWriter, r *http.Request, identifier, password, mfaToken string) {
	or, _ := s.pending(r)
	if or == nil {
		s.notice(w, r, 400, "linkerror", "error", "shield-alert", "", map[string]any{"cta": "Back to sign in", "ctaHref": "/auth/sign-in"})
		return
	}
	ident, err := s.Svc.ParseIdentifier(identifier)
	if err != nil {
		s.signInView(w, r, 401, "password", errText(core.ErrInvalidCredentials), "/oauth/authorize")
		return
	}
	code, err := s.Svc.SW.Authorize(r.Context(), core.AuthCodeRequest{
		AccountName: ident.Address(), AccountSecret: password, MFAToken: mfaToken,
		ClientID: or.ClientID, RedirectURI: or.RedirectURI, Scope: or.Scope, Nonce: or.Nonce, State: or.State,
		CodeChallenge: or.Challenge, Consent: true,
	})
	if err != nil {
		if errors.Is(err, core.ErrMFARequired) {
			s.beginMFA(w, identifier, password, true)
			s.requestView(w, r, 401, "mfa", "code", "/auth/2fa", "", "")
			return
		}
		s.signInView(w, r, 401, "password", errText(err), "/oauth/authorize")
		return
	}
	s.showConsent(w, r, or, ident.Address(), identifier, code)
}

func (s *Server) showConsent(w http.ResponseWriter, r *http.Request, or *oauthReq, account, identifier, code string) {
	or.Code = code
	b, _ := json.Marshal(or)
	cl := core.NewClaims("oauth", or.ClientID, 5*time.Minute)
	cl.Extra = map[string]string{"req": string(b), "account": identifier}
	s.setCookie(w, cookieOAuth, s.Svc.Sign.Sign(cl), 5*time.Minute)
	scopes := []map[string]any{}
	for _, sc := range strings.Fields(or.Scope) {
		label := map[string]string{"openid": "Your account identifier", "email": "Your email address", "profile": "Your name", "offline_access": "Access while you are away"}[sc]
		scopes = append(scopes, map[string]any{"id": sc, "title": nonEmpty(label, sc), "text": sc, "icon": "check"})
	}
	s.render(w, r, 200, s.text(r, "consent", "title"), blocks.AuthflyConsent(blocks.AuthflyConsentProps{
		Id: "authfly", Title: s.text(r, "consent", "title"),
		Text:   s.Clients[or.ClientID].Name + " wants to sign you in with your mail account.",
		Action: "/oauth/consent", Csrf: s.csrf(w, r),
		Client: s.Clients[or.ClientID].Name, Account: account, Scopes: scopes, Labels: s.lab(r, "consent"),
	}))
}

package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ui8kit/authkit/server/core"
)

// APIKey, when set, is required in the X-Authkit-Key header of every JSON API call (adapters call from servers).
var APIKey string

func (s *Server) api(m *http.ServeMux) {
	h := func(pattern string, f func(r *http.Request, in map[string]string) (int, any)) {
		m.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if APIKey != "" && r.Header.Get("X-Authkit-Key") != APIKey {
				w.WriteHeader(401)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
				return
			}
			in := map[string]string{}
			if r.Method == "POST" {
				_ = json.NewDecoder(r.Body).Decode(&in)
			}
			code, out := f(r, in)
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	fail := func(code int, err error) (int, any) {
		kind := "error"
		switch {
		case errors.Is(err, core.ErrInvalidCredentials), errors.Is(err, core.ErrOtherDomain):
			kind = "invalid_credentials"
		case errors.Is(err, core.ErrUnverified):
			kind = "unverified"
		case errors.Is(err, core.ErrAccountExists):
			kind = "account_exists"
		case errors.Is(err, core.ErrBadToken):
			kind = "invalid_token"
		case errors.Is(err, core.ErrWeakPassword), errors.Is(err, core.ErrBadUsername):
			kind = "invalid_input"
		case errors.Is(err, core.ErrMFARequired):
			kind = "mfa_required"
		}
		return code, map[string]string{"error": kind, "message": errText(err)}
	}
	h("POST /api/v1/sign-up", func(r *http.Request, in map[string]string) (int, any) {
		u, err := s.Svc.SignUp(r.Context(), in["name"], in["username"], in["password"])
		if err != nil {
			return fail(400, err)
		}
		return 201, map[string]any{"user": u}
	})
	h("POST /api/v1/sign-in", func(r *http.Request, in map[string]string) (int, any) {
		u, _, err := s.Svc.PasswordSignIn(r.Context(), in["identifier"], in["password"])
		if err != nil {
			return fail(401, err)
		}
		return 200, map[string]any{"token": s.SessionToken(u), "user": u}
	})
	h("POST /api/v1/magic-link", func(r *http.Request, in map[string]string) (int, any) {
		addr, err := s.Svc.RequestMagicLink(r.Context(), in["identifier"])
		if err != nil {
			return fail(400, err)
		}
		return 202, map[string]any{"sent_to": addr}
	})
	h("POST /api/v1/magic-link/verify", func(r *http.Request, in map[string]string) (int, any) {
		u, err := s.Svc.VerifyMagicLink(r.Context(), in["token"])
		if err != nil {
			return fail(400, err)
		}
		return 200, map[string]any{"token": s.SessionToken(u), "user": u}
	})
	h("POST /api/v1/verify-email", func(r *http.Request, in map[string]string) (int, any) {
		addr, err := s.Svc.VerifyEmail(in["token"])
		if err != nil {
			return fail(400, err)
		}
		return 200, map[string]any{"email": addr, "email_verified": true}
	})
	h("POST /api/v1/forgot", func(r *http.Request, in map[string]string) (int, any) {
		addr, err := s.Svc.ForgotPassword(r.Context(), in["email"])
		if err != nil {
			return fail(400, err)
		}
		return 202, map[string]any{"sent_to": addr}
	})
	h("POST /api/v1/reset", func(r *http.Request, in map[string]string) (int, any) {
		addr, err := s.Svc.ResetPassword(r.Context(), in["token"], in["password"])
		if err != nil {
			return fail(400, err)
		}
		return 200, map[string]any{"email": addr}
	})
	h("GET /api/v1/me", func(r *http.Request, _ map[string]string) (int, any) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		u := s.userFromToken(tok)
		if u == nil {
			if u = s.user(r); u == nil {
				return 401, map[string]string{"error": "unauthenticated"}
			}
		}
		return 200, map[string]any{"user": u}
	})
	h("GET /api/v1/config", func(r *http.Request, _ map[string]string) (int, any) {
		return 200, map[string]any{"domain": s.Svc.Cfg.Domain, "product": s.Svc.Cfg.ProductName, "methods": []string{"password", "magic_link"}, "methods_stubbed": []string{"social", "totp", "webauthn"}}
	})
}

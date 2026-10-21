package web

// GDPR endpoints. Self-service on the public JSON API (/api/v1/me/...), and the internal admin API used by the Authfly
// Console (AdminHandler, served on AUTHFLY_ADMIN_ADDR, never published, key in X-Authfly-Admin-Key).

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/authfly/cli/server/core"
)

// TermsVersion is recorded with the terms consent of hosted sign-up.
var TermsVersion = "2026-10"

func (s *Server) apiUser(r *http.Request) *core.User {
	if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok != "" {
		if u := s.userFromToken(tok); u != nil {
			return u
		}
	}
	return s.user(r)
}

type apiFunc = func(r *http.Request, in map[string]string) (int, any)

func (s *Server) meGDPR(h func(string, func(*http.Request, map[string]string) (int, any)), fail func(int, error) (int, any)) {
	auth := func(f func(r *http.Request, in map[string]string, u *core.User) (int, any)) apiFunc {
		return func(r *http.Request, in map[string]string) (int, any) {
			u := s.apiUser(r)
			if u == nil {
				return 401, map[string]string{"error": "unauthenticated"}
			}
			return f(r, in, u)
		}
	}
	h("GET /api/v1/me/export", auth(func(r *http.Request, _ map[string]string, u *core.User) (int, any) {
		out, err := s.Svc.Export(r.Context(), u.Address, "self")
		if err != nil {
			return fail(500, err)
		}
		return 200, out
	}))
	h("GET /api/v1/me/consents", auth(func(r *http.Request, _ map[string]string, u *core.User) (int, any) {
		return 200, map[string]any{"consents": s.Svc.Store.Consents(u.Address)}
	}))
	h("GET /api/v1/me/audit", auth(func(r *http.Request, _ map[string]string, u *core.User) (int, any) {
		return 200, map[string]any{"events": s.Svc.Audit.Query(u.Address, 200)}
	}))
	h("POST /api/v1/me/sign-out-everywhere", auth(func(r *http.Request, _ map[string]string, u *core.User) (int, any) {
		s.Svc.Store.Revoke(u.Address)
		s.Svc.Audit.Log("self", u.Address, "sign_out_everywhere", "ok", nil)
		return 200, map[string]any{"revoked": true}
	}))
	// Erasure needs the password again (a stolen session alone must not delete an account).
	h("DELETE /api/v1/me", auth(func(r *http.Request, in map[string]string, u *core.User) (int, any) {
		if _, _, err := s.Svc.PasswordSignIn(r.Context(), u.Address, in["password"]); err != nil && !errors.Is(err, core.ErrUnverified) {
			return fail(401, core.ErrInvalidCredentials)
		}
		rep, err := s.Svc.Erase(r.Context(), u.Address, "self")
		if err != nil {
			return fail(500, err)
		}
		return 200, rep
	}))
}

// AdminHandler is the internal API of the Authfly Console. Only GDPR and Authfly-state operations live here
// (Stalwart management goes from the console to Stalwart directly); the store and the audit log have one writer.
func (s *Server) AdminHandler(key string) http.Handler {
	m := http.NewServeMux()
	j := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	h := func(pattern string, f func(w http.ResponseWriter, r *http.Request, actor string)) {
		m.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if key == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Authfly-Admin-Key")), []byte(key)) != 1 {
				j(w, 401, map[string]string{"error": "unauthorized"})
				return
			}
			actor := "console"
			if a := r.Header.Get("X-Authfly-Actor"); a != "" {
				actor = "console:" + a
			}
			f(w, r, actor)
		})
	}
	h("GET /admin/v1/users/{addr}/export", func(w http.ResponseWriter, r *http.Request, actor string) {
		out, err := s.Svc.Export(r.Context(), r.PathValue("addr"), actor)
		if err != nil {
			j(w, statusOf(err), map[string]string{"error": err.Error()})
			return
		}
		j(w, 200, out)
	})
	h("POST /admin/v1/users/{addr}/erase", func(w http.ResponseWriter, r *http.Request, actor string) {
		rep, err := s.Svc.Erase(r.Context(), r.PathValue("addr"), actor)
		if err != nil {
			j(w, statusOf(err), map[string]string{"error": err.Error()})
			return
		}
		j(w, 200, rep)
	})
	h("POST /admin/v1/users/{addr}/revoke", func(w http.ResponseWriter, r *http.Request, actor string) {
		s.Svc.Store.Revoke(r.PathValue("addr"))
		s.Svc.Audit.Log(actor, r.PathValue("addr"), "sign_out_everywhere", "ok", nil)
		j(w, 200, map[string]any{"revoked": true})
	})
	h("GET /admin/v1/users/{addr}", func(w http.ResponseWriter, r *http.Request, actor string) {
		j(w, 200, map[string]any{"authfly": s.Svc.Store.Snapshot(r.PathValue("addr")), "audit": s.Svc.Audit.Query(r.PathValue("addr"), 50)})
	})
	h("GET /admin/v1/audit", func(w http.ResponseWriter, r *http.Request, actor string) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if n <= 0 {
			n = 200
		}
		total, broken := s.Svc.Audit.Verify()
		j(w, 200, map[string]any{"events": s.Svc.Audit.Query(r.URL.Query().Get("subject"), n), "total": total, "chainIntact": broken < 0, "firstBroken": broken})
	})
	h("POST /admin/v1/retention/run", func(w http.ResponseWriter, r *http.Request, actor string) {
		n := s.Svc.Audit.Prune(s.Svc.Cfg.AuditRetention)
		s.Svc.Audit.Log(actor, "", "retention", "ok", map[string]string{"pruned": strconv.Itoa(n)})
		j(w, 200, map[string]any{"pruned": n, "auditRetention": s.Svc.Cfg.AuditRetention.String()})
	})
	h("GET /admin/v1/retention", func(w http.ResponseWriter, r *http.Request, actor string) {
		j(w, 200, map[string]any{"auditRetention": s.Svc.Cfg.AuditRetention.String(), "now": time.Now().UTC()})
	})
	return m
}

func statusOf(err error) int {
	switch {
	case errors.Is(err, core.ErrNotFound):
		return 404
	case errors.Is(err, core.ErrOtherDomain), errors.Is(err, core.ErrBadUsername):
		return 400
	}
	return 500
}

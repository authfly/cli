package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func (s *Server) loadLabels() {
	s.labels = map[string]map[string]map[string]any{}
	parse := func(lang string, raw []byte) {
		var m map[string]map[string]any
		if json.Unmarshal(raw, &m) != nil {
			return
		}
		s.labels[lang] = m
	}
	parse("en", labelsJSON)
	parse("ru", labelsRU)
}

func (s *Server) lang(r *http.Request) string {
	if r == nil {
		return "en"
	}
	if c, err := r.Cookie(cookieLang); err == nil && (c.Value == "ru" || c.Value == "en") {
		return c.Value
	}
	al := strings.ToLower(r.Header.Get("Accept-Language"))
	if strings.HasPrefix(al, "ru") {
		return "ru"
	}
	return "en"
}

func (s *Server) pack(lang string) map[string]map[string]any {
	if s.labels == nil {
		return map[string]map[string]any{}
	}
	if p := s.labels[lang]; p != nil {
		return p
	}
	if p := s.labels["en"]; p != nil {
		return p
	}
	return map[string]map[string]any{}
}

func (s *Server) text(r *http.Request, page, key string) string {
	return s.textLang(s.lang(r), page, key)
}

func (s *Server) textLang(lang, page, key string) string {
	if v, ok := s.pack(lang)[page][key].(string); ok {
		return v
	}
	if v, ok := s.labels["en"][page][key].(string); ok {
		return v
	}
	return ""
}

func (s *Server) lab(r *http.Request, page string) map[string]any {
	return s.labLang(s.lang(r), page)
}

func (s *Server) labLang(lang, page string) map[string]any {
	m := map[string]any{}
	src := s.pack(lang)[page]
	if src == nil {
		src = s.labels["en"][page]
	}
	if l, ok := src["labels"].(map[string]any); ok {
		for k, v := range l {
			m[k] = v
		}
	}
	if page == "signup" && Policy.TermsLabel != "" {
		m["terms"] = Policy.TermsLabel
	}
	if page == "signup" && m["invite"] == nil {
		if t := s.textLang(lang, "invite", "title"); t != "" {
			// invite field copy lives under invite.labels.token
			if inv := s.pack(lang)["invite"]; inv != nil {
				if l, ok := inv["labels"].(map[string]any); ok {
					if tok, ok := l["token"].(string); ok {
						m["invite"] = tok
					}
				}
			}
		}
	}
	if s.Svc != nil {
		if page == "signup" || page == "signin" || page == "magic" {
			m["domain"] = "@" + s.Svc.Cfg.UserDomain()
		}
		if !s.Svc.Cfg.PublicSignup && (page == "signin" || page == "magic") {
			m["signupText"] = s.textLang(lang, "invite", "have")
			m["signupLink"] = s.textLang(lang, "invite", "link")
			m["signupHref"] = "/auth/sign-up"
		}
	}
	return m
}

func (s *Server) setLang(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("set")
	if v != "ru" && v != "en" {
		v = "en"
	}
	s.setCookie(w, cookieLang, v, 365*24*time.Hour)
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

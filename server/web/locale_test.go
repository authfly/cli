package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authfly/cli/server/core"
)

func TestDefaultLocale(t *testing.T) {
	req := func(al, cookie string) *http.Request {
		r := httptest.NewRequest("GET", "/auth/sign-in", nil)
		if al != "" {
			r.Header.Set("Accept-Language", al)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: cookieLang, Value: cookie})
		}
		return r
	}
	s := testServer(t)
	// no default: Accept-Language, else en (unchanged behaviour)
	for _, c := range []struct{ al, ck, want string }{{"", "", "en"}, {"ru-RU,ru;q=0.9", "", "ru"}, {"en-US", "", "en"}, {"ru", "en", "en"}} {
		if got := s.lang(req(c.al, c.ck)); got != c.want {
			t.Errorf("no default: lang(al=%q, cookie=%q) = %q, want %q", c.al, c.ck, got, c.want)
		}
	}
	s.Svc.Cfg.DefaultLocale = "ru"
	// default ru: the browser language does not override it, an explicit cookie does
	for _, c := range []struct{ al, ck, want string }{{"", "", "ru"}, {"en-US,en;q=0.9", "", "ru"}, {"en-US", "en", "en"}, {"", "ru", "ru"}} {
		if got := s.lang(req(c.al, c.ck)); got != c.want {
			t.Errorf("default ru: lang(al=%q, cookie=%q) = %q, want %q", c.al, c.ck, got, c.want)
		}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req("en-US", ""))
	if b := rec.Body.String(); rec.Code >= 400 || !containsLangRU(b) {
		t.Errorf("default ru: sign-in page not rendered in ru (code %d)", rec.Code)
	}
}

func containsLangRU(b string) bool { return strings.Contains(b, `lang="ru"`) }

func TestParseLocale(t *testing.T) {
	for in, want := range map[string]string{"ru": "ru", "RU": "ru", "ru-RU": "ru", "ru_RU": "ru", "en": "en", "en-GB": "en", "de": "", "": "", " ru ": "ru"} {
		if got := core.ParseLocale(in); got != want {
			t.Errorf("ParseLocale(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUILocale(t *testing.T) {
	if uiLocale([]string{"en"}, false) != "" || uiLocale([]string{"ru"}, false) != "ru" || uiLocale([]string{"en"}, true) != "en" || uiLocale(nil, true) != "" {
		t.Error("uiLocale")
	}
}

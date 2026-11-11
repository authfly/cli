package rp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/me": "/me", "/me?x=1": "/me?x=1", "": "", "//evil.com": "", "https://evil.com": "", "/\\evil.com": "", "me": "", "/a\r\nb": ""} {
		if got := SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLangDefault(t *testing.T) {
	defer func() { DefaultLang = "" }()
	mk := func(q, cookie, al string) *http.Request {
		r := httptest.NewRequest("GET", "/"+q, nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "lang", Value: cookie})
		}
		if al != "" {
			r.Header.Set("Accept-Language", al)
		}
		return r
	}
	cases := []struct {
		def, q, ck, al, want string
	}{
		{"", "", "", "", "en"}, {"", "", "", "ru-RU", "ru"}, {"", "", "en", "ru", "en"},
		{"ru", "", "", "", "ru"}, {"ru", "", "", "en-US", "ru"}, {"ru", "", "en", "", "en"}, {"ru", "?lang=en", "", "", "en"},
		{"en", "", "", "ru-RU", "en"},
	}
	for _, c := range cases {
		DefaultLang = c.def
		if got := Lang(mk(c.q, c.ck, c.al)); got != c.want {
			t.Errorf("default %q: Lang(q=%q cookie=%q al=%q) = %q, want %q", c.def, c.q, c.ck, c.al, got, c.want)
		}
	}
}

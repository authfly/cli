package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/authfly/cli/server/core"
	"github.com/authfly/cli/server/ext"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	st, err := core.OpenStore(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc := &core.Service{
		Cfg:   core.Config{Domain: "cab.yself.link", UserDomainName: "cab.yself.link", OrgDomainName: "yself.link", ProductName: "YSELF", PublicURL: "http://accounts.test", PublicSignup: false},
		Store: st,
		Sign:  core.Signer{Key: []byte("0123456789abcdef0123456789abcdef")},
		SW:    &core.Stalwart{BaseURL: "http://127.0.0.1:9"},
	}
	return New(svc, ext.Registry{}, nil, false)
}

func TestRootAnonymousGoesToSignIn(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/auth/sign-in" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestRootSignedInGoesToAccount(t *testing.T) {
	s := testServer(t)
	u := &core.User{Sub: "acc1", Address: "alice@cab.yself.link", Username: "alice", Name: "Alice", Method: "password"}
	tok := s.SessionToken(u)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: tok})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestSignUpIsInviteOnly(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/auth/sign-up", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invite") && !strings.Contains(strings.ToLower(w.Body.String()), "invite") {
		t.Fatalf("expected invite gate, got %s", w.Body.String()[:min(400, len(w.Body.String()))])
	}
}

func TestLangSwitchSetsCookie(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/auth/lang?set=ru&next=/auth/sign-in", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d", w.Code)
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieLang && c.Value == "ru" {
			found = true
		}
	}
	if !found {
		t.Fatal("lang cookie")
	}
}

func TestI18nRussianSignIn(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/auth/sign-in", nil)
	r.AddCookie(&http.Cookie{Name: cookieLang, Value: "ru"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Вход") {
		t.Fatalf("expected Russian title, got %s", w.Body.String()[:min(500, len(w.Body.String()))])
	}
}

func TestAccountRequiresSession(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/account", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/auth/sign-in" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
}

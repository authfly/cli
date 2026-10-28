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

func TestConfigDropsMagicWhenDisabled(t *testing.T) {
	s := testServer(t)
	s.Svc.Cfg.Methods = []string{"password"}
	r := httptest.NewRequest("GET", "/api/v1/config", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	if strings.Contains(body, "magic_link") {
		t.Fatalf("magic_link still advertised: %s", body)
	}
	if !strings.Contains(body, `"password"`) {
		t.Fatalf("password missing: %s", body)
	}
}

func TestSignInHidesMagicWhenDisabled(t *testing.T) {
	s := testServer(t)
	s.Svc.Cfg.Methods = []string{"password"}
	s.Svc.Mail = &core.Mailer{Addr: "localhost:25"}
	r := httptest.NewRequest("GET", "/auth/sign-in", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "Email me a sign-in link") {
		t.Fatal("magic link still shown")
	}
}

func TestSignInHidesForgotWithoutSMTP(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/auth/sign-in", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "Forgot password?") {
		t.Fatal("forgot still shown with SMTP unset")
	}
	r = httptest.NewRequest("GET", "/auth/forgot", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("forgot page %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "SMTP_ADDR") && !strings.Contains(strings.ToLower(w.Body.String()), "mail") {
		t.Fatalf("expected nomail message, got %s", w.Body.String()[:min(400, len(w.Body.String()))])
	}
	r = httptest.NewRequest("POST", "/api/v1/forgot", strings.NewReader(`{"email":"alice@cab.yself.link"}`))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("forgot api %d %s", w.Code, w.Body.String())
	}
}

func TestOAuthAuthorizeWithSessionStillAsksPassword(t *testing.T) {
	s := testServer(t)
	s.Clients["app"] = Client{ID: "app", Name: "App", RedirectURIs: []string{"https://app.example/cb"}}
	u := &core.User{Sub: "acc1", Address: "alice@cab.yself.link", Username: "alice", Name: "Alice", Method: "password"}
	tok := s.SessionToken(u)
	r := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://app.example/cb&code_challenge=abc&code_challenge_method=S256&state=s&scope=openid", nil)
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: tok})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(strings.ToLower(body), "password") {
		t.Fatalf("expected password prompt, got %s", body[:min(500, len(body))])
	}
	if strings.Contains(body, "alice@cab.yself.link") && !strings.Contains(strings.ToLower(body), "password") {
		t.Fatal("skipped to consent")
	}
}

func TestDiscoveryRewriteDropsDeviceAndCIMD(t *testing.T) {
	d := map[string]any{
		"authorization_endpoint":                "https://mail.example/auth/authorize",
		"device_authorization_endpoint":         "https://mail.example/auth/device",
		"registration_endpoint":                 "https://mail.example/auth/register",
		"introspection_endpoint":                "https://mail.example/auth/introspect",
		"client_id_metadata_document_supported": true,
		"grant_types_supported":                 []any{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
	}
	rewriteDiscovery(d, "https://accounts.example")
	if d["authorization_endpoint"] != "https://accounts.example/oauth/authorize" {
		t.Fatalf("%v", d["authorization_endpoint"])
	}
	for _, k := range []string{"device_authorization_endpoint", "registration_endpoint", "introspection_endpoint", "client_id_metadata_document_supported"} {
		if _, ok := d[k]; ok {
			t.Fatalf("still present %s", k)
		}
	}
	g, _ := d["grant_types_supported"].([]any)
	for _, x := range g {
		if x == "urn:ietf:params:oauth:grant-type:device_code" || x == "device_code" {
			t.Fatalf("device_code still in grants: %v", g)
		}
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

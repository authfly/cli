package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/authfly/cli/server/core"
	"github.com/authfly/cli/server/idp"
)

type rpSink struct {
	mu     sync.Mutex
	tokens map[string][]string // client -> logout tokens
}

func (k *rpSink) handler(client string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		k.tokens[client] = append(k.tokens[client], r.PostFormValue("logout_token"))
		k.mu.Unlock()
	}
}

func (k *rpSink) n(client string) int { k.mu.Lock(); defer k.mu.Unlock(); return len(k.tokens[client]) }

type env struct {
	t    *testing.T
	s    *Server
	ts   *httptest.Server
	sink *rpSink
	dir  string
	hc   *http.Client
}

func hexsha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, s: testServer(t), sink: &rpSink{tokens: map[string][]string{}}, dir: t.TempDir()}
	var h http.Handler
	e.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(e.ts.Close)
	rpA := httptest.NewServer(e.sink.handler("app-a"))
	rpB := httptest.NewServer(e.sink.handler("app-b"))
	t.Cleanup(rpA.Close)
	t.Cleanup(rpB.Close)
	st, err := idp.OpenStore(filepath.Join(e.dir, "idp.json"))
	if err != nil {
		t.Fatal(err)
	}
	ks, err := idp.LoadKeySet([]string{filepath.Join(e.dir, "k.pem")}, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := idp.New(idp.Options{Issuer: e.ts.URL, Store: st, Keys: ks, Insecure: true, Clients: []idp.ClientConfig{
		{ID: "app-a", Name: "App A", RedirectURIs: []string{"https://a.test/cb"}, PostLogoutRedirectURIs: []string{"https://a.test/"}, BackchannelLogoutURI: rpA.URL, SecretSHA256: hexsha("sa")},
		{ID: "app-b", Name: "App B", RedirectURIs: []string{"https://b.test/cb"}, PostLogoutRedirectURIs: []string{"https://b.test/"}, BackchannelLogoutURI: rpB.URL, SecretSHA256: hexsha("sb")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	e.s.Svc.Cfg.PublicURL = e.ts.URL
	e.s.IdP = p
	h = e.s.Handler()
	e.hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return e
}

// signIn creates a portal (= SSO) session as a password sign-in would, returning the cookie.
func (e *env) signIn() *http.Cookie {
	u := &core.User{Sub: "2", Address: "wmaster@cab.yself.link", Username: "wmaster", Name: "W Master", Method: "password"}
	w := httptest.NewRecorder()
	e.s.signIn(w, httptest.NewRequest("POST", "/auth/sign-in", nil), u)
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieSession {
			return c
		}
	}
	e.t.Fatal("no session cookie")
	return nil
}

func (e *env) get(u string, c *http.Cookie) *http.Response {
	if strings.HasPrefix(u, "/") {
		u = e.ts.URL + u
	}
	req, _ := http.NewRequest("GET", u, nil)
	if c != nil {
		req.AddCookie(c)
	}
	res, err := e.hc.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	return res
}

// authorize runs the code flow; it returns the final redirect to the client (code or error).
func (e *env) authorize(client, redirect string, c *http.Cookie, extra url.Values) *url.URL {
	verifier := idp.RandomID()
	h := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {redirect}, "scope": {"openid profile email offline_access"}, "state": {"st"}, "nonce": {"n1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(h[:])}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		q[k] = v
	}
	loc := e.ts.URL + idp.PathAuthorize + "?" + q.Encode()
	for i := 0; i < 6; i++ {
		res := e.get(loc, c)
		if res.StatusCode/100 != 3 {
			e.t.Fatalf("authorize step %d: http %d at %s", i, res.StatusCode, loc)
		}
		l, _ := res.Location()
		if strings.HasPrefix(l.String(), redirect) {
			l.Fragment = verifier // carry the verifier for the exchange
			return l
		}
		loc = l.String()
	}
	e.t.Fatal("authorize: too many redirects")
	return nil
}

func (e *env) exchange(client, secret, redirect string, cb *url.URL) map[string]any {
	f := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "client_id": {client}, "client_secret": {secret}, "redirect_uri": {redirect}, "code_verifier": {cb.Fragment}}
	res, err := http.PostForm(e.ts.URL+idp.PathToken, f)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(res.Body).Decode(&m)
	if res.StatusCode != 200 {
		e.t.Fatalf("token: %d %v", res.StatusCode, m)
	}
	return m
}

func claims(t *testing.T, jwt string) map[string]any {
	p := strings.Split(jwt, ".")
	b, _ := base64.RawURLEncoding.DecodeString(p[1])
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIdPSSOSecondAppWithoutPassword(t *testing.T) {
	e := newEnv(t)
	ck := e.signIn()
	a := e.exchange("app-a", "sa", "https://a.test/cb", e.authorize("app-a", "https://a.test/cb", ck, nil))
	ca := claims(t, a["id_token"].(string))
	if ca["sub"] != "2" || ca["sid"] == nil || ca["iss"] != e.ts.URL || ca["nonce"] != "n1" {
		t.Fatalf("id token claims %v", ca)
	}
	// second application: no password page, code straight away (SSO)
	b := e.exchange("app-b", "sb", "https://b.test/cb", e.authorize("app-b", "https://b.test/cb", ck, nil))
	cb := claims(t, b["id_token"].(string))
	if cb["sid"] != ca["sid"] || cb["name"] != "W Master" {
		t.Fatalf("sso claims %v", cb)
	}
	if g := e.s.IdP.Store.GrantsOf("2"); len(g) != 2 {
		t.Fatalf("grants %v", g)
	}
	// userinfo with the opaque access token
	req, _ := http.NewRequest("GET", e.ts.URL+idp.PathUserinfo, nil)
	req.Header.Set("Authorization", "Bearer "+a["access_token"].(string))
	res, _ := http.DefaultClient.Do(req)
	var ui map[string]any
	_ = json.NewDecoder(res.Body).Decode(&ui)
	res.Body.Close()
	if ui["sub"] != "2" || ui["email"] != "wmaster@cab.yself.link" {
		t.Fatalf("userinfo %v", ui)
	}
}

func TestIdPPromptNone(t *testing.T) {
	e := newEnv(t)
	cb := e.authorize("app-a", "https://a.test/cb", nil, url.Values{"prompt": {"none"}})
	if cb.Query().Get("error") != "login_required" || cb.Query().Get("state") != "st" {
		t.Fatalf("prompt=none without session: %s", cb)
	}
	ck := e.signIn()
	cb = e.authorize("app-a", "https://a.test/cb", ck, url.Values{"prompt": {"none"}})
	if cb.Query().Get("code") == "" {
		t.Fatalf("prompt=none with session: %s", cb)
	}
	// prompt=login shows the sign-in page instead of reusing the session
	res := e.get(idp.PathAuthorize+"?"+url.Values{"response_type": {"code"}, "client_id": {"app-a"}, "redirect_uri": {"https://a.test/cb"}, "scope": {"openid"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}, "prompt": {"login"}}.Encode(), ck)
	l, _ := res.Location()
	if res2 := e.get(l.String(), ck); res2.StatusCode != 200 {
		t.Fatalf("prompt=login: %d", res2.StatusCode)
	}
}

func TestIdPAppLogoutKeepsSSOAndOtherApps(t *testing.T) {
	e := newEnv(t)
	ck := e.signIn()
	a := e.exchange("app-a", "sa", "https://a.test/cb", e.authorize("app-a", "https://a.test/cb", ck, nil))
	b := e.exchange("app-b", "sb", "https://b.test/cb", e.authorize("app-b", "https://b.test/cb", ck, nil))
	q := url.Values{"id_token_hint": {a["id_token"].(string)}, "client_id": {"app-a"}, "post_logout_redirect_uri": {"https://a.test/"}}
	res := e.get(idp.PathEndSession+"?"+q.Encode(), nil)
	if l, _ := res.Location(); res.StatusCode/100 != 3 || !strings.HasPrefix(l.String(), "https://a.test/") {
		t.Fatalf("end_session: %d %v", res.StatusCode, l)
	}
	sid := claims(t, a["id_token"].(string))["sid"].(string)
	ss := e.s.IdP.Store.Session(sid)
	if ss == nil || ss.Clients["app-a"] != nil || ss.Clients["app-b"] == nil {
		t.Fatalf("session after app logout: %+v", ss)
	}
	if refresh(e, "app-a", "sa", a) == 200 || refresh(e, "app-b", "sb", b) != 200 {
		t.Fatal("app-a refresh must die, app-b must live")
	}
	if e.sink.n("app-a")+e.sink.n("app-b") != 0 {
		t.Fatal("no back-channel on per-app logout")
	}
	// the SSO session still signs app-a in without a password
	if e.authorize("app-a", "https://a.test/cb", ck, url.Values{"prompt": {"none"}}).Query().Get("code") == "" {
		t.Fatal("sso session lost")
	}
}

func refresh(e *env, client, secret string, tok map[string]any) int {
	rt, _ := tok["refresh_token"].(string)
	res, err := http.PostForm(e.ts.URL+idp.PathToken, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {client}, "client_secret": {secret}})
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestIdPAccountsSignOutCascades(t *testing.T) {
	e := newEnv(t)
	ck := e.signIn()
	a := e.exchange("app-a", "sa", "https://a.test/cb", e.authorize("app-a", "https://a.test/cb", ck, nil))
	e.exchange("app-b", "sb", "https://b.test/cb", e.authorize("app-b", "https://b.test/cb", ck, nil))
	sid := claims(t, a["id_token"].(string))["sid"].(string)
	form := url.Values{"csrf": {"x"}}
	req, _ := http.NewRequest("POST", e.ts.URL+"/auth/sign-out", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	req.AddCookie(&http.Cookie{Name: cookieCSRF, Value: "x"})
	res, _ := e.hc.Do(req)
	res.Body.Close()
	if e.s.IdP.Store.Session(sid) != nil {
		t.Fatal("sso session must be deleted")
	}
	if e.sink.n("app-a") != 1 || e.sink.n("app-b") != 1 {
		t.Fatalf("back-channel: a=%d b=%d", e.sink.n("app-a"), e.sink.n("app-b"))
	}
	sw := &core.Stalwart{BaseURL: e.ts.URL}
	c, err := sw.VerifyLogoutToken(context.Background(), e.sink.tokens["app-a"][0], "app-a")
	if err != nil || c["sid"] != sid || c["sub"] != "2" {
		t.Fatalf("logout token: %v %v", err, c)
	}
	if _, err := sw.VerifyLogoutToken(context.Background(), e.sink.tokens["app-a"][0], "app-b"); err == nil {
		t.Fatal("audience must be checked")
	}
	if refresh(e, "app-a", "sa", a) == 200 {
		t.Fatal("tokens must be revoked")
	}
	if cb := e.authorize("app-a", "https://a.test/cb", ck, url.Values{"prompt": {"none"}}); cb.Query().Get("error") != "login_required" {
		t.Fatalf("old cookie must not sign in: %s", cb)
	}
}

func TestIdPRevokeSingleApp(t *testing.T) {
	e := newEnv(t)
	ck := e.signIn()
	a := e.exchange("app-a", "sa", "https://a.test/cb", e.authorize("app-a", "https://a.test/cb", ck, nil))
	b := e.exchange("app-b", "sb", "https://b.test/cb", e.authorize("app-b", "https://b.test/cb", ck, nil))
	form := url.Values{"csrf": {"x"}, "client": {"app-b"}}
	req, _ := http.NewRequest("POST", e.ts.URL+"/account/apps/client/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	req.AddCookie(&http.Cookie{Name: cookieCSRF, Value: "x"})
	res, _ := e.hc.Do(req)
	res.Body.Close()
	if res.StatusCode != 200 || e.sink.n("app-b") != 1 || e.sink.n("app-a") != 0 {
		t.Fatalf("revoke: %d a=%d b=%d", res.StatusCode, e.sink.n("app-a"), e.sink.n("app-b"))
	}
	if refresh(e, "app-b", "sb", b) == 200 || refresh(e, "app-a", "sa", a) != 200 {
		t.Fatal("only app-b tokens must die")
	}
	if len(e.s.IdP.Store.GrantsOf("2")) != 1 {
		t.Fatal("grant must be removed")
	}
	// CSRF required
	req, _ = http.NewRequest("POST", e.ts.URL+"/account/apps/client/revoke", strings.NewReader("client=app-a"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	res, _ = e.hc.Do(req)
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("csrf: %d", res.StatusCode)
	}
}

func TestIdPStorePersists(t *testing.T) {
	e := newEnv(t)
	ck := e.signIn()
	a := e.exchange("app-a", "sa", "https://a.test/cb", e.authorize("app-a", "https://a.test/cb", ck, nil))
	sid := claims(t, a["id_token"].(string))["sid"].(string)
	st, err := idp.OpenStore(filepath.Join(e.dir, "idp.json"))
	if err != nil {
		t.Fatal(err)
	}
	ss := st.Session(sid)
	if ss == nil || ss.Clients["app-a"] == nil || len(st.GrantsOf("2")) != 1 || st.Profile("2") == nil {
		t.Fatalf("not persisted: %+v", ss)
	}
	ks, _ := idp.LoadKeySet([]string{filepath.Join(e.dir, "k.pem")}, false)
	if ks.Active().ID() != e.s.IdP.Keys.Active().ID() {
		t.Fatal("key must persist")
	}
}

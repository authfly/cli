package main

import (
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestServe is a local preview (YSELF_PREVIEW=127.0.0.1:port go test -run TestServe): a signed-in session with the
// cookie value printed, seeded links, for screenshots. Skipped otherwise.
func TestServe(t *testing.T) {
	addr := os.Getenv("YSELF_PREVIEW")
	if addr == "" {
		t.Skip()
	}
	a, c, s := testApp(t)
	do(a, "GET", "/me", c, nil)
	do(a, "POST", "/me/profile", c, url.Values{"csrf": {s.CSRF}, "handle": {"wmaster"}, "name": {"Web Master"}, "bio": {"Building YSELF: mail, single sign-on and a page for everyone at yself.link."}, "theme": {os.Getenv("YSELF_THEME")}, "buttons": {os.Getenv("YSELF_BUTTONS")}, "shape": {"pill"}})
	for _, l := range [][3]string{{"GitHub · authfly", "https://github.com/authfly", "code-xml"}, {"Write to me", "mailto:wmaster@yself.link", "mail"}, {"YSELF accounts", "https://accounts.yself.link", "shield-check"}} {
		do(a, "POST", "/me/links", c, url.Values{"csrf": {s.CSRF}, "title": {l[0]}, "url": {l[1]}, "icon": {l[2]}, "enabled": {"1"}})
	}
	t.Logf("cookie %s=%s", c.Name, c.Value)
	os.WriteFile(os.Getenv("YSELF_PREVIEW_COOKIE"), []byte(c.Value), 0o600)
	srv := &http.Server{Addr: addr, Handler: a.routes()}
	go srv.ListenAndServe()
	time.Sleep(90 * time.Second)
}

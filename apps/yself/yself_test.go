package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/authfly/cli/server/rp"
)

func testApp(t *testing.T) (*app, *http.Cookie, *rp.Session) {
	t.Setenv("YSELF_DATA", t.TempDir())
	a, err := newApp()
	if err != nil {
		t.Fatal(err)
	}
	a.c = rp.NewOffline("https://yself.link", a.st)
	s := &rp.Session{Sub: "2", Name: "Web Master", Email: "wmaster@yself.link"}
	return a, &http.Cookie{Name: rp.CookieSession, Value: a.c.AddSession(s)}, s
}

func do(a *app, method, path string, c *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "https://yself.link"+path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	return w
}

func TestFlow(t *testing.T) {
	a, c, s := testApp(t)
	if w := do(a, "GET", "/", nil, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `data-testid="hero"`) {
		t.Fatalf("landing %d", w.Code)
	}
	if w := do(a, "GET", "/me", nil, nil); w.Code != 302 || w.Header().Get("Location") != "/auth/login" {
		t.Fatalf("me anon %d", w.Code)
	}
	w := do(a, "GET", "/me", c, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "yself.link/wmaster") {
		t.Fatalf("editor %d %s", w.Code, w.Body.String()[:200])
	}
	// CSRF
	if w := do(a, "POST", "/me/links", c, url.Values{"title": {"x"}, "url": {"https://a.b"}}); w.Code != 403 {
		t.Fatalf("no csrf: %d", w.Code)
	}
	// bad URL schemes
	for _, u := range []string{"javascript:alert(1)", "http://x.y", "data:text/html,x", "//evil", "mailto:x"} {
		if w := do(a, "POST", "/me/links", c, url.Values{"csrf": {s.CSRF}, "title": {"x"}, "url": {u}}); w.Code != 422 {
			t.Fatalf("url %q accepted: %d", u, w.Code)
		}
	}
	if w := do(a, "POST", "/me/links", c, url.Values{"csrf": {s.CSRF}, "title": {`<script>alert(1)</script>`}, "url": {"https://example.com/?a=1&b=2"}, "enabled": {"1"}, "icon": {"globe"}}); w.Code != 303 {
		t.Fatalf("add link %d %s", w.Code, w.Body.String())
	}
	do(a, "POST", "/me/links", c, url.Values{"csrf": {s.CSRF}, "title": {"Mail"}, "url": {"mailto:wmaster@yself.link"}, "enabled": {"1"}})
	// handle rules
	for h, code := range map[string]int{"ab": 422, "admin": 422, "me": 422, "Bad_Name": 422, "-ab": 422, "a--b": 422, "web-master": 303} {
		if w := do(a, "POST", "/me/profile", c, url.Values{"csrf": {s.CSRF}, "handle": {h}, "name": {"Web <b>Master</b>"}, "bio": {"hi"}, "theme": {"dark"}}); w.Code != code {
			t.Fatalf("handle %q: %d want %d", h, w.Code, code)
		}
	}
	do(a, "POST", "/me/profile", c, url.Values{"csrf": {s.CSRF}, "handle": {"wmaster"}, "name": {"Web <b>Master</b>"}, "bio": {"hi"}, "theme": {"dark"}})
	w = do(a, "GET", "/wmaster", nil, nil)
	b := w.Body.String()
	if w.Code != 200 || strings.Contains(b, "<script>alert") || strings.Contains(b, "<b>Master") || !strings.Contains(b, `rel="noopener nofollow ugc"`) || !strings.Contains(b, `class="dark"`) || !strings.Contains(b, `og:title`) {
		t.Fatalf("public page %d: %s", w.Code, b)
	}
	if w := do(a, "GET", "/WMaster", nil, nil); w.Code != 301 {
		t.Fatalf("uppercase %d", w.Code)
	}
	if w := do(a, "GET", "/nobody-here", nil, nil); w.Code != 404 {
		t.Fatalf("unknown %d", w.Code)
	}
	if w := do(a, "GET", "/avatars/..%2f..%2fetc%2fpasswd", nil, nil); w.Code != 404 {
		t.Fatalf("traversal %d", w.Code)
	}
	// second user cannot take the handle or edit the first user's links
	s2 := &rp.Session{Sub: "3", Email: "wmaster2@yself.link"}
	c2 := &http.Cookie{Name: rp.CookieSession, Value: a.c.AddSession(s2)}
	if w := do(a, "POST", "/me/profile", c2, url.Values{"csrf": {s2.CSRF}, "handle": {"wmaster"}}); w.Code != 422 && w.Code != 409 {
		t.Fatalf("steal handle %d", w.Code)
	}
	if w := do(a, "POST", "/me/links/1/delete", c2, url.Values{"csrf": {s2.CSRF}}); w.Code != 404 {
		t.Fatalf("idor %d", w.Code)
	}
	// reorder
	if w := do(a, "POST", "/me/links/2/move", c, url.Values{"csrf": {s.CSRF}, "dir": {"up"}}); w.Code != 303 {
		t.Fatalf("move %d", w.Code)
	}
	ls, _ := a.st.Links("2", false)
	if len(ls) != 2 || ls[0].Title != "Mail" {
		t.Fatalf("order %+v", ls)
	}
}

func TestAvatar(t *testing.T) {
	a, c, s := testApp(t)
	do(a, "GET", "/me", c, nil)
	img := image.NewRGBA(image.Rect(0, 0, 640, 480))
	for x := 0; x < 640; x++ {
		img.Set(x, 10, color.RGBA{255, 0, 0, 255})
	}
	var pb bytes.Buffer
	png.Encode(&pb, img)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("csrf", s.CSRF)
	fw, _ := mw.CreateFormFile("avatar", "../../evil.png")
	fw.Write(pb.Bytes())
	mw.Close()
	r := httptest.NewRequest("POST", "https://yself.link/me/avatar", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(c)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("upload %d %s", w.Code, w.Body.String())
	}
	p, _ := a.st.BySub("2")
	if !avatarFile.MatchString(p.Avatar) {
		t.Fatalf("avatar name %q", p.Avatar)
	}
	data, err := os.ReadFile(a.avatars + "/" + p.Avatar)
	if err != nil {
		t.Fatal(err)
	}
	cfg, f, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || f != "jpeg" || cfg.Width != 256 || cfg.Height != 256 {
		t.Fatalf("avatar %v %s %+v", err, f, cfg)
	}
	if _, err := processAvatar(strings.NewReader("<svg onload=alert(1)>")); err == nil {
		t.Fatal("svg accepted")
	}
}

func TestCleanURL(t *testing.T) {
	ok := map[string]string{"https://example.com": "https://example.com", "HTTPS://example.com/a?b=c": "https://example.com/a?b=c", "mailto:a@b.co": "mailto:a@b.co"}
	for in, want := range ok {
		if got, err := cleanURL(in); err != nil || got != want {
			t.Errorf("%q -> %q %v", in, got, err)
		}
	}
	for _, in := range []string{"javascript:alert(1)", "https://user:pw@x.y", "https:///x", "mailto:", "mailto:a@b.co,c@d.co", "ftp://x", "https://x.y/\"><script>"} {
		if _, err := cleanURL(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestOrientation(t *testing.T) {
	// 4x2 image, orientation 6 (rotate 90° CW) -> 2x4, top-left pixel comes from bottom-left of the source
	src := image.NewRGBA(image.Rect(0, 0, 4, 2))
	src.Set(0, 1, color.RGBA{255, 0, 0, 255})
	o := orient(src, 6)
	if o.Bounds().Dx() != 2 || o.Bounds().Dy() != 4 {
		t.Fatalf("bounds %v", o.Bounds())
	}
	if r, _, _, _ := o.At(0, 0).RGBA(); r>>8 != 255 {
		t.Fatalf("pixel not rotated")
	}
	// minimal JPEG prefix with an EXIF APP1 (big-endian TIFF, one IFD entry Orientation=6)
	tiff := []byte{'M', 'M', 0, 42, 0, 0, 0, 8, 0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0}
	app1 := append([]byte("Exif\x00\x00"), tiff...)
	j := append([]byte{0xFF, 0xD8, 0xFF, 0xE1, byte((len(app1) + 2) >> 8), byte(len(app1) + 2)}, app1...)
	j = append(j, 0xFF, 0xD9)
	if got := jpegOrientation(j); got != 6 {
		t.Fatalf("orientation %d", got)
	}
	if jpegOrientation([]byte("garbage")) != 1 {
		t.Fatal("garbage")
	}
}

func TestSessionPersist(t *testing.T) {
	a, c, _ := testApp(t)
	ss, err := a.st.LoadSessions()
	if err != nil || len(ss) != 1 {
		t.Fatalf("persisted %d %v", len(ss), err)
	}
	for k := range ss {
		if k == c.Value {
			t.Fatal("cookie value stored as key")
		}
	}
	b := rp.NewOffline("https://yself.link", nil)
	_ = b
}

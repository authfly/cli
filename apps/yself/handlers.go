package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/authfly/cli/server/rp"
	"github.com/authfly/cli/server/rpui"
)

const (
	cspApp     = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'"
	cspPublic  = "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
	flashName  = "__Host-yself_flash"
	maxFormMem = 64 << 10
)

var flashKeys = map[string]bool{"saved": true, "avatar": true, "avatarRemoved": true, "linkAdded": true, "linkSaved": true, "linkDeleted": true, "moved": true}

func tr(r *http.Request) (string, T) {
	l := rp.Lang(r)
	return l, dict[l]
}

// setLang remembers ?lang= for later pages (plain preference cookie).
func setLang(w http.ResponseWriter, r *http.Request) {
	if l := r.URL.Query().Get("lang"); l == "en" || l == "ru" {
		http.SetCookie(w, &http.Cookie{Name: "lang", Value: l, Path: "/", MaxAge: 365 * 24 * 3600, Secure: true, SameSite: http.SameSiteLaxMode, HttpOnly: true})
	}
}

func (a *app) page(w http.ResponseWriter, r *http.Request, status int, csp string, c templ.Component) {
	rpui.Secure(w, csp)
	setLang(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		log.Printf("render: %v", err)
	}
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	l, t := tr(r)
	s := a.c.Current(r)
	var p *Profile
	if s != nil {
		p, _ = a.st.BySub(s.Sub)
	}
	a.page(w, r, 200, cspApp, Landing(a.chrome(r, l, t, s, p, "/"), t, p, a.accounts))
}

func (a *app) loginFailed(w http.ResponseWriter, r *http.Request, msg string) {
	l, t := tr(r)
	a.page(w, r, http.StatusBadRequest, cspApp, LoginFailed(a.chrome(r, l, t, nil, nil, "/"), t, msg))
}

func (a *app) notFound(w http.ResponseWriter, r *http.Request) {
	l, t := tr(r)
	a.page(w, r, http.StatusNotFound, cspApp, NotFound(a.chrome(r, l, t, a.c.Current(r), nil, r.URL.Path), t))
}

// Chrome is what the app shell needs: language, path, the signed-in user and their handle.
type Chrome struct {
	Lang, Path, Title string
	T                 T
	Signed            bool
	Handle            string
	Meta              rpui.Meta
}

func (a *app) chrome(r *http.Request, l string, t T, s *rp.Session, p *Profile, path string) Chrome {
	c := Chrome{Lang: l, Path: path, T: t, Signed: s != nil, Meta: rpui.Meta{Title: "YSELF — yself.link", Lang: l, Description: t["hero.lead"], URL: a.public + "/"}}
	if p != nil {
		c.Handle = p.Handle
	}
	return c
}

// --- public page ---

var avatarFile = regexp.MustCompile(`^[a-f0-9]{32}\.jpg$`)

func (a *app) publicPage(w http.ResponseWriter, r *http.Request) {
	h := r.PathValue("handle")
	if lh := strings.ToLower(h); lh != h && handleRe.MatchString(lh) {
		http.Redirect(w, r, "/"+lh, http.StatusMovedPermanently)
		return
	}
	if !handleRe.MatchString(h) {
		a.notFound(w, r)
		return
	}
	p, err := a.st.ByHandle(h)
	if err != nil || p == nil {
		a.notFound(w, r)
		return
	}
	links, _ := a.st.Links(p.Sub, true)
	l, t := tr(r)
	m := rpui.Meta{Title: nonEmpty(p.Name, p.Handle) + " · yself.link/" + p.Handle, Lang: l, Description: nonEmpty(p.Bio, t["hero.title"]), URL: a.public + "/" + p.Handle, NoThemeScript: true}
	if p.Theme == "dark" {
		m.HTMLClass = "dark"
	}
	m.BodyClass = surfaceCls(p.Theme)
	if p.Avatar != "" {
		m.Image = a.public + "/avatars/" + p.Avatar
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	a.page(w, r, 200, cspPublic, PublicPage(m, t, p, links))
}

func (a *app) avatar(w http.ResponseWriter, r *http.Request) {
	f := r.PathValue("file")
	if !avatarFile.MatchString(f) { // no path separators, no dots beyond the extension: no traversal
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	http.ServeFile(w, r, filepath.Join(a.avatars, f))
}

// --- editor ---

// EditorVM is the editor page state.
type EditorVM struct {
	C                     Chrome
	P                     *Profile
	Links                 []Link
	CSRF, Flash, Err      string
	ErrField              string // handle | link | avatar | form
	Public                string
	FormHandle, FormName  string
	FormBio               string
	NewTitle, NewURL      string
	NewIcon               string
	BadLink               int64 // id of a link whose edit failed (0 = the new-link form)
}

// ensure returns the signed-in user's profile, creating it on first visit (handle = mail local part when free).
func (a *app) ensure(s *rp.Session) (*Profile, error) {
	p, err := a.st.BySub(s.Sub)
	if err != nil || p != nil {
		return p, err
	}
	local := localPart(s.Email, s.PreferredUsername)
	cands := []string{defaultHandle(local)}
	if s.Sub != "" {
		cands = append(cands, defaultHandle(local)+"-"+defaultHandle(s.Sub), "user-"+defaultHandle(s.Sub))
	}
	for _, h := range cands {
		if checkHandle(h, local) != nil {
			continue
		}
		np := &Profile{Sub: s.Sub, Handle: h, Name: clip(s.Name, 60, false), Theme: "light", Buttons: "solid", Shape: "rounded"}
		if err := a.st.Create(np); err == nil {
			return np, nil
		} else if !errors.Is(err, ErrTaken) {
			return nil, err
		}
	}
	return nil, errors.New("no free handle")
}

func (a *app) editor(w http.ResponseWriter, r *http.Request) {
	s := a.c.Current(r)
	if s == nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"sub": s.Sub, "name": s.Name, "email": s.Email})
		return
	}
	vm, ok := a.vm(w, r, s)
	if !ok {
		return
	}
	if c, err := r.Cookie(flashName); err == nil {
		if flashKeys[c.Value] {
			vm.Flash = vm.C.T["flash."+c.Value]
		}
		http.SetCookie(w, &http.Cookie{Name: flashName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
	a.page(w, r, 200, cspApp, Editor(vm))
}

func (a *app) vm(w http.ResponseWriter, r *http.Request, s *rp.Session) (*EditorVM, bool) {
	p, err := a.ensure(s)
	if err != nil {
		log.Printf("profile: %v", err)
		http.Error(w, "profile unavailable", http.StatusInternalServerError)
		return nil, false
	}
	links, _ := a.st.Links(s.Sub, false)
	l, t := tr(r)
	c := a.chrome(r, l, t, s, p, "/me")
	c.Meta.Title = t["ed.title"] + " — YSELF"
	c.Meta.Robots = "noindex"
	return &EditorVM{C: c, P: p, Links: links, CSRF: s.CSRF, Public: a.public + "/" + p.Handle, FormHandle: p.Handle, FormName: p.Name, FormBio: p.Bio}, true
}

// post gates every editor POST: signed in, same origin + CSRF token, rate limit.
func (a *app) post(w http.ResponseWriter, r *http.Request, lim *limiter) *rp.Session {
	s := a.c.Current(r)
	if s == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return nil
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormMem)
		r.ParseForm()
	}
	if !a.c.CheckPost(r, s) {
		a.fail(w, r, s, http.StatusForbidden, "csrf", "form")
		return nil
	}
	if !lim.allow(clientIP(r, a.trusted)) || !lim.allow("sub:"+s.Sub) {
		a.fail(w, r, s, http.StatusTooManyRequests, "rate", "form")
		return nil
	}
	return s
}

func (a *app) fail(w http.ResponseWriter, r *http.Request, s *rp.Session, status int, key, field string, tweak ...func(*EditorVM)) {
	vm, ok := a.vm(w, r, s)
	if !ok {
		return
	}
	vm.Err, vm.ErrField = vm.C.T["err."+key], field
	for _, f := range tweak {
		f(vm)
	}
	a.page(w, r, status, cspApp, Editor(vm))
}

func (a *app) done(w http.ResponseWriter, r *http.Request, flash, anchor string) {
	http.SetCookie(w, &http.Cookie{Name: flashName, Value: flash, Path: "/", MaxAge: 60, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/me"+anchor, http.StatusSeeOther)
}

func (a *app) saveProfile(w http.ResponseWriter, r *http.Request) {
	s := a.post(w, r, a.posts)
	if s == nil {
		return
	}
	p, err := a.ensure(s)
	if err != nil {
		a.fail(w, r, s, 500, "generic", "form")
		return
	}
	h := strings.ToLower(strings.TrimSpace(r.FormValue("handle")))
	name, bio := clip(r.FormValue("name"), 60, false), clip(r.FormValue("bio"), 160, true)
	keep := func(vm *EditorVM) { vm.FormHandle, vm.FormName, vm.FormBio = h, name, bio }
	if h != p.Handle {
		if err := checkHandle(h, localPart(s.Email, s.PreferredUsername)); err != nil {
			a.fail(w, r, s, http.StatusUnprocessableEntity, err.Error(), "handle", keep)
			return
		}
	}
	np := *p
	np.Handle, np.Name, np.Bio = h, name, bio
	np.Theme, np.Buttons, np.Shape = oneOf(r.FormValue("theme"), themes), oneOf(r.FormValue("buttons"), buttonStyles), oneOf(r.FormValue("shape"), shapes)
	if err := a.st.Save(&np); errors.Is(err, ErrTaken) {
		a.fail(w, r, s, http.StatusConflict, "handle.taken", "handle", keep)
		return
	} else if err != nil {
		log.Printf("save: %v", err)
		a.fail(w, r, s, 500, "generic", "form")
		return
	}
	a.done(w, r, "saved", "#profile")
}

func randName() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b) + ".jpg"
}

func (a *app) uploadAvatar(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarBytes+64<<10)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		if s := a.c.Current(r); s != nil {
			a.fail(w, r, s, http.StatusRequestEntityTooLarge, "avatar.big", "avatar")
			return
		}
	}
	s := a.post(w, r, a.uploads)
	if s == nil {
		return
	}
	p, err := a.ensure(s)
	if err != nil {
		a.fail(w, r, s, 500, "generic", "form")
		return
	}
	f, _, err := r.FormFile("avatar")
	if err != nil {
		a.fail(w, r, s, http.StatusUnprocessableEntity, "avatar.format", "avatar")
		return
	}
	defer f.Close()
	img, err := processAvatar(f)
	if err != nil {
		a.fail(w, r, s, http.StatusUnprocessableEntity, err.Error(), "avatar")
		return
	}
	name := randName()
	tmp := filepath.Join(a.avatars, "."+name+".tmp")
	if err := os.WriteFile(tmp, img, 0o640); err != nil || os.Rename(tmp, filepath.Join(a.avatars, name)) != nil {
		os.Remove(tmp)
		a.fail(w, r, s, 500, "generic", "avatar")
		return
	}
	if err := a.st.SetAvatar(s.Sub, name); err != nil {
		a.fail(w, r, s, 500, "generic", "avatar")
		return
	}
	if p.Avatar != "" && avatarFile.MatchString(p.Avatar) {
		os.Remove(filepath.Join(a.avatars, p.Avatar))
	}
	a.done(w, r, "avatar", "#avatar")
}

func (a *app) deleteAvatar(w http.ResponseWriter, r *http.Request) {
	s := a.post(w, r, a.posts)
	if s == nil {
		return
	}
	p, err := a.ensure(s)
	if err == nil && p.Avatar != "" {
		a.st.SetAvatar(s.Sub, "")
		if avatarFile.MatchString(p.Avatar) {
			os.Remove(filepath.Join(a.avatars, p.Avatar))
		}
	}
	a.done(w, r, "avatarRemoved", "#avatar")
}

func linkFromForm(r *http.Request) (Link, string) {
	l := Link{Title: clip(r.FormValue("title"), 60, false), Icon: r.FormValue("icon"), Enabled: r.FormValue("enabled") != ""}
	if !validIcon(l.Icon) {
		l.Icon = ""
	}
	if l.Title == "" {
		return l, "link.title"
	}
	u, err := cleanURL(r.FormValue("url"))
	if err != nil {
		return l, "link.url"
	}
	l.URL = u
	return l, ""
}

func (a *app) addLink(w http.ResponseWriter, r *http.Request) {
	s := a.post(w, r, a.posts)
	if s == nil {
		return
	}
	if _, err := a.ensure(s); err != nil {
		a.fail(w, r, s, 500, "generic", "form")
		return
	}
	l, bad := linkFromForm(r)
	if n, _ := a.st.CountLinks(s.Sub); bad == "" && n >= maxLinks {
		bad = "link.max"
	}
	if bad != "" {
		a.fail(w, r, s, http.StatusUnprocessableEntity, bad, "link", func(vm *EditorVM) { vm.NewTitle, vm.NewURL, vm.NewIcon = l.Title, r.FormValue("url"), l.Icon })
		return
	}
	if err := a.st.AddLink(s.Sub, l); err != nil {
		a.fail(w, r, s, 500, "generic", "link")
		return
	}
	a.done(w, r, "linkAdded", "#links")
}

func linkID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func (a *app) updateLink(w http.ResponseWriter, r *http.Request) {
	s := a.post(w, r, a.posts)
	if s == nil {
		return
	}
	l, bad := linkFromForm(r)
	l.ID = linkID(r)
	if bad != "" {
		a.fail(w, r, s, http.StatusUnprocessableEntity, bad, "link", func(vm *EditorVM) { vm.BadLink = l.ID })
		return
	}
	if ok, err := a.st.UpdateLink(s.Sub, l); err != nil || !ok {
		a.fail(w, r, s, http.StatusNotFound, "generic", "link")
		return
	}
	a.done(w, r, "linkSaved", "#links")
}

func (a *app) moveLink(w http.ResponseWriter, r *http.Request) {
	s := a.post(w, r, a.posts)
	if s == nil {
		return
	}
	dir := 1
	if r.FormValue("dir") == "up" {
		dir = -1
	}
	if err := a.st.MoveLink(s.Sub, linkID(r), dir); err != nil {
		a.fail(w, r, s, 500, "generic", "link")
		return
	}
	a.done(w, r, "moved", "#links")
}

func (a *app) deleteLink(w http.ResponseWriter, r *http.Request) {
	s := a.post(w, r, a.posts)
	if s == nil {
		return
	}
	if ok, err := a.st.DeleteLink(s.Sub, linkID(r)); err != nil || !ok {
		a.fail(w, r, s, http.StatusNotFound, "generic", "link")
		return
	}
	a.done(w, r, "linkDeleted", "#links")
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

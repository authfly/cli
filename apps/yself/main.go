// Command yself is the YSELF app on yself.link: the welcome page, the public link pages (yself.link/<handle>) and the
// page editor (/me) for users signed in through accounts.yself.link (OIDC relying party, server/rp). Pages are SSR
// templ on UI8Kit 3 primitives, no JavaScript needed; data in SQLite, avatars as files, both under YSELF_DATA.
//
//	YSELF_DATA=/var/lib/yself RP_ISSUER=https://accounts.yself.link RP_PUBLIC_URL=https://yself.link RP_CLIENT_ID=yself-link \
//	RP_CLIENT_SECRET_FILE=/etc/rp/client-secret RP_ADDR=10.10.10.16:8080 YSELF_TRUSTED_PROXY=10.10.10.10 yself
//	yself seed -sub 2 -handle wmaster -name "Web Master" -bio "..." -link "Title|https://…|icon" …
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/authfly/cli/server/rp"
	"github.com/authfly/cli/server/rpui"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type app struct {
	c        *rp.Client
	st       *Store
	data     string
	avatars  string
	public   string
	accounts string
	trusted  string
	posts    *limiter
	uploads  *limiter
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "seed" {
		seed(os.Args[2:])
		return
	}
	a, err := newApp()
	if err != nil {
		log.Fatal(err)
	}
	c, err := rp.New(rp.Config{Issuer: a.accounts, PublicURL: a.public, ClientID: env("RP_CLIENT_ID", "yself-link"),
		SecretFile: os.Getenv("RP_CLIENT_SECRET_FILE"), Scope: env("RP_SCOPE", "openid profile email"), Fail: a.loginFailed, Store: a.st})
	if err != nil {
		log.Fatalf("rp: %v", err)
	}
	a.c = c
	addr := env("RP_ADDR", ":8080")
	log.Printf("yself: %s issuer %s data %s on %s", a.public, a.accounts, a.data, addr)
	srv := &http.Server{Addr: addr, Handler: a.routes(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func newApp() (*app, error) {
	a := &app{data: env("YSELF_DATA", "./data"), public: strings.TrimRight(env("RP_PUBLIC_URL", "https://yself.link"), "/"),
		accounts: strings.TrimRight(env("RP_ISSUER", "https://accounts.yself.link"), "/"), trusted: os.Getenv("YSELF_TRUSTED_PROXY"),
		posts: newLimiter(60, time.Minute), uploads: newLimiter(10, 10*time.Minute)}
	a.avatars = filepath.Join(a.data, "avatars")
	if err := os.MkdirAll(a.avatars, 0o750); err != nil {
		return nil, err
	}
	loadReserved(os.Getenv("AUTHFLY_RESERVED_NAMES_FILE"))
	st, err := OpenStore(filepath.Join(a.data, "yself.db"))
	if err != nil {
		return nil, err
	}
	a.st = st
	return a, nil
}

func (a *app) routes() http.Handler {
	m := http.NewServeMux()
	if a.c != nil {
		a.c.Mount(m)
	}
	m.Handle("GET /assets/", rpui.Assets())
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	m.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "User-agent: *\nDisallow: /me\nDisallow: /auth/\n")
	})
	m.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	m.HandleFunc("GET /{$}", a.home)
	m.HandleFunc("GET /me", a.editor)
	m.HandleFunc("GET /edit", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/me", http.StatusSeeOther) })
	m.HandleFunc("POST /me/profile", a.saveProfile)
	m.HandleFunc("POST /me/avatar", a.uploadAvatar)
	m.HandleFunc("POST /me/avatar/delete", a.deleteAvatar)
	m.HandleFunc("POST /me/links", a.addLink)
	m.HandleFunc("POST /me/links/{id}", a.updateLink)
	m.HandleFunc("POST /me/links/{id}/move", a.moveLink)
	m.HandleFunc("POST /me/links/{id}/delete", a.deleteLink)
	m.HandleFunc("GET /avatars/{file}", a.avatar)
	m.HandleFunc("GET /{handle}", a.publicPage)
	m.HandleFunc("/", a.notFound)
	return m
}

// seed creates or updates a profile from the command line (used once to seed yself.link/wmaster).
func seed(args []string) {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	sub := fs.String("sub", "", "OIDC sub (Stalwart account id)")
	handle := fs.String("handle", "", "handle")
	name := fs.String("name", "", "display name")
	bio := fs.String("bio", "", "bio")
	theme := fs.String("theme", "light", "theme")
	buttons := fs.String("buttons", "solid", "buttons")
	shape := fs.String("shape", "rounded", "shape")
	var links multi
	fs.Var(&links, "link", "Title|URL|icon (repeatable; replaces nothing, only added when the profile has no links)")
	fs.Parse(args)
	a, err := newApp()
	if err != nil {
		log.Fatal(err)
	}
	if *sub == "" || checkHandle(*handle, *handle) != nil {
		log.Fatal("seed: -sub and a valid -handle are required")
	}
	p, _ := a.st.BySub(*sub)
	np := &Profile{Sub: *sub, Handle: *handle, Name: clip(*name, 60, false), Bio: clip(*bio, 160, true), Theme: oneOf(*theme, themes), Buttons: oneOf(*buttons, buttonStyles), Shape: oneOf(*shape, shapes)}
	if p == nil {
		err = a.st.Create(np)
	} else {
		np.Avatar = p.Avatar
		err = a.st.Save(np)
	}
	if err != nil {
		log.Fatal(err)
	}
	if n, _ := a.st.CountLinks(*sub); n == 0 {
		for _, l := range links {
			parts := strings.SplitN(l, "|", 3)
			if len(parts) < 2 {
				continue
			}
			u, err := cleanURL(parts[1])
			if err != nil {
				log.Fatalf("seed link %q: %v", parts[1], err)
			}
			icon := ""
			if len(parts) == 3 && validIcon(parts[2]) {
				icon = parts[2]
			}
			a.st.AddLink(*sub, Link{Title: clip(parts[0], 60, false), URL: u, Icon: icon, Enabled: true})
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]string{"seeded": np.Handle})
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

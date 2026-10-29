// Package rpui is the shared templ chrome (document, header, language and theme switch) and static assets of the
// Authfly relying-party apps.
package rpui

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed assets
var assets embed.FS

// Version busts asset caches; bump with the CSS.
var Version = "1"

func upper(s string) string { return strings.ToUpper(s) }

// Assets serves /assets/* (embedded app.css, theme.js) with a long cache (URLs carry ?v=).
func Assets() http.Handler {
	fs := http.FileServerFS(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fs.ServeHTTP(w, r)
	})
}

// Secure sets the common security headers. csp is the page's Content-Security-Policy.
func Secure(w http.ResponseWriter, csp string) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func bodyCls(c string) string {
	if c == "" {
		return "bg-background text-foreground"
	}
	return c
}

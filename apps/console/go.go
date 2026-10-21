package main

import (
	"net/http"
	"strings"
)

// goTo serves the mobile navigation select (GET /go?to=/path).
func (c *Console) goTo(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	if !strings.HasPrefix(to, "/") || strings.HasPrefix(to, "//") {
		to = "/"
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

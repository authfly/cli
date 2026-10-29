package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authfly/cli/server/core"
)

// End-session redirects must reach the browser, not be followed by the proxy.
func TestForwardRelaysRedirect(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://rp.example/", http.StatusFound)
	}))
	defer up.Close()
	s := &Server{Svc: &core.Service{SW: &core.Stalwart{BaseURL: up.URL}}}
	rec := httptest.NewRecorder()
	s.forward(rec, httptest.NewRequest("GET", "/auth/logout?post_logout_redirect_uri=https%3A%2F%2Frp.example%2F", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://rp.example/" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

package web

// OIDC proxy: Stalwart's HTTP listener stays on the internal network; Authkit forwards only the OpenID Connect
// endpoints relying parties need. Everything else of Stalwart's HTTP surface (/jmap management and mail, /api/*,
// /admin, /account, /login, /auth/device, /auth/register, /auth/introspect, DAV, health) is not reachable through Authkit.
//
// Stalwart's STALWART_PUBLIC_URL is set to Authkit's public URL, so the issuer and the endpoint URLs in the discovery
// document already point at Authkit; the proxy rewrites authorization_endpoint to Authkit's /oauth/authorize (the
// hosted sign-in) and removes the endpoints it does not forward.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// OIDCProxyPaths are forwarded to Stalwart (method and path).
var OIDCProxyPaths = []string{
	"GET /.well-known/openid-configuration",
	"GET /.well-known/oauth-authorization-server",
	"GET /auth/jwks.json",
	"POST /auth/token",
	"GET /auth/userinfo",
	"POST /auth/userinfo",
}

var proxyClient = &http.Client{Timeout: 15 * time.Second}

func (s *Server) oidcProxy(m *http.ServeMux) {
	for _, p := range OIDCProxyPaths {
		m.HandleFunc(p, s.forward)
	}
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimRight(s.Svc.SW.BaseURL, "/") + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	for _, h := range []string{"Content-Type", "Authorization", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	res, err := proxyClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", 502)
		return
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if strings.HasPrefix(r.URL.Path, "/.well-known/") && res.StatusCode == 200 {
		var d map[string]any
		if json.Unmarshal(body, &d) == nil {
			d["authorization_endpoint"] = s.Svc.Cfg.PublicURL + "/oauth/authorize"
			for _, k := range []string{"device_authorization_endpoint", "registration_endpoint", "introspection_endpoint"} {
				delete(d, k)
			}
			body, _ = json.Marshal(d)
		}
	}
	for _, h := range []string{"Content-Type", "Cache-Control", "Pragma", "WWW-Authenticate"} {
		if v := res.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(body)
}

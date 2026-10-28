package web

// OIDC proxy: Stalwart's HTTP listener stays on the internal network; Authfly forwards only the OpenID Connect
// endpoints relying parties need. Everything else of Stalwart's HTTP surface (/jmap management and mail, /api/*,
// /admin, /account, /login, /auth/device, /auth/register, /auth/introspect, DAV, health) is not reachable through Authfly.
//
// Stalwart's STALWART_PUBLIC_URL is set to Authfly's public URL, so the issuer and the endpoint URLs in the discovery
// document already point at Authfly; the proxy rewrites authorization_endpoint to Authfly's /oauth/authorize (the
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
	"POST /auth/revoke",
	"GET /auth/logout",
	"POST /auth/logout",
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
			rewriteDiscovery(d, s.Svc.Cfg.PublicURL)
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

// rewriteDiscovery points authorization at Authfly's hosted sign-in and strips surfaces Authfly does not proxy
// (device flow, dynamic registration, introspection, CIMD).
func rewriteDiscovery(d map[string]any, publicURL string) {
	d["authorization_endpoint"] = publicURL + "/oauth/authorize"
	d["revocation_endpoint"] = publicURL + "/auth/revoke"
	d["end_session_endpoint"] = publicURL + "/auth/logout"
	for _, k := range []string{
		"device_authorization_endpoint", "registration_endpoint", "introspection_endpoint",
		"client_id_metadata_document_supported",
	} {
		delete(d, k)
	}
	if g, ok := d["grant_types_supported"]; ok {
		d["grant_types_supported"] = filterGrants(g)
	}
}

func filterGrants(v any) []any {
	var in []any
	switch t := v.(type) {
	case []any:
		in = t
	case []string:
		for _, s := range t {
			in = append(in, s)
		}
	default:
		return nil
	}
	out := make([]any, 0, len(in))
	for _, x := range in {
		s, _ := x.(string)
		if s == "urn:ietf:params:oauth:grant-type:device_code" || s == "device_code" {
			continue
		}
		out = append(out, x)
	}
	return out
}

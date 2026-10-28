// Package core is the shared Authfly logic: the Stalwart client (OIDC authorization code + PKCE, JMAP management of
// accounts), SMTP mail through Stalwart, one-time tokens and sessions. Every runtime family talks to it, directly (Go)
// or over the Authfly HTTP API (TypeScript, PHP, Python adapters).
package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Stalwart talks to one Stalwart server (v1.0). Endpoints verified against the v1.0.0 source
// (crates/http/src/auth/oauth/auth.rs, crates/registry/src/schema/structs.rs):
//
//	POST /jmap                 JMAP, capability urn:stalwart:jmap: x:Domain/*, x:Account/*, x:AccountPassword,
//	                           x:AppPassword, x:OAuthGrant, x:OAuthClient, nested x:EmailAlias
//	POST /api/auth             {type:"authCode", accountName, accountSecret, mfaToken?, query:"client_id=…&redirect_uri=…&code_challenge=…&code_challenge_method=S256…", consent:true}
//	                           -> {type:"authenticated", location} | mfaRequired | failure | expired | invalid | redirect
//	POST /auth/token           authorization_code + code_verifier (PKCE S256 required; no password grant)
//	GET  /auth/userinfo, /auth/jwks.json, POST /auth/revoke, GET|POST /auth/logout
//	GET  /.well-known/openid-configuration
type Stalwart struct {
	BaseURL    string // internal URL Authfly uses to reach Stalwart, e.g. http://stalwart:8080
	AdminUser  string // management credential (dev: STALWART_RECOVERY_ADMIN; production: an API key as AdminToken)
	AdminPass  string
	AdminToken string
	HTTP       *http.Client

	mu         sync.Mutex
	disco      *Discovery
	jwks       map[string]*ecdsa.PublicKey
	domainID   map[string]string
	userDomain string
	orgDomain  string
}

type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrMFARequired = errors.New("multi-factor authentication required")
var ErrAccountExists = errors.New("account exists")
var ErrNotFound = errors.New("not found")
var ErrAuthRedirect = errors.New("authorization redirected with an error")

func (s *Stalwart) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second} // ReloadSettings can take a while (it re-validates every setting)
}

func (s *Stalwart) do(ctx context.Context, method, path string, body io.Reader, ctype string, admin bool) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.BaseURL, "/")+path, body)
	if err != nil {
		return nil, 0, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if admin {
		if s.AdminToken != "" {
			req.Header.Set("Authorization", "Bearer "+s.AdminToken)
		} else {
			req.SetBasicAuth(s.AdminUser, s.AdminPass)
		}
	}
	res, err := s.client().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return b, res.StatusCode, err
}

// JMAP runs management method calls with the admin credential and returns the responses in order.
func (s *Stalwart) JMAP(ctx context.Context, calls ...[]any) ([][]json.RawMessage, error) {
	return s.JMAPUsing(ctx, []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"}, calls...)
}

// JMAPUsing posts method calls with the given capabilities; a method error fails the call.
func (s *Stalwart) JMAPUsing(ctx context.Context, using []string, calls ...[]any) ([][]json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"using": using, "methodCalls": calls})
	if os.Getenv("AUTHFLY_DEBUG_JMAP") != "" { // method names only, never arguments (they can carry passwords)
		for _, c := range calls {
			log.Printf("jmap: %v", c[0])
		}
	}
	b, code, err := s.do(ctx, "POST", "/jmap", bytes.NewReader(body), "application/json", true)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("stalwart jmap: http %d: %s", code, b)
	}
	var out struct {
		MethodResponses [][]json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	for _, r := range out.MethodResponses {
		var name string
		_ = json.Unmarshal(r[0], &name)
		if name == "error" {
			return nil, fmt.Errorf("stalwart jmap error: %s", r[1])
		}
	}
	return out.MethodResponses, nil
}

// EnsureDomain returns the id of a domain, creating it when missing (x:Domain/query, x:Domain/set).
func (s *Stalwart) EnsureDomain(ctx context.Context, name string) (string, error) {
	s.mu.Lock()
	if id, ok := s.domainID[name]; ok {
		s.mu.Unlock()
		return id, nil
	}
	s.mu.Unlock()
	r, err := s.JMAP(ctx, []any{"x:Domain/query", map[string]any{"filter": map[string]any{}}, "q"},
		[]any{"x:Domain/get", map[string]any{"#ids": map[string]any{"resultOf": "q", "name": "x:Domain/query", "path": "/ids"}, "properties": []string{"name"}}, "g"})
	if err != nil {
		return "", err
	}
	var got struct {
		List []struct{ ID, Name string } `json:"list"`
	}
	_ = json.Unmarshal(r[1][1], &got)
	id := ""
	for _, d := range got.List {
		if strings.EqualFold(d.Name, name) {
			id = d.ID
		}
	}
	if id == "" {
		r, err = s.JMAP(ctx, []any{"x:Domain/set", map[string]any{"create": map[string]any{"d": map[string]any{"name": name}}}, "c"})
		if err != nil {
			return "", err
		}
		var set struct {
			Created    map[string]struct{ ID string } `json:"created"`
			NotCreated map[string]any                 `json:"notCreated"`
		}
		_ = json.Unmarshal(r[0][1], &set)
		if set.Created["d"].ID == "" {
			return "", fmt.Errorf("stalwart: domain not created: %v", set.NotCreated)
		}
		id = set.Created["d"].ID
	}
	s.mu.Lock()
	if s.domainID == nil {
		s.domainID = map[string]string{}
	}
	s.domainID[name] = id
	s.mu.Unlock()
	return id, nil
}

// Account is the part of a Stalwart Account (variant User) Authfly reads.
type Account struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	EmailAddress string `json:"emailAddress"`
	Description  string `json:"description"`
	DomainID     string `json:"domainId"`
}

// FindAccount looks an account up by local part in a domain (x:Account/query filter name, then exact match).
func (s *Stalwart) FindAccount(ctx context.Context, domain, name string) (*Account, error) {
	did, err := s.EnsureDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	r, err := s.JMAP(ctx, []any{"x:Account/query", map[string]any{"filter": map[string]any{"name": name, "domainId": did}}, "q"},
		[]any{"x:Account/get", map[string]any{"#ids": map[string]any{"resultOf": "q", "name": "x:Account/query", "path": "/ids"}, "properties": []string{"name", "emailAddress", "description", "domainId"}}, "g"})
	if err != nil {
		return nil, err
	}
	var got struct {
		List []Account `json:"list"`
	}
	_ = json.Unmarshal(r[1][1], &got)
	for _, a := range got.List {
		if strings.EqualFold(a.Name, name) && a.DomainID == did {
			a := a
			return &a, nil
		}
	}
	return nil, ErrNotFound
}

// CreateAccount creates a User account with a password credential (x:Account/set). Prefer CreateAccountKind
// when dual-domain namespace mirroring is on.
func (s *Stalwart) CreateAccount(ctx context.Context, domain, name, password, fullName string) (*Account, error) {
	return s.CreateAccountKind(ctx, domain, name, password, fullName, KindUser)
}

// Discovery reads /.well-known/openid-configuration (cached).
func (s *Stalwart) Discovery(ctx context.Context) (*Discovery, error) {
	s.mu.Lock()
	d := s.disco
	s.mu.Unlock()
	if d != nil {
		return d, nil
	}
	b, code, err := s.do(ctx, "GET", "/.well-known/openid-configuration", nil, "", false)
	if err != nil || code != 200 {
		return nil, fmt.Errorf("stalwart discovery: %v %d", err, code)
	}
	d = &Discovery{}
	if err := json.Unmarshal(b, d); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.disco = d
	s.mu.Unlock()
	return d, nil
}

// AuthCodeRequest is the body of POST /api/auth (type authCode) for Stalwart 1.0.
// Query is the original OAuth authorize query string (client_id, redirect_uri, code_challenge,
// code_challenge_method=S256, scope, nonce, state, response_type). Consent must be true for
// registered clients (requires_consent); otherwise Stalwart returns type redirect with access_denied.
type AuthCodeRequest struct {
	AccountName, AccountSecret, MFAToken, Query string
	Consent                                     bool
	// Legacy fields: used only to build Query when Query is empty (v0.16 callers / tests).
	ClientID, RedirectURI, Scope, Nonce, State, CodeChallenge string
}

// AuthResult is a successful /api/auth response: the redirect Location (contains code=) and the code itself.
type AuthResult struct {
	Code     string
	Location string
}

// Authorize checks a password with Stalwart and returns an OAuth authorization code bound to the
// client, redirect URI and PKCE S256 challenge. PKCE S256 is required; there is no password grant.
func (s *Stalwart) Authorize(ctx context.Context, a AuthCodeRequest) (string, error) {
	res, err := s.AuthorizeEx(ctx, a)
	if err != nil {
		return "", err
	}
	return res.Code, nil
}

// AuthorizeEx is Authorize plus the Location Stalwart 1.0 returns (type authenticated).
func (s *Stalwart) AuthorizeEx(ctx context.Context, a AuthCodeRequest) (*AuthResult, error) {
	q := a.Query
	if q == "" {
		v := url.Values{"client_id": {a.ClientID}, "redirect_uri": {a.RedirectURI},
			"response_type": {"code"}, "code_challenge_method": {"S256"}}
		if a.CodeChallenge != "" {
			v.Set("code_challenge", a.CodeChallenge)
		}
		if a.Scope != "" {
			v.Set("scope", a.Scope)
		}
		if a.Nonce != "" {
			v.Set("nonce", a.Nonce)
		}
		if a.State != "" {
			v.Set("state", a.State)
		}
		q = v.Encode()
	}
	body := map[string]any{"type": "authCode", "accountName": a.AccountName, "accountSecret": a.AccountSecret, "query": q, "consent": a.Consent}
	if a.MFAToken != "" {
		body["mfaToken"] = a.MFAToken
	}
	bb, _ := json.Marshal(body)
	b, code, err := s.do(ctx, "POST", "/api/auth", bytes.NewReader(bb), "application/json", false)
	if err != nil {
		return nil, err
	}
	var out struct {
		Type        string `json:"type"`
		Location    string `json:"location"`
		ClientCode  string `json:"client_code"` // v0.16 leftover; 1.0 uses location
		ClientCode2 string `json:"clientCode"`
		Error       string `json:"error"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(b, &out)
	switch out.Type {
	case "authenticated":
		tok := out.ClientCode
		if tok == "" {
			tok = out.ClientCode2
		}
		if tok == "" && out.Location != "" {
			if u, err := url.Parse(out.Location); err == nil {
				tok = u.Query().Get("code")
			}
		}
		if tok == "" {
			return nil, ErrInvalidCredentials
		}
		return &AuthResult{Code: tok, Location: out.Location}, nil
	case "mfaRequired":
		return nil, ErrMFARequired
	case "expired":
		return nil, ErrExpired
	case "redirect":
		return nil, fmt.Errorf("%w: %s", ErrAuthRedirect, out.Location)
	}
	if code == 429 {
		return nil, fmt.Errorf("stalwart: rate limited")
	}
	return nil, ErrInvalidCredentials
}

// Tokens is the token endpoint response.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
}

// Exchange trades an authorization code and its PKCE verifier for tokens at /auth/token.
func (s *Stalwart) Exchange(ctx context.Context, clientID, clientSecret, code, redirectURI, verifier string) (*Tokens, error) {
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	if clientSecret != "" {
		f.Set("client_secret", clientSecret)
	}
	b, status, err := s.do(ctx, "POST", "/auth/token", strings.NewReader(f.Encode()), "application/x-www-form-urlencoded", false)
	if err != nil {
		return nil, err
	}
	t := &Tokens{}
	_ = json.Unmarshal(b, t)
	if status != 200 || t.AccessToken == "" {
		return nil, fmt.Errorf("stalwart token: http %d %s", status, b)
	}
	return t, nil
}

// UserInfo calls the OIDC userinfo endpoint with an access token.
func (s *Stalwart) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(s.BaseURL, "/")+"/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var m map[string]any
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("userinfo: http %d", res.StatusCode)
	}
	return m, json.NewDecoder(res.Body).Decode(&m)
}

// VerifyIDToken checks the signature (ES256 keys of /auth/jwks.json; Stalwart's default signing key on v0.16 is ES256),
// issuer, audience, expiry and nonce of an ID token, and returns its claims.
func (s *Stalwart) VerifyIDToken(ctx context.Context, idToken, audience, nonce string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("id_token: malformed")
	}
	var hdr struct{ Alg, Kid string }
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &hdr)
	if hdr.Alg != "ES256" {
		return nil, fmt.Errorf("id_token: alg %s not supported by this verifier (configure ES256)", hdr.Alg)
	}
	key, err := s.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("id_token: bad signature encoding")
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("id_token: bad signature")
	}
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, err
	}
	d, err := s.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	if c["iss"] != d.Issuer {
		return nil, fmt.Errorf("id_token: issuer %v", c["iss"])
	}
	if c["aud"] != audience {
		return nil, fmt.Errorf("id_token: audience %v", c["aud"])
	}
	if exp, _ := c["exp"].(float64); int64(exp) < time.Now().Unix() {
		return nil, errors.New("id_token: expired")
	}
	if nonce != "" && c["nonce"] != nonce {
		return nil, errors.New("id_token: nonce mismatch")
	}
	return c, nil
}

func (s *Stalwart) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	s.mu.Lock()
	k := s.jwks[kid]
	s.mu.Unlock()
	if k != nil {
		return k, nil
	}
	b, code, err := s.do(ctx, "GET", "/auth/jwks.json", nil, "", false)
	if err != nil || code != 200 {
		return nil, fmt.Errorf("jwks: %v %d", err, code)
	}
	var set struct {
		Keys []struct{ Kty, Crv, Kid, X, Y string } `json:"keys"`
	}
	_ = json.Unmarshal(b, &set)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jwks == nil {
		s.jwks = map[string]*ecdsa.PublicKey{}
	}
	for _, j := range set.Keys {
		if j.Kty != "EC" || j.Crv != "P-256" {
			continue
		}
		x, _ := base64.RawURLEncoding.DecodeString(j.X)
		y, _ := base64.RawURLEncoding.DecodeString(j.Y)
		s.jwks[j.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	}
	if s.jwks[kid] == nil {
		return nil, fmt.Errorf("jwks: no key %q", kid)
	}
	return s.jwks[kid], nil
}

// PKCE returns a fresh verifier and its S256 challenge.
func PKCE() (verifier, challenge string) {
	verifier = RandomString(32)
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
}

// RandomString returns n random bytes, base64url.
func RandomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Raw posts a JMAP request body as the management credential and returns the HTTP status and body unchanged
// (the Authfly Console's request runner).
func (s *Stalwart) Raw(ctx context.Context, method, path string, body []byte, ctype string) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	b, code, err := s.do(ctx, method, path, rd, ctype, true)
	return code, b, err
}

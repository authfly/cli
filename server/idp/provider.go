package idp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

// ClientConfig is a relying party in AUTHFLY_CLIENTS_FILE (JSON). The secret is never stored: secret_sha256 is the
// hex SHA-256 of it (or secret_file names a file holding the plain secret, read at start).
type ClientConfig struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	BackchannelLogoutURI   string   `json:"backchannel_logout_uri,omitempty"`
	SecretSHA256           string   `json:"secret_sha256,omitempty"`
	SecretFile             string   `json:"secret_file,omitempty"`
}

// Paths: the same endpoint paths the Stalwart-proxy era published, so relying parties keep working unchanged.
const (
	PathAuthorize  = "/oauth/authorize"
	PathToken      = "/auth/token"
	PathUserinfo   = "/auth/userinfo"
	PathRevoke     = "/auth/revoke"
	PathEndSession = "/auth/logout"
	PathKeys       = "/auth/jwks.json"
	PathIntrospect = "/auth/introspect"
	PathLogin      = "/idp/login"
)

// Routes lists what Handler serves (mounted on the portal mux).
var Routes = []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", PathAuthorize, PathAuthorize + "/callback",
	PathToken, PathUserinfo, PathRevoke, PathEndSession, PathKeys, PathIntrospect}

// Provider is Authfly's OpenID provider.
type Provider struct {
	Issuer  string
	Store   *Store
	Keys    *KeySet
	Clients map[string]*Client
	OP      *op.Provider
	HTTP    *http.Client
	// SessionAlive (optional) lets the portal veto a sid (e.g. "sign out everywhere" through core.Store).
	SessionAlive func(sid string) bool
}

type Options struct {
	Issuer    string
	Store     *Store
	Keys      *KeySet
	Clients   []ClientConfig
	CryptoKey [32]byte
	Insecure  bool // allow http issuer (tests)
}

func New(o Options) (*Provider, error) {
	p := &Provider{Issuer: strings.TrimRight(o.Issuer, "/"), Store: o.Store, Keys: o.Keys, Clients: map[string]*Client{}, HTTP: &http.Client{Timeout: 5 * time.Second}}
	for _, c := range o.Clients {
		if c.SecretSHA256 == "" && c.SecretFile != "" {
			if b, err := readFile(c.SecretFile); err == nil {
				h := sha256.Sum256([]byte(strings.TrimSpace(string(b))))
				c.SecretSHA256 = hex.EncodeToString(h[:])
			} else {
				return nil, err
			}
		}
		p.Clients[c.ID] = &Client{ID: c.ID, Name: c.Name, SecretSHA256: strings.ToLower(c.SecretSHA256), RedirectURIList: c.RedirectURIs,
			PostLogoutRedirectList: c.PostLogoutRedirectURIs, BackchannelLogoutURI: c.BackchannelLogoutURI,
			loginURL: func(id string) string { return PathLogin + "?id=" + url.QueryEscape(id) }}
	}
	cfg := &op.Config{CryptoKey: o.CryptoKey, CodeMethodS256: true, AuthMethodPost: true, GrantTypeRefreshToken: true,
		SupportedUILocales: []language.Tag{language.English, language.Russian}, BackChannelLogoutSupported: true, BackChannelLogoutSessionSupported: true}
	opts := []op.Option{
		op.WithCustomAuthEndpoint(op.NewEndpoint(strings.TrimPrefix(PathAuthorize, "/"))),
		op.WithCustomTokenEndpoint(op.NewEndpoint(strings.TrimPrefix(PathToken, "/"))),
		op.WithCustomUserinfoEndpoint(op.NewEndpoint(strings.TrimPrefix(PathUserinfo, "/"))),
		op.WithCustomRevocationEndpoint(op.NewEndpoint(strings.TrimPrefix(PathRevoke, "/"))),
		op.WithCustomEndSessionEndpoint(op.NewEndpoint(strings.TrimPrefix(PathEndSession, "/"))),
		op.WithCustomKeysEndpoint(op.NewEndpoint(strings.TrimPrefix(PathKeys, "/"))),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint(strings.TrimPrefix(PathIntrospect, "/"))),
	}
	if o.Insecure {
		opts = append(opts, op.WithAllowInsecure())
	}
	prov, err := op.NewOpenIDProvider(p.Issuer, cfg, &storage{p: p}, opts...)
	if err != nil {
		return nil, err
	}
	p.OP = prov
	return p, nil
}

// Handler serves the protocol endpoints.
func (p *Provider) Handler() http.Handler { return p.OP }

// CallbackURL is where the login UI sends the browser after CompleteAuthRequest.
func (p *Provider) CallbackURL(ctx context.Context, id string) string {
	return p.Issuer + PathAuthorize + "/callback?id=" + url.QueryEscape(id)
}

func (p *Provider) sessionAlive(sid string) bool {
	if sid == "" {
		return false
	}
	if p.Store.Session(sid) == nil {
		return false
	}
	return p.SessionAlive == nil || p.SessionAlive(sid)
}

func (c *Client) checkSecret(secret string) bool {
	if c.SecretSHA256 == "" {
		return false
	}
	h := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(c.SecretSHA256)) == 1
}

// ---- logout

// EndSession destroys an SSO session (sign-out on accounts.yself.link): tokens revoked, record deleted, and a
// back-channel logout token sent to every application signed in through it.
func (p *Provider) EndSession(sid string) {
	ss := p.Store.DeleteSession(sid)
	if ss == nil {
		return
	}
	for cid := range ss.Clients {
		p.BackchannelLogout(cid, ss.Sub, sid)
	}
}

// EndSessionsOf ends every SSO session of a user except keep ("" = all).
func (p *Provider) EndSessionsOf(sub, keep string) {
	for _, ss := range p.Store.SessionsOf(sub) {
		if ss.SID != keep {
			p.EndSession(ss.SID)
		}
	}
}

// RevokeClient revokes one application for the user (tokens, consent) and logs it out over the back channel.
func (p *Provider) RevokeClient(sub, client string) {
	for _, sid := range p.Store.RevokeClient(sub, client) {
		p.BackchannelLogout(client, sub, sid)
	}
}

// LogoutToken builds an OIDC Back-Channel Logout 1.0 logout_token (§2.4): iss, aud, iat, exp, jti, sub, sid,
// events; never a nonce; typ logout+jwt.
func (p *Provider) LogoutToken(client, sub, sid string) (string, error) {
	k := p.Keys.Active()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k.priv}, (&jose.SignerOptions{}).WithType("logout+jwt").WithHeader("kid", k.id))
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := map[string]any{"iss": p.Issuer, "aud": client, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": RandomID(),
		"sub": sub, "sid": sid, "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}
	b, _ := json.Marshal(claims)
	jws, err := signer.Sign(b)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// BackchannelLogout POSTs a logout_token to the client's backchannel_logout_uri (best effort, logged).
func (p *Provider) BackchannelLogout(client, sub, sid string) {
	c := p.Clients[client]
	if c == nil || c.BackchannelLogoutURI == "" {
		return
	}
	tok, err := p.LogoutToken(client, sub, sid)
	if err != nil {
		log.Printf("idp: logout token %s: %v", client, err)
		return
	}
	res, err := p.HTTP.PostForm(c.BackchannelLogoutURI, url.Values{"logout_token": {tok}})
	if err != nil {
		log.Printf("idp: back-channel logout %s: %v", client, err)
		return
	}
	res.Body.Close()
	log.Printf("idp: back-channel logout %s sid=%s… http %d", client, sid[:min(4, len(sid))], res.StatusCode)
}

// RandomID returns 32 random bytes, base64url.
func RandomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

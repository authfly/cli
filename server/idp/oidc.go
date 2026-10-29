package idp

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	accessTTL  = 15 * time.Minute
	refreshTTL = 12 * time.Hour
)

// AuthRequest is a pending /authorize request (persisted).
type AuthRequest struct {
	ID           string              `json:"id"`
	CreationDate time.Time           `json:"created"`
	ClientID     string              `json:"clientId"`
	RedirectURI  string              `json:"redirectUri"`
	State        string              `json:"state,omitempty"`
	Nonce        string              `json:"nonce,omitempty"`
	Scopes       []string            `json:"scopes"`
	ResponseType oidc.ResponseType   `json:"responseType"`
	ResponseMode oidc.ResponseMode   `json:"responseMode,omitempty"`
	Prompt       []string            `json:"prompt,omitempty"`
	MaxAge       *int64              `json:"maxAge,omitempty"` // seconds
	UILocales    []string            `json:"uiLocales,omitempty"`
	LoginHint    string              `json:"loginHint,omitempty"`
	Challenge    *oidc.CodeChallenge `json:"challenge,omitempty"`
	Subject      string              `json:"sub,omitempty"`
	SID          string              `json:"sid,omitempty"`
	AMR          []string            `json:"amr,omitempty"`
	AuthTime     time.Time           `json:"authTime"`
	IsDone       bool                `json:"done"`
	Code         string              `json:"code,omitempty"`
}

func (a *AuthRequest) GetID() string                         { return a.ID }
func (a *AuthRequest) GetACR() string                        { return "" }
func (a *AuthRequest) GetAMR() []string                      { return a.AMR }
func (a *AuthRequest) GetAudience() []string                 { return []string{a.ClientID} }
func (a *AuthRequest) GetAuthTime() time.Time                { return a.AuthTime }
func (a *AuthRequest) GetClientID() string                   { return a.ClientID }
func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.Challenge }
func (a *AuthRequest) GetNonce() string                      { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string                { return a.RedirectURI }
func (a *AuthRequest) GetResponseType() oidc.ResponseType    { return a.ResponseType }
func (a *AuthRequest) GetResponseMode() oidc.ResponseMode    { return a.ResponseMode }
func (a *AuthRequest) GetScopes() []string                   { return a.Scopes }
func (a *AuthRequest) GetState() string                      { return a.State }
func (a *AuthRequest) GetSubject() string                    { return a.Subject }
func (a *AuthRequest) Done() bool                            { return a.IsDone }

// HasPrompt reports whether prompt contains p.
func (a *AuthRequest) HasPrompt(p string) bool { return slices.Contains(a.Prompt, p) }

type refreshReq struct{ *Refresh }

func (r *refreshReq) GetAMR() []string            { return r.AMR }
func (r *refreshReq) GetAudience() []string       { return r.Audience }
func (r *refreshReq) GetAuthTime() time.Time      { return r.AuthTime }
func (r *refreshReq) GetClientID() string         { return r.ClientID }
func (r *refreshReq) GetScopes() []string         { return r.Scopes }
func (r *refreshReq) GetSubject() string          { return r.Subject }
func (r *refreshReq) SetCurrentScopes(s []string) { r.Scopes = s }

// Client is a registered relying party.
type Client struct {
	ID                     string
	Name                   string
	SecretSHA256           string // hex; empty = public client (PKCE only)
	RedirectURIList        []string
	PostLogoutRedirectList []string
	BackchannelLogoutURI   string
	loginURL               func(string) string
}

func (c *Client) GetID() string                       { return c.ID }
func (c *Client) RedirectURIs() []string              { return c.RedirectURIList }
func (c *Client) PostLogoutRedirectURIs() []string    { return c.PostLogoutRedirectList }
func (c *Client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c *Client) AuthMethod() oidc.AuthMethod {
	if c.SecretSHA256 == "" {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodPost
}
func (c *Client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *Client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}
func (c *Client) LoginURL(id string) string           { return c.loginURL(id) }
func (c *Client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }
func (c *Client) IDTokenLifetime() time.Duration      { return time.Hour }
func (c *Client) DevMode() bool                       { return false }
func (c *Client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *Client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *Client) IsScopeAllowed(string) bool           { return false }
func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c *Client) ClockSkew() time.Duration             { return 0 }

// ---- op.Storage

type storage struct{ p *Provider }

var errNotFound = errors.New("not found")

func (s *storage) CreateAuthRequest(_ context.Context, r *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	a := &AuthRequest{ID: RandomID(), CreationDate: time.Now(), ClientID: r.ClientID, RedirectURI: r.RedirectURI, State: r.State, Nonce: r.Nonce,
		Scopes: r.Scopes, ResponseType: r.ResponseType, ResponseMode: r.ResponseMode, LoginHint: r.LoginHint, Subject: userID}
	for _, p := range r.Prompt {
		a.Prompt = append(a.Prompt, p)
	}
	if r.MaxAge != nil {
		v := int64(*r.MaxAge)
		a.MaxAge = &v
	}
	for _, l := range r.UILocales {
		a.UILocales = append(a.UILocales, l.String())
	}
	if r.CodeChallenge != "" {
		a.Challenge = &oidc.CodeChallenge{Challenge: r.CodeChallenge, Method: r.CodeChallengeMethod}
	}
	s.p.Store.tx(true, func(d *data) { d.AuthRequests[a.ID] = a })
	return a, nil
}

func (s *storage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	if a := s.p.Store.AuthRequest(id); a != nil {
		return a, nil
	}
	return nil, errNotFound
}

func (s *storage) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	var a *AuthRequest
	s.p.Store.tx(false, func(d *data) {
		if id, ok := d.Codes[code]; ok {
			a = d.AuthRequests[id]
		}
	})
	if a == nil {
		return nil, errNotFound
	}
	return a, nil
}

func (s *storage) SaveAuthCode(_ context.Context, id, code string) error {
	var err error
	s.p.Store.tx(true, func(d *data) {
		a := d.AuthRequests[id]
		if a == nil {
			err = errNotFound
			return
		}
		a.Code = code
		d.Codes[code] = id
	})
	return err
}

// DeleteAuthRequest makes codes single-use (op calls it after a code exchange).
func (s *storage) DeleteAuthRequest(_ context.Context, id string) error {
	s.p.Store.tx(true, func(d *data) {
		if a := d.AuthRequests[id]; a != nil {
			delete(d.Codes, a.Code)
		}
		delete(d.AuthRequests, id)
	})
	return nil
}

func reqInfo(r op.TokenRequest) (client, sid string, amr []string, authTime time.Time) {
	switch t := r.(type) {
	case *AuthRequest:
		return t.ClientID, t.SID, t.AMR, t.AuthTime
	case *refreshReq:
		return t.ClientID, t.SID, t.AMR, t.AuthTime
	}
	return "", "", nil, time.Time{}
}

func (s *storage) CreateAccessToken(_ context.Context, r op.TokenRequest) (string, time.Time, error) {
	client, sid, amr, at := reqInfo(r)
	t := &Token{ID: RandomID(), ClientID: client, Subject: r.GetSubject(), SID: sid, Audience: r.GetAudience(), Scopes: r.GetScopes(), AMR: amr, AuthTime: at, Expiration: time.Now().Add(accessTTL)}
	if !s.p.sessionAlive(sid) {
		return "", time.Time{}, oidc.ErrInvalidGrant().WithDescription("session ended")
	}
	s.p.Store.tx(true, func(d *data) { d.Tokens[t.ID] = t })
	s.p.Store.recordUse(t.Subject, sid, client, t.Scopes)
	return t.ID, t.Expiration, nil
}

func (s *storage) CreateAccessAndRefreshTokens(_ context.Context, r op.TokenRequest, current string) (string, string, time.Time, error) {
	client, sid, amr, at := reqInfo(r)
	if !s.p.sessionAlive(sid) {
		return "", "", time.Time{}, oidc.ErrInvalidGrant().WithDescription("session ended")
	}
	t := &Token{ID: RandomID(), ClientID: client, Subject: r.GetSubject(), SID: sid, Audience: r.GetAudience(), Scopes: r.GetScopes(), AMR: amr, AuthTime: at, Expiration: time.Now().Add(accessTTL)}
	rt := &Refresh{Token: RandomID(), AccessID: t.ID, ClientID: client, Subject: t.Subject, SID: sid, Audience: t.Audience, Scopes: t.Scopes, AMR: amr, AuthTime: at, Expiration: time.Now().Add(refreshTTL)}
	t.RefreshToken = rt.Token
	var err error
	s.p.Store.tx(true, func(d *data) {
		if current != "" {
			old := d.Refresh[current]
			if old == nil {
				err = oidc.ErrInvalidGrant()
				return
			}
			delete(d.Refresh, current) // rotation
			delete(d.Tokens, old.AccessID)
		}
		d.Tokens[t.ID] = t
		d.Refresh[rt.Token] = rt
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	s.p.Store.recordUse(t.Subject, sid, client, t.Scopes)
	return t.ID, rt.Token, t.Expiration, nil
}

func (s *storage) TokenRequestByRefreshToken(_ context.Context, token string) (op.RefreshTokenRequest, error) {
	var rt *Refresh
	s.p.Store.tx(false, func(d *data) {
		if v := d.Refresh[token]; v != nil {
			c := *v
			rt = &c
		}
	})
	if rt == nil || time.Now().After(rt.Expiration) || !s.p.sessionAlive(rt.SID) {
		return nil, oidc.ErrInvalidGrant()
	}
	return &refreshReq{rt}, nil
}

// TerminateSession is the fallback when end_session has no id_token_hint sid: revoke this client's tokens of the user.
func (s *storage) TerminateSession(_ context.Context, userID, clientID string) error {
	for _, ss := range s.p.Store.SessionsOf(userID) {
		s.p.Store.RemoveClientFromSession(ss.SID, clientID)
	}
	return nil
}

// TerminateSessionFromRequest implements RP-initiated logout as per-client logout: the calling application's
// tokens for this SSO session are revoked and the application is removed from the session; the SSO session on
// accounts.yself.link and the other applications stay signed in.
func (s *storage) TerminateSessionFromRequest(ctx context.Context, r *op.EndSessionRequest) (string, error) {
	sid := ""
	if r.IDTokenHintClaims != nil {
		sid, _ = r.IDTokenHintClaims.Claims["sid"].(string)
	}
	if sid != "" && r.ClientID != "" {
		s.p.Store.RemoveClientFromSession(sid, r.ClientID)
	} else if r.UserID != "" && r.ClientID != "" {
		_ = s.TerminateSession(ctx, r.UserID, r.ClientID)
	}
	return r.RedirectURI, nil
}

func (s *storage) RevokeToken(_ context.Context, token, userID, clientID string) *oidc.Error {
	s.p.Store.tx(true, func(d *data) {
		if t := d.Tokens[token]; t != nil && t.ClientID == clientID {
			delete(d.Tokens, token)
		}
		if rt := d.Refresh[token]; rt != nil && rt.ClientID == clientID {
			delete(d.Refresh, token)
			delete(d.Tokens, rt.AccessID)
		}
	})
	return nil
}

func (s *storage) GetRefreshTokenInfo(_ context.Context, clientID, token string) (string, string, error) {
	var rt *Refresh
	s.p.Store.tx(false, func(d *data) { rt = d.Refresh[token] })
	if rt == nil || rt.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rt.Subject, rt.Token, nil
}

func (s *storage) SigningKey(context.Context) (op.SigningKey, error) { return s.p.Keys.Active(), nil }
func (s *storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.ES256}, nil
}
func (s *storage) KeySet(context.Context) ([]op.Key, error) { return s.p.Keys.Public(), nil }

func (s *storage) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	if c := s.p.Clients[id]; c != nil {
		return c, nil
	}
	return nil, oidc.ErrInvalidClient()
}

func (s *storage) AuthorizeClientIDSecret(_ context.Context, id, secret string) error {
	c := s.p.Clients[id]
	if c == nil || !c.checkSecret(secret) {
		return oidc.ErrInvalidClient()
	}
	return nil
}

func (s *storage) setInfo(info *oidc.UserInfo, sub string, scopes []string) error {
	p := s.p.Store.Profile(sub)
	if p == nil {
		return errNotFound
	}
	for _, sc := range scopes {
		switch sc {
		case oidc.ScopeOpenID:
			info.Subject = sub
		case oidc.ScopeProfile:
			info.Name, info.PreferredUsername = p.Name, p.Username
		case oidc.ScopeEmail:
			info.Email, info.EmailVerified = p.Email, oidc.Bool(p.EmailVerified)
		}
	}
	return nil
}

func (s *storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil // filled in SetUserinfoFromRequest / SetUserinfoFromToken
}

// SetUserinfoFromRequest also asserts sid (OIDC Back-Channel Logout §2.1) into ID tokens.
func (s *storage) SetUserinfoFromRequest(_ context.Context, info *oidc.UserInfo, r op.IDTokenRequest, scopes []string) error {
	if err := s.setInfo(info, r.GetSubject(), scopes); err != nil {
		return err
	}
	_, sid, _, _ := reqInfo(r.(op.TokenRequest))
	if sid != "" {
		info.AppendClaims("sid", sid)
	}
	return nil
}

func (s *storage) SetUserinfoFromToken(_ context.Context, info *oidc.UserInfo, tokenID, subject, _ string) error {
	var t *Token
	s.p.Store.tx(false, func(d *data) { t = d.Tokens[tokenID] })
	if t == nil || time.Now().After(t.Expiration) || !s.p.sessionAlive(t.SID) {
		return errors.New("token is invalid or has expired")
	}
	return s.setInfo(info, t.Subject, t.Scopes)
}

func (s *storage) SetIntrospectionFromToken(_ context.Context, ir *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	var t *Token
	s.p.Store.tx(false, func(d *data) { t = d.Tokens[tokenID] })
	if t == nil || time.Now().After(t.Expiration) || !s.p.sessionAlive(t.SID) {
		return errors.New("token is invalid or has expired")
	}
	ui := new(oidc.UserInfo)
	_ = s.setInfo(ui, t.Subject, t.Scopes)
	ir.SetUserInfo(ui)
	ir.Active, ir.Scope, ir.ClientID, ir.Subject = true, t.Scopes, t.ClientID, t.Subject
	ir.Audience, ir.Expiration = t.Audience, oidc.FromTime(t.Expiration)
	return nil
}

func (s *storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}
func (s *storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errNotFound
}
func (s *storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("jwt profile not supported")
}
func (s *storage) Health(context.Context) error { return nil }

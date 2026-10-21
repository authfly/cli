package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// Config of the Authkit service.
type Config struct {
	Domain          string // the mail domain accounts live in, e.g. example.com
	PublicURL       string // public base URL of Authkit, used in emails and as OIDC redirect URI
	ClientID        string // the OAuth client id Authkit uses with Stalwart for its own sessions
	RequireVerified bool   // refuse password sign-in until the address is verified
	ProductName     string
	MagicTTL        time.Duration
	ResetTTL        time.Duration
	VerifyTTL       time.Duration
	AuditRetention  time.Duration // audit entries older than this are pruned (0: keep)
}

// Service is the Authkit core every adapter calls.
type Service struct {
	Cfg   Config
	SW    *Stalwart
	Mail  *Mailer
	Sign  Signer
	Store *Store
	Audit *Audit // nil: no audit log
}

// User is the signed-in identity.
type User struct {
	Sub      string `json:"sub"`
	Address  string `json:"email"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Verified bool   `json:"email_verified"`
	Method   string `json:"amr"` // password | magic | oidc
}

var (
	ErrUnverified   = errors.New("email address not verified")
	ErrWeakPassword = errors.New("password must have at least 10 characters")
	ErrBadUsername  = errors.New("username: 2 to 32 characters, lowercase letters, digits, dot, dash, underscore")
	ErrOtherDomain  = errors.New("address belongs to another domain")
)

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

// LocalPart turns an identifier (username or address at the Authkit domain) into the account name.
func (s *Service) LocalPart(identifier string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(identifier))
	if i := strings.LastIndexByte(id, '@'); i >= 0 {
		if id[i+1:] != strings.ToLower(s.Cfg.Domain) {
			return "", ErrOtherDomain
		}
		id = id[:i]
	}
	if !usernameRe.MatchString(id) {
		return "", ErrBadUsername
	}
	return id, nil
}

// Address returns the full address of a local part.
func (s *Service) Address(local string) string { return local + "@" + s.Cfg.Domain }

func (s *Service) address(local string) string { return s.Address(local) }

// SignUp creates the Stalwart account (x:Account/set) and emails the verification link.
func (s *Service) SignUp(ctx context.Context, name, username, password string) (*User, error) {
	local, err := s.LocalPart(username)
	if err != nil {
		return nil, err
	}
	if len(password) < 10 {
		return nil, ErrWeakPassword
	}
	acc, err := s.SW.CreateAccount(ctx, s.Cfg.Domain, local, password, strings.TrimSpace(name))
	if err != nil {
		return nil, err
	}
	addr := s.address(local)
	s.Audit.Log("self", addr, "sign_up", "ok", nil)
	if err := s.SendVerification(addr); err != nil {
		log.Printf("authkit: verification mail to %s failed: %v", addr, err)
	}
	return &User{Sub: acc.ID, Address: addr, Username: local, Name: acc.Description}, nil
}

// SendVerification emails a link that proves the address.
func (s *Service) SendVerification(addr string) error {
	tok := s.Sign.Sign(NewClaims("verify", addr, s.Cfg.VerifyTTL))
	link := s.Cfg.PublicURL + "/auth/verify-email?token=" + tok
	return s.Mail.Send(addr, "Verify your email address", fmt.Sprintf("Welcome to %s.\n\nConfirm your address with this link (valid %s):\n\n%s\n\nIf you did not sign up, ignore this email.\n", s.Cfg.ProductName, s.Cfg.VerifyTTL, link))
}

// VerifyEmail consumes a verification token.
func (s *Service) VerifyEmail(token string) (string, error) {
	c, err := s.Sign.Verify(token, "verify")
	if err != nil || !s.Store.Use(c.ID, c.Exp) {
		return "", ErrBadToken
	}
	s.Store.MarkVerified(c.Subject)
	s.Audit.Log("self", c.Subject, "verify_email", "ok", nil)
	return c.Subject, nil
}

// PasswordSignIn checks the password with Stalwart through the OIDC authorization code flow with PKCE
// (POST /api/auth, then /auth/token) and verifies the ID token. identifier is a username or a full address.
func (s *Service) PasswordSignIn(ctx context.Context, identifier, password string) (*User, *Tokens, error) {
	local, err := s.LocalPart(identifier)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}
	verifier, challenge := PKCE()
	nonce := RandomString(12)
	redirect := s.Cfg.PublicURL + "/auth/callback"
	// Authkit always sends the full address: a bare name only resolves when Stalwart has a default domain.
	name := s.address(local)
	code, err := s.SW.Authorize(ctx, AuthCodeRequest{AccountName: name, AccountSecret: password, ClientID: s.Cfg.ClientID, RedirectURI: redirect, Scope: "openid", Nonce: nonce, CodeChallenge: challenge})
	if err != nil {
		s.Audit.Log("self", name, "sign_in", "denied", map[string]string{"method": "password"})
		return nil, nil, err
	}
	tok, err := s.SW.Exchange(ctx, s.Cfg.ClientID, "", code, redirect, verifier)
	if err != nil {
		return nil, nil, err
	}
	claims, err := s.SW.VerifyIDToken(ctx, tok.IDToken, s.Cfg.ClientID, nonce)
	if err != nil {
		return nil, nil, err
	}
	addr := s.address(local)
	u := &User{Sub: str(claims["sub"]), Address: addr, Username: local, Name: str(claims["description"]), Verified: s.Store.IsVerified(addr), Method: "password"}
	if info, err := s.SW.UserInfo(ctx, tok.AccessToken); err == nil && str(info["name"]) != "" {
		u.Name = str(info["name"])
	}
	if s.Cfg.RequireVerified && !u.Verified {
		s.Audit.Log("self", addr, "sign_in", "denied", map[string]string{"method": "password", "reason": "unverified"})
		return u, tok, ErrUnverified
	}
	s.Audit.Log("self", addr, "sign_in", "ok", map[string]string{"method": "password"})
	return u, tok, nil
}

// RequestMagicLink emails a one-time sign-in link when the account exists; it never tells whether it does.
func (s *Service) RequestMagicLink(ctx context.Context, identifier string) (string, error) {
	local, err := s.LocalPart(identifier)
	if err != nil {
		return "", err
	}
	addr := s.address(local)
	if _, err := s.SW.FindAccount(ctx, s.Cfg.Domain, local); err != nil {
		if errors.Is(err, ErrNotFound) {
			return addr, nil
		}
		return addr, err
	}
	s.Audit.Log("self", addr, "magic_link", "ok", nil)
	tok := s.Sign.Sign(NewClaims("magic", addr, s.Cfg.MagicTTL))
	link := s.Cfg.PublicURL + "/auth/magic/verify?token=" + tok
	return addr, s.Mail.Send(addr, "Your sign-in link", fmt.Sprintf("Sign in to %s with this link (valid %s, single use):\n\n%s\n\nIf you did not ask for it, ignore this email.\n", s.Cfg.ProductName, s.Cfg.MagicTTL, link))
}

// VerifyMagicLink consumes a magic-link token and returns the user. Following the link also proves the address.
func (s *Service) VerifyMagicLink(ctx context.Context, token string) (*User, error) {
	c, err := s.Sign.Verify(token, "magic")
	if err != nil {
		return nil, ErrBadToken
	}
	local := strings.SplitN(c.Subject, "@", 2)[0]
	acc, err := s.SW.FindAccount(ctx, s.Cfg.Domain, local)
	if err != nil {
		return nil, ErrBadToken
	}
	if !s.Store.Use(c.ID, c.Exp) {
		return nil, ErrBadToken
	}
	s.Store.MarkVerified(c.Subject)
	s.Audit.Log("self", c.Subject, "sign_in", "ok", map[string]string{"method": "magic"})
	return &User{Sub: acc.ID, Address: c.Subject, Username: local, Name: acc.Description, Verified: true, Method: "magic"}, nil
}

// ForgotPassword emails a reset link when the account exists.
func (s *Service) ForgotPassword(ctx context.Context, identifier string) (string, error) {
	local, err := s.LocalPart(identifier)
	if err != nil {
		return "", err
	}
	addr := s.address(local)
	if _, err := s.SW.FindAccount(ctx, s.Cfg.Domain, local); err != nil {
		if errors.Is(err, ErrNotFound) {
			return addr, nil
		}
		return addr, err
	}
	tok := s.Sign.Sign(NewClaims("reset", addr, s.Cfg.ResetTTL))
	link := s.Cfg.PublicURL + "/auth/reset?token=" + tok
	return addr, s.Mail.Send(addr, "Reset your password", fmt.Sprintf("Choose a new password for %s with this link (valid %s, single use):\n\n%s\n\nIf you did not ask for it, ignore this email.\n", s.Cfg.ProductName, s.Cfg.ResetTTL, link))
}

// CheckResetToken validates a reset token without consuming it.
func (s *Service) CheckResetToken(token string) error {
	_, err := s.Sign.Verify(token, "reset")
	return err
}

// ResetPassword sets the new password in Stalwart (x:Account/set) and consumes the token.
func (s *Service) ResetPassword(ctx context.Context, token, password string) (string, error) {
	c, err := s.Sign.Verify(token, "reset")
	if err != nil {
		return "", ErrBadToken
	}
	if len(password) < 10 {
		return "", ErrWeakPassword
	}
	local := strings.SplitN(c.Subject, "@", 2)[0]
	acc, err := s.SW.FindAccount(ctx, s.Cfg.Domain, local)
	if err != nil {
		return "", ErrBadToken
	}
	if !s.Store.Use(c.ID, c.Exp) {
		return "", ErrBadToken
	}
	if err := s.SW.SetPassword(ctx, acc.ID, password); err != nil {
		return "", err
	}
	s.Store.MarkVerified(c.Subject)
	s.Store.Revoke(c.Subject) // a new password signs out every existing session
	s.Audit.Log("self", c.Subject, "password_reset", "ok", nil)
	return c.Subject, nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

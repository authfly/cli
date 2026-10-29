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

// Config of the Authfly service.
type Config struct {
	Domain          string // legacy: mail domain of person accounts (same as UserDomainName when that is empty)
	UserDomainName  string // person mailboxes, e.g. cab.yself.link
	OrgDomainName   string // organisation / service accounts, e.g. yself.link (empty: single-domain)
	PublicURL       string // public base URL of Authfly, used in emails and as OIDC redirect URI
	ClientID        string // the OAuth client id Authfly uses with Stalwart for its own sessions
	RequireVerified bool   // refuse password sign-in until the address is verified
	PublicSignup    bool   // when false (default), sign-up needs a single-use invite
	ProductName     string
	Methods         []string // password, magic; empty means both (tests / default)
	MagicTTL        time.Duration
	ResetTTL        time.Duration
	VerifyTTL       time.Duration
	AuditRetention  time.Duration // audit entries older than this are pruned (0: keep)
}

// Service is the Authfly core every adapter calls.
type Service struct {
	Cfg   Config
	SW    *Stalwart
	Mail  *Mailer
	Sign  Signer
	Store *Store
	Audit *Audit // nil: no audit log
}

// MailEnabled reports whether SMTP is configured (forgot-password and magic links need it).
func (s *Service) MailEnabled() bool {
	return s != nil && s.Mail.Enabled()
}

// User is the signed-in identity.
type User struct {
	Sub      string `json:"sub"`
	Address  string `json:"email"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Verified bool   `json:"email_verified"`
	Method   string `json:"amr"` // password | magic | oidc
	// OIDCSub is the subject Stalwart's OIDC tokens carry for this account (the numeric account id, e.g. "2"),
	// while Sub is the JMAP id (e.g. "c"). Authfly's own issuer keeps OIDCSub so relying parties see no change.
	OIDCSub string `json:"-"`
}

var (
	ErrUnverified   = errors.New("email address not verified")
	ErrWeakPassword = errors.New("password must have at least 10 characters")
	ErrBadUsername  = errors.New("username: 2 to 32 characters, lowercase letters, digits, dot, dash, underscore")
	ErrOtherDomain  = errors.New("address belongs to another domain")
)

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

// ParseIdentifier turns a username or address into an Identity on the user or org domain.
// Reserved names are accepted here so existing service accounts (e.g. wmaster@yself.link) can
// sign in; SignUpInvite is what refuses them for new registrations.
func (s *Service) ParseIdentifier(identifier string) (Identity, error) {
	id := strings.ToLower(strings.TrimSpace(identifier))
	local, domain := id, ""
	if i := strings.LastIndexByte(id, '@'); i >= 0 {
		local, domain = id[:i], id[i+1:]
	}
	if !usernameRe.MatchString(local) {
		return Identity{}, ErrBadUsername
	}
	userD, orgD := strings.ToLower(s.Cfg.UserDomain()), strings.ToLower(s.Cfg.OrgDomain())
	switch {
	case domain == "":
		return Identity{Local: local, Domain: userD, Kind: KindUser}, nil
	case domain == userD:
		return Identity{Local: local, Domain: userD, Kind: KindUser}, nil
	case orgD != "" && domain == orgD:
		return Identity{Local: local, Domain: orgD, Kind: KindOrg}, nil
	default:
		return Identity{}, ErrOtherDomain
	}
}

// LocalPart turns an identifier (username or address at an Authfly domain) into the account name.
func (s *Service) LocalPart(identifier string) (string, error) {
	id, err := s.ParseIdentifier(identifier)
	if err != nil {
		return "", err
	}
	return id.Local, nil
}

// Address returns the full address of a local part on the user domain (legacy helpers).
func (s *Service) Address(local string) string { return local + "@" + s.Cfg.UserDomain() }

func (s *Service) address(local string) string { return s.Address(local) }

func (s *Service) auditID(accID, addr string) string {
	if accID != "" {
		return accID
	}
	return Pseudonym(addr)
}

// SignUp creates the Stalwart account (x:Account/set) and emails the verification link.
// Public sign-up is disabled: callers must pass a valid invite token unless PublicSignup is on.
func (s *Service) SignUp(ctx context.Context, name, username, password string) (*User, error) {
	return s.SignUpInvite(ctx, name, username, password, "", KindUser)
}

// SignUpInvite creates an account of the invite's kind (or kind, when PublicSignup is on).
func (s *Service) SignUpInvite(ctx context.Context, name, username, password, inviteToken, kind string) (*User, error) {
	if !s.Cfg.PublicSignup {
		if inviteToken == "" {
			return nil, ErrInviteRequired
		}
		inv, err := s.Store.PeekInvite(inviteToken)
		if err != nil {
			return nil, err
		}
		kind = inv.Kind
	}
	if kind != KindOrg {
		kind = KindUser
	}
	ident, err := s.ParseIdentifier(username)
	if err != nil {
		return nil, err
	}
	if IsReservedName(ident.Local) {
		return nil, ErrReservedName
	}
	ident.Kind = kind
	if kind == KindOrg {
		if o := s.Cfg.OrgDomain(); o != "" {
			ident.Domain = o
		}
	} else {
		ident.Domain = s.Cfg.UserDomain()
	}
	if len(password) < 10 {
		return nil, ErrWeakPassword
	}
	taken, err := s.SW.NameTaken(ctx, ident.Local, s.Cfg.Domains()...)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrAccountExists
	}
	acc, err := s.SW.CreateAccountKind(ctx, ident.Domain, ident.Local, password, strings.TrimSpace(name), kind)
	if err != nil {
		return nil, err
	}
	if inviteToken != "" {
		_ = s.Store.ConsumeInvite(inviteToken, acc.ID)
	}
	addr := ident.Address()
	s.Audit.Log("self", acc.ID, "sign_up", "ok", map[string]string{"kind": kind})
	if err := s.SendVerification(addr); err != nil {
		log.Printf("authfly: verification mail to %s failed: %v", addr, err)
	}
	return &User{Sub: acc.ID, Address: addr, Username: ident.Local, Name: acc.Description}, nil
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
	s.Audit.Log("self", s.auditID("", c.Subject), "verify_email", "ok", nil)
	return c.Subject, nil
}

// PasswordSignIn checks the password with Stalwart through the OIDC authorization code flow with PKCE S256
// (POST /api/auth query+consent, then /auth/token) and verifies the ID token. identifier is a username or a full address.
func (s *Service) PasswordSignIn(ctx context.Context, identifier, password string) (*User, *Tokens, error) {
	return s.PasswordSignInMFA(ctx, identifier, password, "")
}

// PasswordSignInMFA is PasswordSignIn with an optional TOTP/mfaToken from a previous mfaRequired response.
func (s *Service) PasswordSignInMFA(ctx context.Context, identifier, password, mfaToken string) (*User, *Tokens, error) {
	ident, err := s.ParseIdentifier(identifier)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}
	verifier, challenge := PKCE()
	nonce := RandomString(12)
	redirect := s.Cfg.PublicURL + "/auth/callback"
	name := ident.Address()
	code, err := s.SW.Authorize(ctx, AuthCodeRequest{
		AccountName: name, AccountSecret: password, MFAToken: mfaToken,
		ClientID: s.Cfg.ClientID, RedirectURI: redirect, Scope: "openid", Nonce: nonce,
		State: RandomString(12), CodeChallenge: challenge,
		Consent: true,
	})
	if err != nil {
		subject := s.auditID("", name)
		if acc, ferr := s.SW.FindAccount(ctx, ident.Domain, ident.Local); ferr == nil {
			subject = acc.ID
		} else if errors.Is(ferr, ErrNotFound) {
			subject = Pseudonym(name)
		}
		s.Audit.Log("self", subject, "sign_in", "denied", map[string]string{"method": "password"})
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
	addr := ident.Address()
	u := &User{Sub: str(claims["sub"]), OIDCSub: str(claims["sub"]), Address: addr, Username: ident.Local, Name: str(claims["description"]), Verified: s.Store.IsVerified(addr), Method: "password"}
	if info, err := s.SW.UserInfo(ctx, tok.AccessToken); err == nil && str(info["name"]) != "" {
		u.Name = str(info["name"])
	}
	if acc, err := s.SW.FindAccount(ctx, ident.Domain, ident.Local); err == nil {
		u.Sub = acc.ID
		if acc.Description != "" && u.Name == "" {
			u.Name = acc.Description
		}
	}
	if s.Cfg.RequireVerified && !u.Verified {
		s.Audit.Log("self", s.auditID(u.Sub, addr), "sign_in", "denied", map[string]string{"method": "password", "reason": "unverified"})
		return u, tok, ErrUnverified
	}
	s.Audit.Log("self", s.auditID(u.Sub, addr), "sign_in", "ok", map[string]string{"method": "password"})
	return u, tok, nil
}

// RequestMagicLink emails a one-time sign-in link when the account exists; it never tells whether it does.
func (s *Service) RequestMagicLink(ctx context.Context, identifier string) (string, error) {
	ident, err := s.ParseIdentifier(identifier)
	if err != nil {
		return "", err
	}
	addr := ident.Address()
	acc, err := s.SW.FindAccount(ctx, ident.Domain, ident.Local)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return addr, nil
		}
		return addr, err
	}
	s.Audit.Log("self", acc.ID, "magic_link", "ok", nil)
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
	ident, err := s.ParseIdentifier(c.Subject)
	if err != nil {
		return nil, ErrBadToken
	}
	acc, err := s.SW.FindAccount(ctx, ident.Domain, ident.Local)
	if err != nil {
		return nil, ErrBadToken
	}
	if !s.Store.Use(c.ID, c.Exp) {
		return nil, ErrBadToken
	}
	s.Store.MarkVerified(c.Subject)
	s.Audit.Log("self", acc.ID, "sign_in", "ok", map[string]string{"method": "magic"})
	return &User{Sub: acc.ID, Address: c.Subject, Username: ident.Local, Name: acc.Description, Verified: true, Method: "magic"}, nil
}

// ForgotPassword emails a reset link when the account exists.
func (s *Service) ForgotPassword(ctx context.Context, identifier string) (string, error) {
	ident, err := s.ParseIdentifier(identifier)
	if err != nil {
		return "", err
	}
	addr := ident.Address()
	if _, err := s.SW.FindAccount(ctx, ident.Domain, ident.Local); err != nil {
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
	ident, err := s.ParseIdentifier(c.Subject)
	if err != nil {
		return "", ErrBadToken
	}
	acc, err := s.SW.FindAccount(ctx, ident.Domain, ident.Local)
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
	s.Store.DropSessions(acc.ID)
	s.Audit.Log("self", acc.ID, "password_reset", "ok", nil)
	return c.Subject, nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Package ext holds the extension points of Authfly: social login, second factors (TOTP) and security keys
// (WebAuthn / YubiKey). Interfaces and stubs only; nothing here is wired to a provider yet. See docs/extensions.md.
package ext

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned by every stub.
var ErrNotImplemented = errors.New("authfly: extension not implemented")

// Identity is what a social provider proves about a person.
type Identity struct {
	Provider, Subject, Email, Name string
	EmailVerified                  bool
}

// SocialProvider is an external OAuth/OIDC identity provider (GitHub, Google, ...). Authfly links an Identity to a
// Stalwart account by verified email, or creates the account on first sign-in (policy of the host app).
type SocialProvider interface {
	ID() string
	Name() string
	// AuthURL returns where to send the browser; state and PKCE are Authfly's.
	AuthURL(state, codeChallenge, redirectURI string) string
	// Exchange finishes the flow at the provider and returns the identity.
	Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*Identity, error)
}

// SecondFactor is a one-time-code factor (TOTP, RFC 6238). Note: Stalwart has its own TOTP and answers
// POST /api/auth with type mfaRequired; an implementation can forward the code as mfaToken (see docs/extensions.md).
type SecondFactor interface {
	Kind() string // "totp"
	Enrolled(ctx context.Context, address string) (bool, error)
	// Enroll returns an otpauth:// URI for a QR code.
	Enroll(ctx context.Context, address string) (string, error)
	Verify(ctx context.Context, address, code string) error
}

// Authenticator is a WebAuthn / FIDO2 security key or passkey (YubiKey and friends). Messages are the JSON of the
// WebAuthn ceremonies (PublicKeyCredentialCreationOptions / RequestOptions and the browser's responses).
type Authenticator interface {
	BeginRegistration(ctx context.Context, address string) ([]byte, error)
	FinishRegistration(ctx context.Context, address string, response []byte) error
	BeginLogin(ctx context.Context, address string) ([]byte, error)
	FinishLogin(ctx context.Context, address string, response []byte) (string, error)
}

// Registry is what the host app plugs in. Empty fields mean the feature is off.
type Registry struct {
	Social   []SocialProvider
	TOTP     SecondFactor
	WebAuthn Authenticator
}

// Stub implementations, so the host can render the UI and the routes answer 501 until a real one is plugged in.
type StubSocial struct{ IDValue, NameValue string }

func (p StubSocial) ID() string                            { return p.IDValue }
func (p StubSocial) Name() string                          { return p.NameValue }
func (p StubSocial) AuthURL(string, string, string) string { return "" }
func (p StubSocial) Exchange(context.Context, string, string, string) (*Identity, error) {
	return nil, ErrNotImplemented
}

type StubTOTP struct{}

func (StubTOTP) Kind() string                                   { return "totp" }
func (StubTOTP) Enrolled(context.Context, string) (bool, error) { return false, nil }
func (StubTOTP) Enroll(context.Context, string) (string, error) { return "", ErrNotImplemented }
func (StubTOTP) Verify(context.Context, string, string) error   { return ErrNotImplemented }

type StubWebAuthn struct{}

func (StubWebAuthn) BeginRegistration(context.Context, string) ([]byte, error) {
	return nil, ErrNotImplemented
}
func (StubWebAuthn) FinishRegistration(context.Context, string, []byte) error {
	return ErrNotImplemented
}
func (StubWebAuthn) BeginLogin(context.Context, string) ([]byte, error) {
	return nil, ErrNotImplemented
}
func (StubWebAuthn) FinishLogin(context.Context, string, []byte) (string, error) {
	return "", ErrNotImplemented
}

# Extensions

Social login, TOTP and WebAuthn are extension points with interfaces and stubs; they are **not implemented**. The stubs let the widgets render the buttons and methods, and the routes answer `501 Not Implemented`, so you can wire a real provider without touching the widgets.

::preview sign-in-social

## Interfaces (Go, `server/ext`)

```go
// SocialProvider: an OAuth 2 / OIDC identity provider (GitHub, Google, ...).
type SocialProvider interface {
	ID() string
	Name() string
	AuthURL(state, codeChallenge, redirectURI string) string
	Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*Identity, error)
}

// SecondFactor: a one-time code factor such as TOTP (RFC 6238).
type SecondFactor interface {
	Kind() string
	Enrolled(ctx context.Context, address string) (bool, error)
	Enroll(ctx context.Context, address string) (string, error)
	Verify(ctx context.Context, address, code string) error
}

// Authenticator: WebAuthn / FIDO2 security keys and passkeys.
type Authenticator interface {
	BeginRegistration(ctx context.Context, address string) ([]byte, error)
	FinishRegistration(ctx context.Context, address string, response []byte) error
	BeginLogin(ctx context.Context, address string) ([]byte, error)
	FinishLogin(ctx context.Context, address string, response []byte) (string, error)
}

type Registry struct {
	Social   []SocialProvider
	TOTP     SecondFactor
	WebAuthn Authenticator
}
```

Pass a `Registry` to `web.New`. `AUTHFLY_SOCIAL_STUBS=true` registers two stub providers (GitHub, Google) so you can see the buttons.

## Widgets

- Sign in: `social="show"` renders the provider list from `providers` (`{id, title, text, icon}`); each links to `/auth/social/{id}`.
- Code: `AuthflyRequest` with `kind="code"` is the second-factor entry form (`code` field).
- Account: the methods list shows "Authenticator app" and "Security key" as "Soon" while the stubs are in place.

## Wiring a real provider

- **Social**: implement `SocialProvider`, then link the identity to a Stalwart account. Stalwart only issues OIDC codes for a password it can check, so a social sign-in gives an Authfly session (like a magic link), not Stalwart tokens.
- **TOTP**: store the secret per address (the state file or your database) and call `Verify` after the password step. Separately, if an account has Stalwart's own two-factor auth on, Stalwart's `/api/auth` answers `mfaRequired` (per the Stalwart docs, not tested live) and Authfly reports `mfa_required`; the hosted pages do not ask for that code yet.
- **WebAuthn**: implement `Authenticator` with a WebAuthn library; the ceremonies need a small script on the page, which the widgets leave to the host.

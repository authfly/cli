# Verified and unverified

Authfly only uses Stalwart APIs and settings it found in the Stalwart documentation, and every one below was exercised against `stalwartlabs/stalwart:v0.16` (v0.16.27) in the dev stack unless marked otherwise.

## Verified live

- Declarative start: a `config.json` with only the `RocksDb` data store skips the bootstrap wizard; `STALWART_RECOVERY_ADMIN=user:pass` works as an admin in normal mode; `STALWART_PUBLIC_URL` becomes the OIDC issuer.
- Management over JMAP with capability `urn:stalwart:jmap`: `x:Domain/query|get|set`, `x:Account/query|get|set` (create a `User` with a `Password` credential, update the credentials to change the password).
- `POST /api/auth` with `type: "authCode"` (account name, secret, client id, redirect URI, PKCE S256, scope, nonce, state) returns an authorization code.
- `/.well-known/openid-configuration`, `/auth/token` (code + PKCE verifier), `/auth/userinfo`, `/auth/jwks.json` (ES256). ID token claims: `iss`, `sub`, `aud`, `nonce`, `preferred_username`, `email`, `description`.
- SMTP on port 25: unauthenticated local delivery to the own domain. JMAP mail (`Email/query`, `Email/get`) to read the mailbox in the tests.

## Differences from the docs

- The management JMAP endpoint answered at `POST /jmap`; the docs mention `/api` for management. Authfly uses `/jmap`.
- `/api/auth` answered `client_code`; the docs say `clientCode`. Authfly accepts both.
- A bare account name failed `/api/auth` without a default domain; Authfly always sends the full address.
- Stalwart rejects the SMTP HELO name `localhost`; Authfly greets with its sender domain.

## Not verified

- `mfaRequired` from `/api/auth` (accounts with Stalwart two-factor auth): handled from the docs, not tested.
- Registered OAuth clients in Stalwart: in the tested setup any client id and `http` redirect URIs were accepted; behavior with registered clients and strict redirect checks was not tested.
- Authenticated SMTP submission (587/465) through Authfly's mailer: implemented, tested only against port 25.
- Production TLS (HTTPS issuer, SMTP TLS) and DNS (MX, SPF, DKIM, DMARC).
- Social login, TOTP and WebAuthn are stubs ([Extensions](extensions.md)).

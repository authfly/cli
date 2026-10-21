# Form contract and API

## Form fields

Every widget posts a form. The field names are the contract between the widgets and any backend:

- Sign in: `identifier` (username or address), `password`, `csrf`.
- Magic link request: `identifier` (address), `csrf`.
- Sign up: `name`, `username`, `password`, `terms` (checkbox), `csrf`.
- Forgot password: `email`, `csrf`. Reset: `token` (hidden), `password`, `confirm`, `csrf`. Code: `code`, `csrf`.
- Consent: `decision` (hidden, `approve` or `deny`, one form per button), `csrf`.
- Sign out: `csrf`.

Each widget takes `action` (the form URL) and `csrf` (the token value) as props, so you can point it at your own backend.

## Hosted routes

- `GET|POST /auth/sign-in`, `/auth/sign-up`, `/auth/magic`, `/auth/forgot`, `/auth/reset`, `/auth/sign-out`
- `GET /auth/magic/verify?token=`, `GET /auth/verify-email?token=`
- `GET /account`
- `GET /oauth/authorize` (OIDC handoff), `POST /oauth/authorize` (sign in during the handoff), `POST /oauth/consent`
- Stubs answering 501: `GET /auth/social/{provider}`, `GET /auth/2fa`

## JSON API

JSON in, JSON out, under `/api/v1`. With `AUTHFLY_API_KEY` set, send it as `X-Authfly-Key`. Sign-in calls return a session token; send it as `Authorization: Bearer <token>`.

- `POST /sign-up` `{name, username, password}` → `{user}` and a verification email.
- `POST /sign-in` `{identifier, password}` → `{token, user}`.
- `POST /magic-link` `{identifier}` → `{sent_to}`; `POST /magic-link/verify` `{token}` → `{token, user}`.
- `POST /verify-email` `{token}`.
- `POST /forgot` `{email}` → `{sent_to}`; `POST /reset` `{token, password}`.
- `GET /me` → `{user}`; `GET /config` → public settings (domain, enabled methods).

User: `{sub, email, username, name, email_verified, amr}` with `amr` one of `password`, `magic`, `oidc`.

Errors: `{error, message}` with `error` one of `invalid_credentials`, `unverified`, `account_exists`, `invalid_token`, `invalid_input`, `mfa_required`, `unauthenticated`, `unauthorized`, `error`.

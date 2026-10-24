# Architecture

```text
 browser ──> your app (any runtime, Authfly widgets) ──> Authfly adapter
                 │                                          │
                 │ OIDC (code + PKCE)                       │ JSON API / hosted pages
                 v                                          v
            Stalwart  <── JMAP management, /api/auth ──  Authfly server (Go core)
         (directory, OIDC,  <──────── SMTP ──────────────   templ hosted pages
          mailboxes, SMTP)
```

## Pieces

- **Stalwart** holds the accounts (`x:Account`, `x:Domain`), checks passwords, issues OIDC codes and tokens, and delivers the emails.
- **Authfly core** (`server/core`, Go): creates accounts and changes passwords over JMAP, gets authorization codes from `/api/auth`, exchanges codes at `/auth/token`, verifies ID tokens (ES256, JWKS), sends mail over SMTP, signs single-use links (HMAC) and keeps a small state file (verified addresses, used links).
- **Hosted pages** (`server/web`, templ): every flow as server-rendered HTML forms with CSRF protection (double-submit cookie). They work without JavaScript.
- **JSON API** (`/api/v1`): the same flows for adapters and single-page apps.
- **Widgets** (authfly/authkit, pinned in `deps.lock`): the forms as components for nine runtimes (react, vue, svelte, solid, webcomponent, templ, twig, latte, jinja2), built on UI8Kit 3 primitives (`npx ui8kit@3`, `@ui8kit/registry` 3.2.2) with the same DOM. They depend only on the `@authfly/core` contract (authfly/authfly).

## Sessions

- Authfly session: an HMAC-signed cookie `authfly_session` (12 hours), or the same token as a bearer token for the JSON API.
- App sessions: your app's own; the Node adapter seals the user into a cookie after the OIDC callback.

## Email links

Verification, magic link and reset links carry a signed token with an expiry and a nonce. Magic and reset links are single use: the nonce is recorded when the link is used.

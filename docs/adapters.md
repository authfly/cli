# Adapters

An adapter connects your app's backend to Authfly and Stalwart. One per runtime family, all thin, all covered by the end-to-end test.

- **Go** (`server/core`, `server/web`): the core itself. Embed `web.New(...).Handler()` or call `core.Service` directly (templ runtime).
- **Node and Bun** (`packages/adapters/ts`, `@authfly/node`): React, Vue, Svelte, Solid backends. OIDC relying party with PKCE, ES256 ID token verification against Stalwart's JWKS, sealed session cookies, and `AuthflyApi` for the JSON API.
- **PHP** (`packages/adapters/php`): Twig and Latte apps. `AuthflyApi` and `Authfly` (OIDC with PKCE). No dependencies.
- **Python** (`packages/adapters/python`): Jinja2 apps (Flask, FastAPI, Django). `AuthflyApi` and `Authfly`. Standard library only.

## Two ways in

1. **SSO with OIDC** (recommended for apps): `authorizeUrl()` sends the user to the Authfly hosted sign-in; `callback()` exchanges the code at Stalwart and returns the claims (`sub`, `email`, `preferred_username`, ...). Your app keeps its own session. See [Configure OIDC](oidc.md).
2. **JSON API** (your own forms): render the widgets in your app, post to your routes, call `signIn`, `signUp`, `requestMagicLink`, `forgot`, `reset` and keep the returned token. See [Form contract and API](contract.md).

## ID token checks

- Node: full check (ES256 signature with the JWKS, `iss`, `aud`, `nonce`, `exp`).
- PHP and Python: the ID token is taken from Stalwart's token endpoint over the back channel, so the adapters check `iss`, `aud`, `nonce` and `exp` and skip the signature, as OpenID Connect Core 3.1.3.7 allows when the token comes directly from the token endpoint over TLS. Use a JOSE library with the `jwks_uri` if you pass ID tokens to other services. In production the token endpoint must be HTTPS.

## Tested

`bun e2e/flow.test.ts` runs the OIDC flow for the React demo (Node adapter), the Python adapter and the PHP adapter against the compose stack: authorize URL, hosted sign-in, consent, code exchange at Stalwart, claims check, then a JSON API sign-in and `/me`.

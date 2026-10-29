# examples/rp — minimal OIDC relying party

The yself.link relying party: Authorization Code + PKCE S256 + `state` + `nonce` against the Authfly-fronted
Stalwart issuer (`https://accounts.yself.link`), confidential client (`client_secret_post`), server-side session
(`__Host-rp_session`, HttpOnly, Secure, SameSite=Lax, 8 h, in memory), `/me` (HTML or `?format=json`), and
RP-initiated logout (`POST /auth/logout` → `end_session_endpoint` with `id_token_hint` + `post_logout_redirect_uri`).
ID tokens are verified with `server/core` (ES256 via JWKS, `iss`, `aud`, `exp`, `nonce`); the `iss` callback
parameter (RFC 9207) is checked when present.

Routes: `/`, `/me`, `/auth/login`, `/auth/callback`, `/auth/logout`, `/healthz`. UI: en/ru (`?lang=` or Accept-Language).

## Registration

* Stalwart `x:OAuthClient` `yself-link`: redirect `https://yself.link/auth/callback`, post-logout `https://yself.link/`, secret.
* Authfly `AUTHFLY_CLIENTS_FILE`: `{"id":"yself-link","name":"yself.link","redirect_uris":["https://yself.link/auth/callback"]}`.

## Deploy (fra-ypanel web/site)

    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o rp ./examples/rp   # → /usr/local/bin/rp
    # /etc/rp/client-secret (root:rp 0640), rp.service (this directory), Caddy: yself.link { reverse_proxy 10.10.10.16:8080 }

Sessions are in memory: a restart signs everyone out (fine for one instance; swap the map for a store to scale out).

# Deploy accounts.yself.link

Turnkey Authfly account portal in front of Stalwart 1.0. Public hostname
`https://accounts.yself.link`. Stalwart stays on the internal network.

Person mailboxes: `name@cab.yself.link`. Organisation / service accounts:
`name@yself.link`. The local-part is unique across both domains (a disabled
mirror alias reserves the name on the other domain). Public registration is
off; create an invite with `authfly invite create`.

## Environment

| Variable | Default | Role |
|---|---|---|
| `AUTHFLY_SECRET` | (required, ≥32 chars) | HMAC key for sessions and one-time links. Prefer `AUTHFLY_SECRET_FILE`. |
| `AUTHFLY_PUBLIC_URL` | `http://localhost:4000` | Public origin; OIDC issuer as seen by apps. |
| `AUTHFLY_ADDR` | `:4000` | Listen address. |
| `AUTHFLY_STORE` | `authfly-store.json` | JSON store (invites, sessions, verification). |
| `AUTHFLY_AUDIT_LOG` | next to the store | Hash-chained audit log. |
| `AUTHFLY_USER_DOMAIN` | `AUTHFLY_DOMAIN` | Person mailbox domain (`cab.yself.link`). |
| `AUTHFLY_ORG_DOMAIN` | empty | Organisation domain (`yself.link`). Empty: single-domain. |
| `AUTHFLY_DOMAIN` | `authfly.test` | Legacy alias of the user domain. |
| `AUTHFLY_PUBLIC_SIGNUP` | `false` | When false, sign-up needs a single-use invite. |
| `AUTHFLY_RESERVED_NAMES_FILE` | built-in list | One local-part per line; `#` comments. Ship `config/reserved-names.txt`. |
| `AUTHFLY_CLIENT_ID` | `authfly` | Authfly’s own OAuth client id at Stalwart (first-party). |
| `AUTHFLY_CLIENTS` | `[]` | JSON array of relying parties `{id,name,redirect_uris}`. |
| `AUTHFLY_REQUIRE_VERIFIED` | `true` | Refuse password sign-in until the address is verified. |
| `AUTHFLY_PRODUCT` | `Authfly` | Product name in chrome and mail. |
| `STALWART_URL` | `http://localhost:8080` | Internal Stalwart HTTP (`http://10.10.10.124:8088` here). |
| `STALWART_ADMIN` / `_FILE` | `admin:admin` | Bootstrap / management credential. |
| `STALWART_ADMIN_TOKEN` | empty | API token instead of basic auth. |
| `SMTP_ADDR` / `SMTP_FROM` | `localhost:25` / `noreply@…` | Verification and magic-link mail. |
| `AUTHFLY_ADMIN_ADDR` / `AUTHFLY_ADMIN_KEY` | off | Internal admin API (invites, GDPR). Never publish. |
| `AUTHFLY_TLS_MODE` | `off` | `off` behind Caddy; `acme` / `manual` if Authfly terminates TLS. |

Secrets: use `*_FILE` (0600) rather than the process environment.

Invite CLI (on the host that holds `AUTHFLY_STORE`):

```
authfly invite create --kind user --ttl 72h --note "alice"
authfly invite create --kind org --ttl 168h --note "ops"
authfly invite list
authfly invite revoke <id>
```

Or `POST /admin/v1/invites` on the admin listener (`X-Authfly-Admin-Key`).

First boot: `authfly init-stalwart` (needs `AUTHFLY_SERVICE_PASSWORD` ≥16 chars).
It creates both domains, the service role (including `x:AccountPassword`,
`x:AppPassword`, `x:OAuthGrant`), disables Stalwart’s web UI, locks OIDC
registration, and registers Authfly as a first-party client.

## Caddy

Caddy terminates TLS for `accounts.yself.link` and reverse-proxies only Authfly.
Stalwart (`http://10.10.10.124:8088`) is not on the public internet. Authfly
already proxies only `/auth/token`, `/auth/userinfo`, `/auth/jwks.json`,
`/auth/revoke`, `/auth/logout` and discovery; `/oauth/authorize` is the hosted
sign-in. Do not proxy Stalwart itself.

```caddy
accounts.yself.link {
	encode gzip
	reverse_proxy 127.0.0.1:4000
}

# Stalwart is internal-only. If anything must reach it through this Caddy,
# allow only OIDC and refuse the rest:
# handle /login*     { respond 404 }
# handle /device*    { respond 404 }
# handle /admin*     { respond 404 }
# handle /account*   { respond 404 }
# handle /jmap*      { respond 404 }
# handle /api/*      { respond 404 }
# handle /auth/register* { respond 404 }
# handle /auth/device*   { respond 404 }
```

Authfly env on this host:

```
AUTHFLY_PUBLIC_URL=https://accounts.yself.link
AUTHFLY_USER_DOMAIN=cab.yself.link
AUTHFLY_ORG_DOMAIN=yself.link
AUTHFLY_PUBLIC_SIGNUP=false
AUTHFLY_RESERVED_NAMES_FILE=/etc/authfly/reserved-names.txt
STALWART_URL=http://10.10.10.124:8088
AUTHFLY_TLS_MODE=off
```

## Binary

Linux amd64: `dist/authfly-linux-amd64` (this release). Run as a systemd unit
behind Caddy; store and audit files on a 0700 directory.

Go toolchain: **1.26+** (module `go 1.26.0`). 1.27.3 could not be installed in
the build environment (proxy.golang.org / go.dev CDN blocked); CI should use
the official Go 1.26 or 1.27 toolchain.

## Stalwart 1.0 notes

- `POST /api/auth` body is `{type:"authCode", accountName, accountSecret, query, consent, mfaToken?}`.
  Registered clients need `consent: true`. The code is in `location` (`?code=`).
- PKCE S256 is required. There is no password grant.
- Password change: `x:AccountPassword` singleton + `currentSecret`.
- Forgot-password: patch only `credentials/{id}/secret`, never replace the list.
- Connected apps: `x:OAuthGrant` query/get/destroy (no create).
- Audit subjects are Stalwart account ids, never email addresses.

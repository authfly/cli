# Security and lock-down

Authfly runs Stalwart as a private back end. The public internet sees the mail ports and Authfly, nothing else. Everything here is checked by `bun e2e/security.test.ts` (11 steps) against the compose stack.

## What is reachable from where

| Surface | Where | Why |
| --- | --- | --- |
| Authfly `:4000` | public | Hosted pages, JSON API, and the OIDC endpoints it proxies |
| SMTP `25`, submissions `465`, IMAPS `993` (dev: 2525, 4465, 9993) | public | Mail. There is no plain IMAP listener |
| Stalwart HTTP `:8080` (JMAP management, `/api/*`, OAuth internals) | `127.0.0.1` and the compose network only | Management must never be public |
| Authfly Console `:4500` | `127.0.0.1` only | Private configurator, opened through an SSH tunnel |
| Authfly admin API `:4001` | compose network only, not published | Used by the console for GDPR actions and Authfly state |

## OIDC through an Authfly proxy, not Stalwart directly

Stalwart has one HTTP listener. The same port serves the OIDC endpoints, JMAP management (`/jmap` with `urn:stalwart:jmap`), `/api/*`, the device flow, dynamic client registration and introspection. Publishing it, even behind a path filter in a generic reverse proxy, exposes all of that. Authfly therefore publishes an allowlist and nothing more (`server/web/oidcproxy.go`):

- `GET /.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`, rewritten: `authorization_endpoint` points to Authfly's hosted sign-in (`/oauth/authorize`); the device, registration and introspection endpoints are removed.
- `GET /auth/jwks.json`, `POST /auth/token`, `GET`/`POST /auth/userinfo`.

`STALWART_PUBLIC_URL` is Authfly's public URL, so the issuer in tokens and discovery is Authfly. Every other path, such as `/jmap`, `/api/*`, `/admin`, `/auth/register`, `/auth/device` or `/auth/introspect`, returns 404 or 405 on Authfly (tested).

## Hardening applied by `authfly init-stalwart`

The one-shot `stalwart-init` service runs with the bootstrap admin before Authfly starts (`server/core/harden.go`, idempotent):

1. Ensures the mail domain exists.
2. Creates or updates the **least-privilege role `authfly-service`**: the built-in User role plus `sysAccountGet/Query/Create/Update/Destroy`, `sysDomainGet/Query`, `impersonate` and `fetchAnyBlob` (GDPR export of the mailbox), and `sysTaskCreate` with `taskStoreMaintenance` (blob purge after erasure). Stalwart refuses to grant permissions the caller lacks, so the role inherits User in order to create users.
3. Creates or updates the service account `authfly-svc@DOMAIN` with that role. Authfly uses this account, never the admin.
4. Disables the web admin and account apps (`x:Application.enabled=false`, then the `UpdateApps` action: `ReloadSettings` alone does not apply it).
5. Locks OIDC: `x:OidcProvider.anonymousClientRegistration=false`, `requireClientRegistration=true`, and registers the clients (`AUTHFLY_CLIENTS` plus Authfly itself) as `x:OAuthClient`.

Tested: the service account can manage accounts but gets errors for `x:Http`, `x:Role`, `x:QueuedMessage`, `x:OidcProvider` and `x:Application`; creating an Admin account with it is refused; anonymous registration returns an error; an unregistered client id gets no code; `/admin/` and `/account/` return 404 even on localhost.

## Opening the private surfaces: SSH tunnel

On the server, the console and Stalwart HTTP listen on `127.0.0.1`. From your machine:

```sh
ssh -N -L 4500:127.0.0.1:4500 -L 8080:127.0.0.1:8080 you@your-server
```

Then open `http://localhost:4500` (Authfly Console). `http://localhost:8080` reaches Stalwart's JMAP API for curl commands exported by the console. Close the tunnel and both are gone again.

## Console protections

- Admin session: `CONSOLE_ADMIN=user:password` (password at least 12 characters), signed cookie (`CONSOLE_SECRET`), HttpOnly, SameSite=Strict, 8 h. Five failed logins lock the user for 15 minutes.
- CSRF: a per-session HMAC token in every form, and cross-site requests refused when the browser sends `Sec-Fetch-Site`. The login form uses a double-submit cookie.
- Headers: CSP `default-src 'self'` (no inline scripts), `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `no-store`.
- Every action is written to a hash-chained audit log (`CONSOLE_DATA/console-audit.jsonl`), including refused CSRF attempts and failed logins.
- Typed confirmation before destructive and GDPR actions. Secrets are masked in responses and in curl exports.

## Release channel: signatures and pins

`authfly deploy`, `upgrade`, `rollback` and `doctor` read the channel manifest (`channel.json`, by default from the
latest GitHub release of authfly/cli) and trust nothing in it until its detached signature `channel.json.sig` checks
out:

- OpenSSH SSHSIG, namespace `authfly-channel`, sha512, over the exact bytes of `channel.json`: every release, binary
  sha256 and image digest in the file is covered.
- The signing key is a FIDO2 security key (`sk-ssh-ed25519@openssh.com`, application `ssh:authfly-release`, on a
  YubiKey): the private key never exists outside the hardware, and every signature needs a touch. The CLI requires
  the user-presence flag in the signature.
- The CLI has the trusted public keys built in (`TrustedKeys` in `server/deploy/sign.go`, `authorized_keys` format).
  A signature by an unknown key, for another namespace or application, without touch, a modified manifest, or a
  missing `.sig` on an `https://` channel is refused with an error that names the reason; `doctor` reports it as
  `FAIL channel` and shows the signing key and counter on `PASS`.
- Dev channels (`tools/release.sh`, local files, `http://` test servers) can be accepted unsigned with
  `channel.allow_unsigned: true` (`authfly init --allow-unsigned-channel`). Off by default, refused for `https://`,
  and a present but wrong signature is refused anyway. `doctor` warns while it is on.
- Inside the signed manifest, binaries are pinned by sha256 and images by the digest of their multi-arch index
  (`docker pull repo@sha256:…`), so the registry cannot substitute content.

Signing on Windows/macOS/Linux, the spare key, loss and rotation: [Releasing](release.md#signing).

## Production checklist

- Replace every `dev-only-*` secret: `STALWART_ADMIN_PASSWORD`, `AUTHFLY_SERVICE_PASSWORD`, `AUTHFLY_SECRET`, `AUTHFLY_ADMIN_KEY`, `CONSOLE_ADMIN`, `CONSOLE_SECRET`.
- Put TLS in front of Authfly (`AUTHFLY_PUBLIC_URL=https://...`, which also sets Secure cookies) and use the real mail ports.
- Keep `127.0.0.1` in the console and 8080 port mappings, and do not add a mapping for 4001.
- Remove `STALWART_RECOVERY_ADMIN` from the stalwart service after the first `stalwart-init` run if you create a separate admin; the console needs an admin credential.

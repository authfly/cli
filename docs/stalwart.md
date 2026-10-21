# Install Stalwart

Authkit needs Stalwart **v0.16** or later. Everything below was checked against `stalwartlabs/stalwart:v0.16` (v0.16.27) in the dev stack; items marked unverified are listed on [Verified and unverified](verification.md).

## Docker Compose

```yaml
services:
  stalwart:
    image: stalwartlabs/stalwart:v0.16
    environment:
      STALWART_RECOVERY_ADMIN: admin:change-me
      STALWART_PUBLIC_URL: https://mail.example.com
    volumes:
      - ./config.json:/etc/stalwart/config.json:ro
      - stalwart-data:/var/lib/stalwart
    ports:
      - "443:443"
      - "25:25"
      - "587:587"
      - "993:993"
volumes:
  stalwart-data:
```

## Skip the setup wizard (declarative)

A fresh Stalwart starts a bootstrap wizard. A `config.json` holding only the data store skips it:

```json
{"@type":"RocksDb","path":"/var/lib/stalwart/"}
```

`STALWART_PUBLIC_URL` sets the public URL, which is also the OIDC issuer published at `/.well-known/openid-configuration`.

## The management credential

Authkit creates accounts and changes passwords through Stalwart's JMAP management API (`urn:stalwart:jmap`: `x:Domain`, `x:Account`). It authenticates with HTTP basic auth (`STALWART_ADMIN=user:password`) or a bearer token (`STALWART_ADMIN_TOKEN`).

- Dev: the recovery admin from `STALWART_RECOVERY_ADMIN` works in normal mode and is what the compose stack uses.
- Production: create a dedicated administrator account in the Stalwart web admin (`/admin`) and give Authkit only that credential. Remove the recovery admin variable once Stalwart is set up.

## The mail domain

Authkit creates the domain named by `AUTHKIT_DOMAIN` if it does not exist (`x:Domain/set`). Users sign up as `username@AUTHKIT_DOMAIN`. For real delivery set up the DNS records (MX, SPF, DKIM, DMARC) as the Stalwart docs describe.

## SMTP

Authkit sends its emails (verification, magic link, reset) through Stalwart:

- Same host or private network: `SMTP_ADDR=stalwart:25`, unauthenticated local delivery to your own domain.
- Submission with auth: `SMTP_ADDR=mail.example.com:587`, `SMTP_USER`, `SMTP_PASS` (STARTTLS), or `SMTP_TLS=true` on 465.

> Stalwart refuses the HELO name `localhost`; Authkit greets with the domain of `SMTP_FROM`.

## Authkit settings

- `AUTHKIT_SECRET`: at least 32 characters; signs sessions and email links.
- `AUTHKIT_PUBLIC_URL`: the browser-facing URL of Authkit (links in emails).
- `AUTHKIT_DOMAIN`: the mail domain accounts live in.
- `STALWART_URL`: how Authkit reaches Stalwart. `STALWART_ADMIN` or `STALWART_ADMIN_TOKEN`.
- `SMTP_ADDR`, `SMTP_FROM`, optional `SMTP_USER`, `SMTP_PASS`, `SMTP_TLS`, `SMTP_INSECURE`.
- `AUTHKIT_CLIENTS`: JSON list of relying parties allowed to use the OIDC handoff: `[{"id":"app","name":"My app","redirect_uris":["https://app.example.com/callback"]}]`.
- `AUTHKIT_REQUIRE_VERIFIED` (default true), `AUTHKIT_PRODUCT` (name in the header), `AUTHKIT_API_KEY` (protects the JSON API), `AUTHKIT_SOCIAL_STUBS`, `AUTHKIT_STORE` (state file), `AUTHKIT_ADDR` (listen address, default `:4000`).

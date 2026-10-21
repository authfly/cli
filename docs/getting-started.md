# Getting started

Authfly is a self-hosted sign-in kit in the spirit of WorkOS Authfly, built on **Stalwart**, the mail server with a built-in directory and OpenID Connect provider. Your users' accounts are mailboxes in Stalwart; Authfly adds the flows (sign up, sign in, magic link, verification, password reset, sign out, consent) and widgets for eight runtimes.

## Run it

```sh
npx authfly init                 # or: authfly init -y --target docker --policy gdpr --domain example.test --tls off ...
npx authfly deploy               # Stalwart + Authfly + Console, hardened; prints what it did
npx authfly doctor               # security, policy and integrity checks
```

This starts:

- **stalwart**: HTTP (JMAP management) on `127.0.0.1` only, plus the mail ports. The web admin is disabled.
  init-stalwart hardens it first ([Security](security.md)).
- **authfly** on the public URL: the hosted pages, the JSON API, `/api/v1/capabilities` (the `@authfly/core`
  flags) and the OIDC handoff.
- **console** on `127.0.0.1`: the private Authfly Console (built from authfly/stalwart).

See [Deploy](deploy.md) for the targets and the security model. The Stalwart dev stack (docker compose with fixed
dev secrets) lives in authfly/stalwart.

## Run the end-to-end test

The tests drive every flow over HTTP against a deployment and read the emails from the Stalwart mailbox over JMAP:

```sh
bun install && bash tools/deps.sh
bash tools/e2e-deploy.sh /path/to/deploy-dir     # flow, security, gdpr
```

Steps: stack up, sign up (account created in Stalwart), refused before verification, verification email and link, magic link, sign out, username + password, email + password, wrong password, password reset, OIDC SSO into the React demo with consent, deny, JSON API.

Suites: flow (15 steps), security (lock-down, 11), gdpr (11). The Console suite lives in authfly/stalwart.

## What is where

- `server/core`: Go core (Stalwart JMAP management, OIDC client with PKCE, SMTP mailer, signed tokens).
- `server/web`: hosted pages (templ) and the JSON API; `cmd/authfly`: the server binary.
- `server/deploy`, `cmd/authfly`: the `authfly` CLI (deploy, policy packs, upgrade, rollback, backup, doctor).
- `apps/demo-react`: the React demo (widgets from authfly/authkit, `@authfly/node` from authfly/authfly via `.deps/`).
- Widgets, the contract, the SDKs and the Stalwart dev stack / Console live in the sibling repos (README.md).

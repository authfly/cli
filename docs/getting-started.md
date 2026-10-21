# Getting started

Authkit is a self-hosted sign-in kit in the spirit of WorkOS AuthKit, built on **Stalwart**, the mail server with a built-in directory and OpenID Connect provider. Your users' accounts are mailboxes in Stalwart; Authkit adds the flows (sign up, sign in, magic link, verification, password reset, sign out, consent) and widgets for eight runtimes.

::preview sign-in

## Run the dev stack

You need Docker with Compose. From the repository root:

```sh
docker compose up -d --build
```

This starts these services:

- **stalwart**: HTTP (JMAP management, OAuth internals) on `127.0.0.1:8080` only, SMTP on `localhost:2525`, submissions on `4465`, IMAPS on `9993`. The web admin is disabled. A one-shot **stalwart-init** hardens it first ([Security](security.md)).
- **authkit** on `http://localhost:4000`: the Go server with the hosted pages (templ), the JSON API and the OIDC handoff.
- **demo-react** on `http://localhost:5173`: a React app that signs in with OpenID Connect (authorization code + PKCE) through Authkit.
- **console** on `http://127.0.0.1:4500`: the private [Authkit Console](console.md) (`console` / `dev-only-console-password`).

Open `http://localhost:4000/auth/sign-up`, create an account, then read the verification email in the new mailbox (any IMAP client on port 9993 with TLS, or JMAP). Then open `http://localhost:5173` and sign in.

> Dev only: the compose file pins secrets. Authkit uses the least-privilege service account `authkit-svc`; the recovery admin is used only by stalwart-init and the console. See [Install Stalwart](stalwart.md) for production settings.

## Run the end-to-end test

The test drives every flow over HTTP against the running stack and reads the emails from the Stalwart mailbox over JMAP:

```sh
bun install
bun e2e/flow.test.ts
```

Steps: stack up, sign up (account created in Stalwart), refused before verification, verification email and link, magic link, sign out, username + password, email + password, wrong password, password reset, OIDC SSO into the React demo with consent, deny, JSON API.

More tests: `bun e2e/security.test.ts` (lock-down, 11 steps), `bun e2e/console.test.ts` (19), `bun e2e/gdpr.test.ts` (11).

## What is where

- `server/core`: Go core (Stalwart JMAP management, OIDC client with PKCE, SMTP mailer, signed tokens).
- `server/web`: hosted pages (templ) and the JSON API; `cmd/authkit`: the server binary.
- `packages/ui/<runtime>`: the generated widgets for React, Svelte, Vue, Solid, templ, Twig, Latte and Jinja2.
- `packages/adapters`: adapters for apps (`ts` for Node and Bun, `php`, `python`).
- `specs/`: the widget specs fed to ui8kit/codegen; `tools/gen-ui.sh` regenerates `packages/ui`.
- `site/`: this documentation site (Go templ to static HTML); `apps/demo-react`: the React demo.

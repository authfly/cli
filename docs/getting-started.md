# Getting started

Authkit is a self-hosted sign-in kit in the spirit of WorkOS AuthKit, built on **Stalwart**, the mail server with a built-in directory and OpenID Connect provider. Your users' accounts are mailboxes in Stalwart; Authkit adds the flows (sign up, sign in, magic link, verification, password reset, sign out, consent) and widgets for eight runtimes.

::preview sign-in

## Run the dev stack

You need Docker with Compose. From the repository root:

```sh
docker compose up -d --build
```

This starts three services:

- **stalwart** on `http://localhost:8080` (JMAP, OAuth/OIDC, web admin), SMTP on `localhost:2525`, IMAP on `localhost:1143`.
- **authkit** on `http://localhost:4000`: the Go server with the hosted pages (templ), the JSON API and the OIDC handoff.
- **demo-react** on `http://localhost:5173`: a React app that signs in with OpenID Connect (authorization code + PKCE) through Authkit.

Open `http://localhost:4000/auth/sign-up`, create an account, then read the verification email in the new mailbox (any IMAP client on port 1143, or JMAP). Then open `http://localhost:5173` and sign in.

> Dev only: the compose file pins secrets and uses Stalwart's recovery admin as the management credential. See [Install Stalwart](stalwart.md) for production settings.

## Run the end-to-end test

The test drives every flow over HTTP against the running stack and reads the emails from the Stalwart mailbox over JMAP:

```sh
bun install
bun e2e/flow.test.ts
```

Steps: stack up, sign up (account created in Stalwart), refused before verification, verification email and link, magic link, sign out, username + password, email + password, wrong password, password reset, OIDC SSO into the React demo with consent, deny, JSON API.

## What is where

- `server/core`: Go core (Stalwart JMAP management, OIDC client with PKCE, SMTP mailer, signed tokens).
- `server/web`: hosted pages (templ) and the JSON API; `cmd/authkit`: the server binary.
- `packages/ui/<runtime>`: the generated widgets for React, Svelte, Vue, Solid, templ, Twig, Latte and Jinja2.
- `packages/adapters`: adapters for apps (`ts` for Node and Bun, `php`, `python`).
- `specs/`: the widget specs fed to ui8kit/codegen; `tools/gen-ui.sh` regenerates `packages/ui`.
- `site/`: this documentation site (Go templ to static HTML); `apps/demo-react`: the React demo.

# Authfly Console

A private configurator for Stalwart and Authfly (`apps/console`, Go and templ, built from the ui8kit primitives). It listens on `127.0.0.1:4500` only; see [Security](security.md) for the SSH tunnel.

```sh
docker compose up -d --build                     # includes the console
ssh -N -L 4500:127.0.0.1:4500 you@your-server    # on a remote server
open http://localhost:4500                       # sign in with CONSOLE_ADMIN
```

Local development without Docker: `bun run console` (needs `CONSOLE_ADMIN`, `CONSOLE_SECRET`, `STALWART_URL`, `STALWART_ADMIN`, `AUTHFLY_ADMIN_URL`, `AUTHFLY_ADMIN_KEY`).

## A configurator driven by the live schema

At start the console reads Stalwart's schema (`GET /api/schema`: 150 objects, 382 schemas, enums, forms, lists, layouts) and derives everything from it:

- **Navigation**: grouped like Stalwart's own admin layouts, plus "Other objects" for everything else. That gives 143 views covering every management object.
- **Forms**: one per object, with the sections and labels from the schema, controls matched to the field type, and the field description as help text.
- **Validation** against the schema before anything is sent: required fields, string length, email, URI, duration (`30s`, `7d`), size (`10mb`), numbers (whole, non-negative, ranges), enum values, references, RFC 3339 times, and JSON for nested objects. Invalid input returns the form with field errors, and nothing reaches Stalwart.
- **Prefill from live data**: reference fields become selects filled from the live objects (domains, roles, accounts, ...), and edit forms start from the current values. Only changed fields are sent, as a JMAP patch.
- **Explanations**: each object shows its description, permissions and edition, curated side effects (for example "changing name changes the address"), and the methods' effects.
- **Dependencies**: "uses" and "used by" are computed from the schema's references (for example `x:Account.domainId → Domain`), plus curated dependencies such as `requireClientRegistration` ↔ OAuth clients, or "the web UI needs the UpdateApps action".
- **Warnings**: destructive and GDPR actions show what will be lost and ask you to type the name to confirm. Personal-data objects carry a GDPR note.
- **Restricted objects** are explained instead of failing: Enterprise-only, per-account, set-only, and log store missing.

## Views

- **Dashboard**: counts, live lock-down checks (with "Re-apply hardening"), scenarios.
- **Users**: list, create (domain and role prefilled), edit name and password (a new password signs the user out of Authfly everywhere), sign out everywhere, export, erase, delete. Shows Authfly's view of the person: verification, consents, audit trail. The service account is flagged.
- **Domains, Groups, OIDC clients, Roles, Mail queue**, and every other object: the schema-driven list, create, edit and delete pages.
- **Request builder**: any object and method (`get`, `query`, `set`, `changes`), a body template generated from the schema, JSON and capability checks, confirmation for `destroy`, a response viewer with status and timing, curl export (password kept as `$STALWART_ADMIN_PASSWORD`), and saved requests.
- **Scenarios**: "Onboard an application" creates a user, registers an OIDC client, runs a real authorization-code + PKCE sign-in, calls userinfo and verifies the ID token signature. It stops at the first failing step and says how to fix it.
- **GDPR**: Stalwart and Authfly retention, encryption at rest, requests by person, "Run retention now".
- **Logs and audit**: console actions and the Authfly audit log, both with hash-chain status; the Stalwart log when a log store exists.

## Settings

| Variable | Meaning |
| --- | --- |
| `CONSOLE_ADDR` | listen address (default `127.0.0.1:4500`; `:4500` inside the container, published as `127.0.0.1:4500`) |
| `CONSOLE_ADMIN` | `user:password` of the console admin |
| `CONSOLE_SECRET` | at least 32 characters; signs the session |
| `CONSOLE_DATA` | audit log and saved requests |
| `STALWART_URL`, `STALWART_ADMIN` | Stalwart management (admin credential) |
| `AUTHFLY_ADMIN_URL`, `AUTHFLY_ADMIN_KEY` | Authfly's internal admin API |
| `AUTHFLY_DOMAIN`, `AUTHFLY_PUBLIC_URL`, `AUTHFLY_SERVICE_NAME` | defaults and hints |

## Tests

`bun e2e/console.test.ts` (19 steps) covers:

- the console answers on localhost and is closed on the public address;
- redirects without a session;
- login CSRF and the wrong password;
- live lock-down checks;
- requests without CSRF or cross-site are refused;
- validation;
- user create, edit and delete, verified in Stalwart, including that the new password works and the old one does not;
- generic form create, patch and delete;
- request builder: send, curl and save; invalid JSON is rejected; destroy asks for confirmation;
- the onboarding scenario passes;
- the audit log is complete;
- all 143 views render;
- sign out.

Screenshots: `node e2e/console-shots.mjs` writes `/workspace/authfly-shots/console-*.png` (11 pages × light/dark × 390/1440).

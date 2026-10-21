## How the surface is organised (v0.16)

- **There is no REST management API in v0.16.** The pre-0.16 REST routes (`/api/principal`, `/api/management`, …) answer 404. Configuration, directory, queue, reports, logs and tasks are JMAP objects with the `x:` prefix under capability `urn:stalwart:jmap`, posted to **`/jmap`** (the docs' narrative mentions `/api` for management; live, `/api` only holds the helpers below).
- `/api/*` holds a handful of helpers: `/api/auth` (credential check that issues an OAuth code), `/api/discover/{email}`, `/api/account` (effective permissions), `/api/schema` (the full configuration schema: objects, fields, forms, list columns, navigation layout, enums), `/api/token/{kind}` and `/api/live/*` (SSE).
- OAuth / OIDC lives under `/auth/*` and `/.well-known/*`. The bundled web UI is an `x:Application` served at `/admin` and `/account`.
- Every object method is a permission: `sys<Object><Get|Query|Create|Update|Destroy>`, `action<Name>`, `task<Name>`, `jmap<Object><Method>`, protocol permissions (`imap*`, `pop3*`, `dav*`, `sieve*`) and specials (`impersonate`, `fetchAnyBlob`, `liveTracing`, …). An account can never grant permissions it does not hold (verified: a service role without the User permissions cannot create user accounts; an admin-role grant is refused).

## Findings that matter for Authkit

- `/api/auth` answers `client_code` (docs: `clientCode`); a bare account name fails without a default domain.
- **Dynamic client registration is anonymous by default** (`POST /auth/register` answered 201 with a stateless `swc1.` client id) and **unregistered client ids are accepted** (`x:OidcProvider.anonymousClientRegistration=true`, `requireClientRegistration=false`). Authkit's hardening turns both off and registers its relying parties as `x:OAuthClient`.
- Disabling the web UI (`x:Application.enabled=false`) takes effect on restart or after `x:Action` `UpdateApps` (verified: `/admin/` 200 → 404). `ReloadSettings` alone does not stop serving it.
- Stalwart also listens on HTTPS `:443` inside the container (listener `https`); the compose file publishes neither 443 nor 8080 publicly.
- `/auth/device` is anonymous and issues device codes; it is not proxied by Authkit.
- An administrator (or a role with `impersonate`) can call JMAP mail methods with another account's `accountId` (the x:Account id): this is how the GDPR export reads a mailbox without the user's password.
- Enterprise-only in this build (answer `forbidden … Enterprise edition`): `x:ArchivedItem` (undelete), `x:Trace` (delivery history), `x:Metric`, `x:MaskedEmail`; `/api/live/tracing|metrics` and `/api/token/tracing|metrics` answer 404. `x:Log` answers `serverUnavailable` while no tracer stores logs (the compose stack logs to stdout).
- `x:ApiKey` and `x:AppPassword` are per account (queried as the account itself, not as admin).

## GDPR map

| Need | Stalwart surface | Status |
|---|---|---|
| Export (Art. 15, 20) | JMAP as the user or with `impersonate`: `Mailbox/get`, `Email/query` + `Email/get` (+ blobs), `Identity/get`, `SieveScript/*`, `AddressBook`/`ContactCard`, `Calendar`/`CalendarEvent`, `VacationResponse`; `x:Account/get` for the directory record | live (Authkit export uses x:Account + Mailbox + Email + Identity) |
| Erasure (Art. 17) | `x:Account/set destroy` removes the account and its data; `x:DataRetention.archiveDeletedAccountsFor` (null = no archive) decides whether a copy is kept; `x:ArchivedItem` (Enterprise) lists archives | live (see docs/gdpr.md for the verification) |
| Retention (Art. 5(1)(e)) | `x:DataRetention`: trash and submission expunge, `holdTracesFor`, `holdMetricsFor`, `holdMtaReportsFor`, archive periods; schedules | live |
| Audit log (Art. 30, 32) | `x:Log` (needs a log store), `x:Trace` (Enterprise), webhooks `x:WebHook`; Authkit keeps its own append-only audit log | live: Stalwart logs not stored in the dev stack |
| Consent records (Art. 7) | none in Stalwart; Authkit stores consent records (OIDC consent, terms at sign-up) | Authkit |
| Encryption at rest (Art. 32) | `x:Email.encryptAtRest` (allow), per account `encryptionAtRest` (`Aes128`, `Aes256` OpenPGP or S/MIME with the user's `publicKey`, `encryptOnAppend`); disk/database encryption is outside Stalwart | live (settings); see docs/gdpr.md |
| Access restriction (Art. 32) | roles (`x:Role`), permissions, tenants (`x:Tenant`), `x:Security` bans, `x:AllowedIp`/`x:BlockedIp`, `x:Http.allowedEndpoints` | live |

# Stalwart API audit (v0.16)

Captured live from `stalwartlabs/stalwart:v0.16` (community edition) at 2026-10-21T10:17:54+0300 by `tools/stalwart-audit.py`, after `authfly init-stalwart` hardened it (so `/auth/register` is refused and `/admin/` is 404 here; the defaults before hardening are described below); regenerate with `python3 tools/stalwart-audit.py && python3 tools/stalwart-api-doc.py`. Raw captures: `docs/api-capture/probe.json` (requests and responses, secrets redacted) and `docs/api-capture/schema.json` (the server's own configuration schema).

## Coverage

- HTTP endpoints: **29** requested live (17 answered 2xx/3xx, the rest with the documented error or 404).
- Management object types (`x:*` over JMAP): **117**, all probed live: **109** answered get/query, **8** answered with a documented restriction (Enterprise only, per-account, set only, store not configured).
- JMAP user-data object types (Email, Mailbox, …): **6**, docs-only here (standard JMAP; Authfly uses Email/query and Email/get live in the e2e test).
- JMAP data objects reachable (from the method permissions): see the JMAP section.
- Permissions: **623** (one per object method), from `GET /api/account`.

## How the surface is organised (v0.16)

- **There is no REST management API in v0.16.** The pre-0.16 REST routes (`/api/principal`, `/api/management`, …) answer 404. Configuration, directory, queue, reports, logs and tasks are JMAP objects with the `x:` prefix under capability `urn:stalwart:jmap`, posted to **`/jmap`** (the docs' narrative mentions `/api` for management; live, `/api` only holds the helpers below).
- `/api/*` holds a handful of helpers: `/api/auth` (credential check that issues an OAuth code), `/api/discover/{email}`, `/api/account` (effective permissions), `/api/schema` (the full configuration schema: objects, fields, forms, list columns, navigation layout, enums), `/api/token/{kind}` and `/api/live/*` (SSE).
- OAuth / OIDC lives under `/auth/*` and `/.well-known/*`. The bundled web UI is an `x:Application` served at `/admin` and `/account`.
- Every object method is a permission: `sys<Object><Get|Query|Create|Update|Destroy>`, `action<Name>`, `task<Name>`, `jmap<Object><Method>`, protocol permissions (`imap*`, `pop3*`, `dav*`, `sieve*`) and specials (`impersonate`, `fetchAnyBlob`, `liveTracing`, …). An account can never grant permissions it does not hold (verified: a service role without the User permissions cannot create user accounts; an admin-role grant is refused).

## Findings that matter for Authfly

- `/api/auth` answers `client_code` (docs: `clientCode`); a bare account name fails without a default domain.
- **Dynamic client registration is anonymous by default** (`POST /auth/register` answered 201 with a stateless `swc1.` client id) and **unregistered client ids are accepted** (`x:OidcProvider.anonymousClientRegistration=true`, `requireClientRegistration=false`). Authfly's hardening turns both off and registers its relying parties as `x:OAuthClient`.
- Disabling the web UI (`x:Application.enabled=false`) takes effect on restart or after `x:Action` `UpdateApps` (verified: `/admin/` 200 → 404). `ReloadSettings` alone does not stop serving it.
- Stalwart also listens on HTTPS `:443` inside the container (listener `https`); the compose file publishes neither 443 nor 8080 publicly.
- `/auth/device` is anonymous and issues device codes; it is not proxied by Authfly.
- An administrator (or a role with `impersonate`) can call JMAP mail methods with another account's `accountId` (the x:Account id): this is how the GDPR export reads a mailbox without the user's password.
- Enterprise-only in this build (answer `forbidden … Enterprise edition`): `x:ArchivedItem` (undelete), `x:Trace` (delivery history), `x:Metric`, `x:MaskedEmail`; `/api/live/tracing|metrics` and `/api/token/tracing|metrics` answer 404. `x:Log` answers `serverUnavailable` while no tracer stores logs (the compose stack logs to stdout).
- `x:ApiKey` and `x:AppPassword` are per account (queried as the account itself, not as admin).

## GDPR map

| Need | Stalwart surface | Status |
|---|---|---|
| Export (Art. 15, 20) | JMAP as the user or with `impersonate`: `Mailbox/get`, `Email/query` + `Email/get` (+ blobs), `Identity/get`, `SieveScript/*`, `AddressBook`/`ContactCard`, `Calendar`/`CalendarEvent`, `VacationResponse`; `x:Account/get` for the directory record | live (Authfly export uses x:Account + Mailbox + Email + Identity) |
| Erasure (Art. 17) | `x:Account/set destroy` removes the account and its data; `x:DataRetention.archiveDeletedAccountsFor` (null = no archive) decides whether a copy is kept; `x:ArchivedItem` (Enterprise) lists archives | live (see docs/gdpr.md for the verification) |
| Retention (Art. 5(1)(e)) | `x:DataRetention`: trash and submission expunge, `holdTracesFor`, `holdMetricsFor`, `holdMtaReportsFor`, archive periods; schedules | live |
| Audit log (Art. 30, 32) | `x:Log` (needs a log store), `x:Trace` (Enterprise), webhooks `x:WebHook`; Authfly keeps its own append-only audit log | live: Stalwart logs not stored in the dev stack |
| Consent records (Art. 7) | none in Stalwart; Authfly stores consent records (OIDC consent, terms at sign-up) | Authfly |
| Encryption at rest (Art. 32) | `x:Email.encryptAtRest` (allow), per account `encryptionAtRest` (`Aes128`, `Aes256` OpenPGP or S/MIME with the user's `publicKey`, `encryptOnAppend`); disk/database encryption is outside Stalwart | live (settings); see docs/gdpr.md |
| Access restriction (Art. 32) | roles (`x:Role`), permissions, tenants (`x:Tenant`), `x:Security` bans, `x:AllowedIp`/`x:BlockedIp`, `x:Http.allowedEndpoints` | live |


## HTTP endpoints

| Method | Path | Auth | Live status | Purpose | Source |
|---|---|---|---|---|---|
| GET | `/.well-known/openid-configuration` | anonymous | 200 | OIDC discovery | docs: auth/openid |
| GET | `/.well-known/oauth-authorization-server` | anonymous | 200 | OAuth metadata (RFC 8414) | docs: auth/oauth/endpoints |
| GET | `/auth/jwks.json` | anonymous | 200 | JSON Web Key Set | docs: auth/openid |
| POST | `/auth/token` | anonymous | 400 | Token endpoint (code, refresh, device) | docs: auth/oauth/endpoints |
| GET | `/auth/userinfo` | anonymous | 401 | UserInfo (bearer) | docs: auth/openid |
| POST | `/auth/introspect` | admin basic/bearer | 200 | Token introspection (RFC 7662) | docs: auth/oauth/endpoints |
| POST | `/auth/device` | anonymous | 200 | Device authorization (RFC 8628) | docs: auth/oauth/endpoints |
| POST | `/auth/register` | anonymous | 401 | Dynamic client registration (RFC 7591) | docs: auth/oauth/client-registration |
| POST | `/api/auth` | anonymous | 401 | Credential check, issues an authorization code | docs: development/api |
| GET | `/api/discover/admin@authfly.test` | anonymous | 200 | OIDC discovery per address | docs: development/api |
| GET | `/api/account` | admin basic/bearer | 200 | Effective permissions, edition, locale | docs: development/api |
| GET | `/api/schema` | admin basic/bearer | 302 | Configuration schema (redirect to hash) | docs: development/api |
| GET | `/api/token/delivery` | admin basic/bearer | 200 | Short-lived SSE token (delivery) | docs: development/api |
| GET | `/api/token/tracing` | admin basic/bearer | 404 | SSE token tracing (Enterprise) | docs: development/api |
| GET | `/api/token/metrics` | admin basic/bearer | 404 | SSE token metrics (Enterprise) | docs: development/api |
| GET | `/api/live/delivery/authfly.test` | admin basic/bearer | 200 | Live delivery test (SSE) | docs: development/api |
| GET | `/api/live/tracing` | admin basic/bearer | 404 | Live tracing (Enterprise, SSE) | docs: development/api |
| GET | `/api/live/metrics` | admin basic/bearer | 404 | Live metrics (Enterprise, SSE) | docs: development/api |
| GET | `/jmap/session` | admin basic/bearer | 200 | JMAP session (RFC 8620) | docs: development (JMAP) |
| POST | `/jmap` | admin basic/bearer | 200 | JMAP API (mail data and x: management objects) | docs: development (JMAP) |
| GET | `/admin` | anonymous | 302 | Web admin (x:Application urlPrefix /admin) | live: x:Application |
| GET | `/account` | anonymous | 302 | Self-service web UI (x:Application urlPrefix /account) | live: x:Application |
| GET | `/` | anonymous | 404 | Root (x:Http redirectRoot) | docs: ref/object/http |
| GET | `/api/management` | admin basic/bearer | 404 | Pre-0.16 REST management (removed?) | older docs |
| GET | `/api/principal` | admin basic/bearer | 404 | Pre-0.16 REST principals (removed?) | older docs |
| GET | `/healthz/live` | anonymous | 200 | Health check | docs: install (Docker healthcheck) |
| GET | `/healthz/ready` | anonymous | 200 | Readiness check | docs: install |
| GET | `/metrics/prometheus` | anonymous | 404 | Prometheus scrape (x:Metrics/CollectorPrometheus) | schema: x:Metrics |
| GET | `/robots.txt` | anonymous | 200 | robots | probe |

### Captured examples

`GET /.well-known/openid-configuration`

```json
{
 "issuer": "http://localhost:4000",
 "authorization_endpoint": "http://localhost:4000/login",
 "token_endpoint": "[redacted]",
 "userinfo_endpoint": "http://localhost:4000/auth/userinfo",
 "jwks_uri": "http://localhost:4000/auth/jwks.json",
 "registration_endpoint": "http://localhost:4000/auth/register",
 "device_authorization_endpoint": "http://localhost:4000/auth/device",
 "scopes_supported": [
  "openid",
  "offline_access",
  "urn:ietf:params:oauth:scope:mail",
  "\u2026"
 ],
 "response_types_supported": [
  "code"
 ],
 "subject_types_supported": [
  "public"
 ],
 "grant_types_supported"
…
```

`GET /.well-known/oauth-authorization-server`

```json
{
 "issuer": "http://localhost:4000",
 "token_endpoint": "[redacted]",
 "authorization_endpoint": "http://localhost:4000/login",
 "device_authorization_endpoint": "http://localhost:4000/auth/device",
 "registration_endpoint": "http://localhost:4000/auth/register",
 "introspection_endpoint": "http://localhost:4000/auth/introspect",
 "grant_types_supported": [
  "authorization_code",
  "refresh_token",
  "urn:ietf:params:oauth:grant-type:device_code"
 ],
 "response_types_supported": [
  "code"
 ],
 "scopes_supported": [
  "openid",
  "offline_access",
  "urn:ietf:params:oauth:scope:mail",
  "\u2
…
```

`GET /auth/jwks.json`

```json
{
 "keys": [
  {
   "use": "sig",
   "alg": "ES256",
   "kid": "default",
   "kty": "EC",
   "crv": "P-256",
   "x": "hCBWtr8x2I9YCjeqw8iALcjP_FoHOZfa68ztpPbSisA",
   "y": "W3Sph68QZl_CvUfD7U14KCABaVHdnPI1UzhMWV4HMqg"
  }
 ]
}
```

`POST /auth/introspect` with `"token=invalid"`

```json
{
 "active": false
}
```

`POST /auth/device` with `"client_id=probe"`

```json
{
 "device_code": "sUONfmVdBNBpuOQGe6jJmFhllusAga5quyJhK5St",
 "user_code": "3Q9L-8M4A",
 "verification_uri": "http://localhost:4000/device",
 "verification_uri_complete": "http://localhost:4000/device/?code=3Q9L-8M4A",
 "expires_in": 1800,
 "interval": 5
}
```

`GET /api/discover/admin@authfly.test`

```json
{
 "issuer": "",
 "authorization_endpoint": "/login",
 "token_endpoint": "[redacted]",
 "userinfo_endpoint": "/auth/userinfo",
 "jwks_uri": "/auth/jwks.json",
 "registration_endpoint": "/auth/register",
 "device_authorization_endpoint": "/auth/device",
 "scopes_supported": [
  "openid",
  "offline_access",
  "urn:ietf:params:oauth:scope:mail",
  "\u2026"
 ],
 "response_types_supported": [
  "code"
 ],
 "subject_types_supported": [
  "public"
 ],
 "grant_types_supported": [
  "authorization_code",
  "refresh_token",
  "urn:ietf:params:oauth:grant-type:device_code"
 ],
 "token_endpoint_auth_meth
…
```

`GET /api/account`

```json
{
 "permissions": [
  "jmapPrincipalCreate",
  "jmapSieveScriptDestroy",
  "jmapSieveScriptUpdate",
  "\u2026"
 ],
 "edition": "community",
 "locale": "en-US"
}
```

`GET /jmap/session`

```json
{
 "capabilities": {
  "urn:ietf:params:jmap:core": {
   "maxSizeUpload": 50000000,
   "maxConcurrentUpload": 4,
   "maxSizeRequest": 10000000,
   "maxConcurrentRequests": 4,
   "maxCallsInRequest": 16,
   "maxObjectsInGet": 500,
   "maxObjectsInSet": 500,
   "collationAlgorithms": [
    "i;ascii-numeric",
    "i;ascii-casemap",
    "i;unicode-casemap"
   ]
  },
  "urn:ietf:params:jmap:mail": {},
  "urn:ietf:params:jmap:calendars": {},
  "urn:ietf:params:jmap:calendars:parse": {},
  "urn:ietf:params:jmap:contacts": {},
  "urn:ietf:params:jmap:contacts:parse": {},
  "urn:ietf:params:jmap:fileno
…
```

`POST /jmap` with `{"using": ["urn:ietf:params:jmap:core"], "methodCalls": [["Core/echo", {"probe": true}, "e"]]}`

```json
{
 "methodResponses": [
  [
   "Core/echo",
   {
    "probe": true
   },
   "e"
  ]
 ],
 "sessionState": "df70323a"
}
```

`GET /healthz/live`

```json
{
 "detail": "OK",
 "status": 200,
 "title": "OK",
 "type": "about:blank"
}
```

`GET /healthz/ready`

```json
{
 "detail": "OK",
 "status": 200,
 "title": "OK",
 "type": "about:blank"
}
```


## JMAP data methods (user data)

Standard JMAP (RFC 8620 core, RFC 8621 mail, RFC 9610 contacts, calendars, file node, sieve, quota drafts) at `POST /jmap`, authenticated as the account or with `impersonate` and the target `accountId`. Methods as permissions of the admin; docs-only except Email/query, Email/get, Mailbox/get, Identity/get (used live by Authfly's e2e test and GDPR export).

| Object | Methods |
|---|---|
| `AddressBook` | Changes, Create, Destroy, Get, Update |
| `Blob` | Copy, Get, Lookup, Upload |
| `Calendar` | Changes, Create, Destroy, Get, Update |
| `CalendarEvent` | Changes, Copy, Create, Destroy, Get, Parse, Query, QueryChanges, Update |
| `CalendarEventNotification` | Changes, Create, Destroy, Get, Query, QueryChanges, Update |
| `ContactCard` | Changes, Copy, Create, Destroy, Get, Parse, Query, QueryChanges, Update |
| `Core` | Echo |
| `Email` | Changes, Copy, Create, Destroy, Get, Import, Parse, Query, QueryChanges, Update |
| `EmailSubmission` | Changes, Create, Destroy, Get, Query, QueryChanges, Update |
| `FileNode` | Changes, Copy, Create, Destroy, Get, Query, QueryChanges, Update |
| `Identity` | Changes, Create, Destroy, Get, Update |
| `Mailbox` | Changes, Create, Destroy, Get, Query, QueryChanges, Update |
| `ParticipantIdentity` | Changes, Create, Destroy, Get, Update |
| `Principal` | Create, Destroy, Update |
| `PushSubscription` | Create, Destroy, Get, Update |
| `Quota` | Changes, Get, Query, QueryChanges |
| `SearchSnippet` | Get |
| `ShareNotification` | Changes, Create, Destroy, Get, Query, QueryChanges, Update |
| `SieveScript` | Create, Destroy, Get, Query, Update, Validate |
| `Thread` | Changes, Get |
| `VacationResponse` | Create, Destroy, Get, Update |

## Management objects (JMAP `x:*`)

All calls: `POST /jmap`, admin auth (basic or bearer), `using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]`. Objects take `x:<Name>/get`, `/query`, `/set` (create, update, destroy) and `/changes`; singletons take `/get` and `/set` with the id `singleton`. Methods listed are the admin's permitted operations.


### Account / Address Books

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `AddressBook` | object | Get, Create, Update, Destroy | docs-only | A named collection of contact cards belonging to an account. |

### Account / Archived Items

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:ArchivedItem` | object | Get, Query, Create, Update, Destroy | live: Enterprise only | Represents an archived item that can be restored. |

### Account / Calendars

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `Calendar` | object | Get, Create, Update, Destroy | docs-only | A named collection of calendar events belonging to an account. |

### Account / Credentials / API Keys

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:ApiKey` | object | - | live: per account | API key credential for programmatic access. |

### Account / Credentials / App Passwords

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:AppPassword` | object | - | live: per account | App password credential for programmatic access. |

### Account / Credentials / Password

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:AccountPassword` | singleton | - | live | Password-based authentication credential. |

### Account / Mailboxes

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `Mailbox` | object | Get, Query, Create, Update, Destroy | docs-only | Represents a named set of emails, analogous to a folder or label in other systems. |

### Account / Masked Addresses

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MaskedEmail` | object | Get, Query, Create, Update, Destroy | live: Enterprise only | Defines a masked email address for privacy protection. |

### Account / Public Keys

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:PublicKey` | object | Get, Query, Create, Update, Destroy | live | Defines a public key for email encryption (OpenPGP or S/MIME). |

### Account / Settings

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:AccountSettings` | singleton | - | live | Configures default account settings for locale and encryption. |

### Account / Sieve Scripts

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `SieveScript` | object | Get, Query, Create, Update, Destroy | docs-only | Defines a Sieve filter script that processes incoming messages for the account. |

### Account / Spam Samples

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamTrainingSample` | object | Get, Query, Create, Update, Destroy | live | Stores an email sample used for spam classifier training. |

### Account / Vacation Response

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `VacationResponse` | singleton | Get, Create, Update, Destroy | docs-only | Configures an automatic reply sent when messages are delivered while the user is away. |

### JMAP (user data)

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `Principal` | object | Create, Update, Destroy | docs-only | Represents an entity that can own or share resources, such as a user, group, resource, or location. |

### Management / Actions

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Action` | object | Get, Query, Create, Update, Destroy | live: set only | Defines server management actions such as reloads, troubleshooting and cache operations. |

### Management / Cluster

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:ClusterNode` | object | Get, Query | live | Represents a node in the cluster |

### Management / Directory / Accounts

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Account` | object | Get, Query, Create, Update, Destroy | live | Defines a user or group account for authentication and email access. |

### Management / Directory / Mailing Lists

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MailingList` | object | Get, Query, Create, Update, Destroy | live | Defines a mailing list that distributes messages to a group of recipients. |

### Management / Directory / OAuth Clients

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:OAuthClient` | object | Get, Query, Create, Update, Destroy | live | Defines a registered OAuth client application. |

### Management / Directory / Roles

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Role` | object | Get, Query, Create, Update, Destroy | live | Defines a named set of permissions that can be assigned to accounts, groups, or tenants. |

### Management / Directory / Tenants

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Tenant` | object | Get, Query, Create, Update, Destroy | live | Defines a tenant for multi-tenant environments with isolated resources and quotas. |

### Management / Domains / DKIM Signatures

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DkimSignature` | object | Get, Query, Create, Update, Destroy | live | Defines a DKIM signature used to sign outgoing email messages. |

### Management / Domains / Domains

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Domain` | object | Get, Query, Create, Update, Destroy | live | Defines an email domain and its DNS, DKIM, and TLS certificate settings. |

### Management / Emails / History / Inbound Delivery

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Trace` | object | Get, Query, Create, Update, Destroy | live: Enterprise only | Stores a message delivery trace with associated events. |

### Management / Emails / Queued

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:QueuedMessage` | object | Get, Query, Update, Destroy | live | Represents a queued email message pending delivery. |

### Management / Observability / Logs

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Log` | object | Get, Query | live: store not configured | Represents a server log entry. |

### Management / Reports / Inbox / ARF

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:ArfExternalReport` | object | Get, Query, Destroy | live | Stores an ARF feedback report received from an external source. |

### Management / Reports / Inbox / DMARC

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DmarcExternalReport` | object | Get, Query, Destroy | live | Stores a DMARC aggregate report received from an external source. |

### Management / Reports / Inbox / TLS

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:TlsExternalReport` | object | Get, Query, Destroy | live | Stores a TLS aggregate report received from an external source. |

### Management / Reports / Outbox / DMARC

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DmarcInternalReport` | object | Get, Query, Destroy | live | Stores an outbound DMARC aggregate report pending delivery. |

### Management / Reports / Outbox / TLS

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:TlsInternalReport` | object | Get, Query, Destroy | live | Stores an outbound TLS aggregate report pending delivery. |

### Management / Tasks / Scheduled

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Task` | object | Get, Query, Create, Update, Destroy | live | Represents a background task scheduled for execution. |

### Other

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Bootstrap` | singleton | - | live | Initial setup shown the first time Stalwart starts. Configures the server's identity, storage, user accounts, logging, and DNS management. |
| `x:Metric` | object | Get, Query, Create, Update, Destroy | live: Enterprise only | Stores a collected server metric data point. |

### Settings / AI

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:AiModel` | object | Get, Query, Create, Update, Destroy | live | Defines an AI model endpoint for LLM-based features. |

### Settings / Authentication / Directories

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Directory` | object | Get, Query, Create, Update, Destroy | live | Defines an external directory for account authentication and lookups. |

### Settings / Authentication / General

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Authentication` | singleton | Get, Update | live | Configures authentication settings including password policies and default roles. |

### Settings / Authentication / OIDC Provider

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:OidcProvider` | singleton | Get, Update | live | Configures the OAuth and OpenID Connect provider settings. |

### Settings / Calendar & Contacts / Address Book

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:AddressBook` | singleton | Get, Update | live | Configures address book and contact storage settings. |

### Settings / Calendar & Contacts / Alarms

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:CalendarAlarm` | singleton | Get, Update | live | Configures calendar alarm email notifications. |

### Settings / Calendar & Contacts / Calendar

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Calendar` | singleton | Get, Update | live | Configures calendar settings including iCalendar limits and default names. |

### Settings / Calendar & Contacts / Scheduling

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:CalendarScheduling` | singleton | Get, Update | live | Configures calendar scheduling, iTIP messaging, and HTTP RSVP settings. |

### Settings / Cluster / Coordinator

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Coordinator` | singleton | Get, Update | live | Configures the cluster coordinator for inter-node communication. |

### Settings / Cluster / Roles

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:ClusterRole` | object | Get, Query, Create, Update, Destroy | live | Defines a cluster node role with enabled tasks and listeners. |

### Settings / Email / Storage

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Email` | singleton | Get, Update | live | Configures email message limits, encryption, compression, and default folder settings. |

### Settings / Enterprise

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Enterprise` | singleton | Get, Update | live | Configures enterprise licensing and branding settings. |

### Settings / Files & Sharing / File Storage

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:FileStorage` | singleton | Get, Update | live | Configures file storage limits. |

### Settings / Files & Sharing / Sharing

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Sharing` | singleton | Get, Update | live | Configures sharing settings for calendars, address books, and files. |

### Settings / Lookups / HTTP Lists

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:HttpLookup` | object | Get, Query, Create, Update, Destroy | live | Defines an HTTP-based lookup list. |

### Settings / Lookups / In-Memory Key-Values

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MemoryLookupKeyValue` | object | Get, Query, Create, Update, Destroy | live | Defines an in-memory lookup key-value pair. |

### Settings / Lookups / Store Lookups

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:StoreLookup` | object | Get, Query, Create, Update, Destroy | live | Defines an external store used for lookups. |

### Settings / MTA / Filters / MTA Hooks

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaHook` | object | Get, Query, Create, Update, Destroy | live | Defines an MTA hook endpoint for message processing. |

### Settings / MTA / Filters / Milters

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaMilter` | object | Get, Query, Create, Update, Destroy | live | Defines a Milter filter endpoint for message processing. |

### Settings / MTA / Inbound / MTA-STS

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaSts` | singleton | Get, Update | live | Configures the MTA-STS policy for the server. |

### Settings / MTA / Inbound / Sender Authentication

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SenderAuth` | singleton | Get, Update | live | Configures sender authentication verification including DKIM, SPF, DMARC, and ARC. |

### Settings / MTA / Inbound / Session

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaInboundSession` | singleton | Get, Update | live | Configures inbound SMTP session timeouts and transfer limits. |

### Settings / MTA / Outbound / Connection Strategies

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaConnectionStrategy` | object | Get, Query, Create, Update, Destroy | live | Defines a connection strategy for outbound message delivery. |

### Settings / MTA / Outbound / Delivery Schedules

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaDeliverySchedule` | object | Get, Query, Create, Update, Destroy | live | Defines retry and notification intervals for message delivery. |

### Settings / MTA / Outbound / Routes

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaRoute` | object | Get, Query, Create, Update, Destroy | live | Defines a routing rule for outbound message delivery. |

### Settings / MTA / Outbound / Strategy

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaOutboundStrategy` | singleton | Get, Update | live | Configures outbound message delivery routing, scheduling, and TLS strategies. |

### Settings / MTA / Outbound / TLS Strategies

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaTlsStrategy` | object | Get, Query, Create, Update, Destroy | live | Defines a TLS security strategy for outbound connections. |

### Settings / MTA / Outbound / Virtual Queues

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaVirtualQueue` | object | Get, Query, Create, Update, Destroy | live | Defines a virtual queue for organizing outbound message delivery. |

### Settings / MTA / Rates & Quotas / Inbound Rate Limits

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaInboundThrottle` | object | Get, Query, Create, Update, Destroy | live | Defines an inbound rate limit rule for SMTP connections. |

### Settings / MTA / Rates & Quotas / Outbound Rate Limits

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaOutboundThrottle` | object | Get, Query, Create, Update, Destroy | live | Defines an outbound rate limit rule for message delivery. |

### Settings / MTA / Rates & Quotas / Queue Quotas

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaQueueQuota` | object | Get, Query, Create, Update, Destroy | live | Defines a quota rule for message queues. |

### Settings / MTA / Reports / DKIM

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DkimReportSettings` | singleton | Get, Update | live | Configures DKIM authentication failure report generation. |

### Settings / MTA / Reports / DMARC

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DmarcReportSettings` | singleton | Get, Update | live | Configures DMARC aggregate and failure report generation. |

### Settings / MTA / Reports / DSN

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DsnReportSettings` | singleton | Get, Update | live | Configures Delivery Status Notification (DSN) report generation. |

### Settings / MTA / Reports / General

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:ReportSettings` | singleton | Get, Update | live | Configures inbound report analysis and outbound report settings. |

### Settings / MTA / Reports / SPF

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpfReportSettings` | singleton | Get, Update | live | Configures SPF authentication failure report generation. |

### Settings / MTA / Reports / TLS

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:TlsReportSettings` | singleton | Get, Update | live | Configures TLS aggregate report generation. |

### Settings / MTA / Session / AUTH Stage

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaStageAuth` | singleton | Get, Update | live | Configures SMTP authentication requirements and error handling. |

### Settings / MTA / Session / Connect Stage

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaStageConnect` | singleton | Get, Update | live | Configures SMTP connection greeting and hostname settings. |

### Settings / MTA / Session / DATA Stage

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaStageData` | singleton | Get, Update | live | Configures message processing rules for the SMTP DATA stage. |

### Settings / MTA / Session / EHLO Stage

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaStageEhlo` | singleton | Get, Update | live | Configures EHLO command requirements and validation. |

### Settings / MTA / Session / Extensions

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaExtensions` | singleton | Get, Update | live | Configures SMTP protocol extensions offered to clients. |

### Settings / MTA / Session / MAIL FROM Stage

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaStageMail` | singleton | Get, Update | live | Configures MAIL FROM stage processing and sender validation. |

### Settings / MTA / Session / RCPT TO Stage

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MtaStageRcpt` | singleton | Get, Update | live | Configures RCPT TO stage processing and recipient validation. |

### Settings / Network / ASN & GeoIP

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Asn` | singleton | Get, Update | live | Configures ASN and geolocation data sources for IP address lookups. |

### Settings / Network / DNS / DNS Providers

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DnsServer` | object | Get, Query, Create, Update, Destroy | live | Defines a DNS server for automatic record management. |

### Settings / Network / DNS / DNS Resolver

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DnsResolver` | singleton | Get, Update | live | Configures the DNS resolver used for domain lookups. |

### Settings / Network / General

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SystemSettings` | singleton | Get, Update | live | Configures core server settings including hostname, thread pool, and network services. |

### Settings / Network / HTTP / Contact Form

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:HttpForm` | singleton | Get, Update | live | Configures the contact form submission endpoint. |

### Settings / Network / HTTP / General

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Http` | singleton | Get, Update | live | Configures HTTP server settings including rate limiting, CORS, and security headers. |

### Settings / Network / IMAP

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Imap` | singleton | Get, Update | live | Configures IMAP protocol settings including authentication, timeouts, and rate limits. |

### Settings / Network / JMAP / Limits

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Jmap` | singleton | Get, Update | live | Configures JMAP protocol limits for requests, uploads, and push notifications. |

### Settings / Network / Listeners

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:NetworkListener` | object | Get, Query, Create, Update, Destroy | live | Defines a network listener for accepting incoming connections. |

### Settings / Network / WebDAV

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:WebDav` | singleton | Get, Update | live | Configures WebDAV protocol settings including property limits and locking. |

### Settings / Search

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Search` | singleton | Get, Update | live | Configures full-text search indexing for emails, calendars, contacts, and tracing. |

### Settings / Security / Allowed IPs

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:AllowedIp` | object | Get, Query, Create, Update, Destroy | live | Defines an allowed IP address or network range. |

### Settings / Security / Blocked IPs

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:BlockedIp` | object | Get, Query, Create, Update, Destroy | live | Defines a blocked IP address or network range. |

### Settings / Security / Settings

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Security` | singleton | Get, Update | live | Configures automatic IP banning rules for abuse, authentication failures, and port scanning. |

### Settings / Sieve / System Interpreter

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SieveSystemInterpreter` | singleton | Get, Update | live | Configures the system-level Sieve script interpreter settings and limits. |

### Settings / Sieve / System Scripts

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SieveSystemScript` | object | Get, Query, Create, Update, Destroy | live | Defines a system Sieve script executed by the server. |

### Settings / Sieve / User Interpreter

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SieveUserInterpreter` | singleton | Get, Update | live | Configures the user-level Sieve script interpreter settings and limits. |

### Settings / Sieve / User Scripts

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SieveUserScript` | object | Get, Query, Create, Update, Destroy | live | Defines a global Sieve script available for user imports. |

### Settings / Spam Filter / Classifier

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamClassifier` | singleton | Get, Update | live | Configures the spam classifier model, training parameters, and auto-learning settings. |

### Settings / Spam Filter / DNSBL / Servers

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamDnsblServer` | object | Get, Query, Create, Update, Destroy | live | Defines a DNSBL server used for spam filtering lookups. |

### Settings / Spam Filter / DNSBL / Settings

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamDnsblSettings` | singleton | Get, Update | live | Configures DNSBL query limits for spam filtering. |

### Settings / Spam Filter / General

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamSettings` | singleton | Get, Update | live | Configures global spam filter thresholds, greylisting, and trust settings. |

### Settings / Spam Filter / LLM Classifier

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamLlm` | singleton | Get, Update | live | Configures the LLM-based spam classifier. |

### Settings / Spam Filter / Lists / File Extensions

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamFileExtension` | object | Get, Query, Create, Update, Destroy | live | Defines a file extension classification rule for spam filtering. |

### Settings / Spam Filter / Lists / Spam Traps

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MemoryLookupKey` | object | Get, Query, Create, Update, Destroy | live | Defines an in-memory lookup key for fast data access. |

### Settings / Spam Filter / Pyzor

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamPyzor` | singleton | Get, Update | live | Configures the Pyzor collaborative spam detection service. |

### Settings / Spam Filter / Rules

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamRule` | object | Get, Query, Create, Update, Destroy | live | Defines a spam filter rule for message classification. |

### Settings / Spam Filter / Scores

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SpamTag` | object | Get, Query, Create, Update, Destroy | live | Defines a score or action assigned to a spam classification tag. |

### Settings / Storage / Blob Store

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:BlobStore` | singleton | Get, Update | live | Configures the blob storage backend for messages and files. |

### Settings / Storage / Cache

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Cache` | singleton | Get, Update | live | Configures in-memory cache sizes for data, DNS records, and authorization tokens. |

### Settings / Storage / Data Retention / Auto-Expunge

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DataRetention` | singleton | Get, Update | live | Configures data retention policies, expunge schedules, and archival settings. |

### Settings / Storage / Data Store

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:DataStore` | singleton | Get, Update | live | Configures the primary data store backend. |

### Settings / Storage / In-Memory Store

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:InMemoryStore` | singleton | Get, Update | live | Configures the in-memory cache and lookup store. |

### Settings / Storage / Metrics Store

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:MetricsStore` | singleton | Get, Update | live | Configures the storage backend for metrics data. |

### Settings / Storage / Search Store

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:SearchStore` | singleton | Get, Update | live | Configures the full-text search backend. |

### Settings / Storage / Tracing Store

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:TracingStore` | singleton | Get, Update | live | Configures the storage backend for tracing data. |

### Settings / TLS / ACME Providers

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:AcmeProvider` | object | Get, Query, Create, Update, Destroy | live | Defines an ACME provider for automatic TLS certificate management. |

### Settings / TLS / Certificates

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Certificate` | object | Get, Query, Create, Update, Destroy | live | Defines a TLS certificate and its associated private key. |

### Settings / Task Manager

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:TaskManager` | singleton | Get, Update | live | Configures task execution settings including retry strategies. |

### Settings / Telemetry / Alerts

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Alert` | object | Get, Query, Create, Update, Destroy | live | Defines an alert rule triggered by metric conditions. |

### Settings / Telemetry / Event Levels

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:EventTracingLevel` | object | Get, Query, Create, Update, Destroy | live | Defines a custom logging level override for a specific event type. |

### Settings / Telemetry / Metrics / General

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Metrics` | singleton | Get, Update | live | Configures metrics collection and export via OpenTelemetry and Prometheus. |

### Settings / Telemetry / Tracers

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Tracer` | object | Get, Query, Create, Update, Destroy | live | Defines a logging and tracing output method. |

### Settings / Telemetry / Webhooks

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:WebHook` | object | Get, Query, Create, Update, Destroy | live | Defines a webhook endpoint for event notifications. |

### Settings / Web Applications

| Object | Kind | Operations | Status | Description |
|---|---|---|---|---|
| `x:Application` | object | Get, Query, Create, Update, Destroy | live | Defines a web application served by the server. |

## Object details


### `x:Account`

Defines a user or group account for authentication and email access. Kind: object. Status: live. Permissions: `sysAccount*`.

Variants: `User` (x:UserAccount), `Group` (x:GroupAccount).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "name": "e2emvhs0ons",
   "domainId": "b",
   "credentials": "[redacted]",
   "createdAt": "2026-10-21T07:14:08Z",
   "memberGroupIds": {},
   "memberTenantId": null,
   "roles": {
    "@type": "User"
   },
   "permissions": {
    "@type": "Inherit"
   },
   "quotas": {},
   "aliases": {},
   "externalId": null,
   "description": "E2E Tester",
   "locale": "en-US",
   "timeZone": null,
   "encryptionAtRest": {
    "@type": "Disabled"
   },
   "@type": "User",
   "usedDiskQuota": 7876,
   "emailAddress": "e2emvhs0ons@authfly.test",
   "id": "c"
  },
  {
   "name": "authfly-svc",
   "domainId": "b",
   "credentials": "[redacted]",
   "createdAt": "2
…
```


### `x:AccountPassword`

Password-based authentication credential. Kind: singleton. Status: live. Permissions: `sysAccountPassword*`.

Fields: `currentSecret`, `otpAuth`, `secret`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": [
  "singleton"
 ]
}
```


### `x:AccountSettings`

Configures default account settings for locale and encryption. Kind: singleton. Status: live. Permissions: `sysAccountSettings*`.

Fields: `description`, `encryptionAtRest`, `locale`, `timeZone`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": [
  "singleton"
 ]
}
```


### `x:AcmeProvider`

Defines an ACME provider for automatic TLS certificate management. Kind: object. Status: live. Permissions: `sysAcmeProvider*`.

Fields: `accountKey` (server set), `accountUri` (server set), `challengeType`, `contact`, `description` (server set), `directory`, `eabHmacKey`, `eabKeyId`, `maxRetries`, `memberTenantId`, `preferredChain`, `renewBefore`, `reuseKey`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:Action`

Defines server management actions such as reloads, troubleshooting and cache operations. Kind: object. Status: live: set only. Permissions: `sysAction*`.

Variants: `ReloadSettings`, `ReloadTlsCertificates`, `ReloadLookupStores`, `ReloadBlockedIps`, `UpdateApps`, `TroubleshootDmarc` (x:DmarcTroubleshoot), `ClassifySpam` (x:SpamClassify), `InvalidateCaches`, `InvalidateNegativeCaches`, `PauseMtaQueue`, `ResumeMtaQueue`.

```json
{
 "type": "invalidArguments",
 "description": "Actions cannot be queried"
}
```


### `x:AddressBook`

Configures address book and contact storage settings. Kind: singleton. Status: live. Permissions: `sysAddressBook*`.

Fields: `defaultDisplayName`, `defaultHrefName`, `maxAddressBooks`, `maxContacts`, `maxVCardSize`, `vCardVersion`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "defaultDisplayName": "Stalwart Address Book",
   "defaultHrefName": "default",
   "maxVCardSize": 524288,
   "maxAddressBooks": 250,
   "maxContacts": null,
   "vCardVersion": "v4",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:AiModel`

Defines an AI model endpoint for LLM-based features. Kind: object. Status: live. Permissions: `sysAiModel*`.

Fields: `allowInvalidCerts`, `httpAuth`, `httpHeaders`, `model`, `modelType`, `name`, `temperature`, `timeout`, `url`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:Alert`

Defines an alert rule triggered by metric conditions. Kind: object. Status: live. Permissions: `sysAlert*`.

Fields: `condition`, `emailAlert`, `enable`, `eventAlert`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:AllowedIp`

Defines an allowed IP address or network range. Kind: object. Status: live. Permissions: `sysAllowedIp*`.

Fields: `address`, `createdAt`, `expiresAt`, `reason`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:ApiKey`

API key credential for programmatic access. Kind: object. Status: live: per account. Permissions: `sysApiKey*`.

Fields: `allowedIps`, `createdAt` (server set), `description`, `expiresAt`, `permissions`, `secret` (server set).

```json
{
 "type": "forbidden",
 "description": "Account not found."
}
```


### `x:AppPassword`

App password credential for programmatic access. Kind: object. Status: live: per account. Permissions: `sysAppPassword*`.

Fields: `allowedIps`, `createdAt` (server set), `description`, `expiresAt`, `permissions`, `secret` (server set).

```json
{
 "type": "forbidden",
 "description": "Account not found."
}
```


### `x:Application`

Defines a web application served by the server. Kind: object. Status: live. Permissions: `sysApplication*`.

Fields: `autoUpdateFrequency`, `description`, `enabled`, `oauthClientId`, `resourceUrl`, `unpackDirectory`, `urlPrefix`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "enabled": false,
   "description": "Stalwart Web Interface",
   "resourceUrl": "https://github.com/stalwartlabs/webui/releases/download/v1.0.11/webui.zip",
   "urlPrefix": {
    "/admin": true,
    "/account": true
   },
   "autoUpdateFrequency": 2592000000,
   "unpackDirectory": null,
   "oauthClientId": null,
   "id": "jkr72dpoaaab"
  }
 ],
 "notFound": []
}
```


### `x:ArchivedItem`

Represents an archived item that can be restored. Kind: object. Status: live: Enterprise only. Permissions: `sysArchivedItem*`.

Variants: `Email` (x:ArchivedEmail), `FileNode` (x:ArchivedFileNode), `CalendarEvent` (x:ArchivedCalendarEvent), `ContactCard` (x:ArchivedContactCard), `SieveScript` (x:ArchivedSieveScript).

```json
{
 "type": "forbidden",
 "description": "This feature is only available in the Enterprise edition. Obtain your trial license at https://license.stalw.art/trial."
}
```


### `x:ArfExternalReport`

Stores an ARF feedback report received from an external source. Kind: object. Status: live. Permissions: `sysArfExternalReport*`.

Fields: `expiresAt`, `from`, `memberTenantId`, `receivedAt`, `report`, `subject`, `to`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:Asn`

Configures ASN and geolocation data sources for IP address lookups. Kind: singleton. Status: live. Permissions: `sysAsn*`.

Variants: `Disabled`, `Resource` (x:AsnResource), `Dns` (x:AsnDns).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "expires": 86400000,
   "maxSize": 104857600,
   "timeout": 300000,
   "asnUrls": {
    "https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn-ipv4.csv": true,
    "https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn-ipv6.csv": true
   },
   "geoUrls": {
    "https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv4.csv": true,
    "https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv6.csv": true
   },
   "httpAuth": {
    "@type": "Unauthenticated"
   },
   "httpHeaders": {},
   "@type": "Resource",
   "id": "singleton"
  }
 ],
 "notFound": []

…
```


### `x:Authentication`

Configures authentication settings including password policies and default roles. Kind: singleton. Status: live. Permissions: `sysAuthentication*`.

Fields: `defaultAdminRoleIds`, `defaultGroupRoleIds`, `defaultTenantRoleIds`, `defaultUserRoleIds`, `directoryId`, `maxApiKeys`, `maxAppPasswords`, `passwordDefaultExpiry`, `passwordHashAlgorithm`, `passwordMaxLength`, `passwordMinLength`, `passwordMinStrength`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "directoryId": null,
   "defaultUserRoleIds": {
    "b": true
   },
   "defaultGroupRoleIds": {
    "c": true
   },
   "defaultTenantRoleIds": {
    "d": true,
    "b": true
   },
   "defaultAdminRoleIds": {
    "e": true,
    "b": true
   },
   "passwordHashAlgorithm": "[redacted]",
   "passwordMinLength": "[redacted]",
   "passwordMaxLength": "[redacted]",
   "passwordMinStrength": "[redacted]",
   "passwordDefaultExpiry": "[redacted]",
   "maxAppPasswords": "[redacted]",
   "maxApiKeys": "[redacted]",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:BlobStore`

Configures the blob storage backend for messages and files. Kind: singleton. Status: live. Permissions: `sysBlobStore*`.

Variants: `Default`, `Sharded` (x:ShardedBlobStore), `S3` (x:S3Store), `Azure` (x:AzureStore), `FileSystem` (x:FileSystemStore), `FoundationDb` (x:FoundationDbStore), `PostgreSql` (x:PostgreSqlStore), `MySql` (x:MySqlStore).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "@type": "Default",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:BlockedIp`

Defines a blocked IP address or network range. Kind: object. Status: live. Permissions: `sysBlockedIp*`.

Fields: `address`, `createdAt` (server set), `expiresAt`, `reason`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:Bootstrap`

Initial setup shown the first time Stalwart starts. Configures the server's identity, storage, user accounts, logging, and DNS management. Kind: singleton. Status: live. Permissions: `sysBootstrap*`.

Fields: `blobStore`, `dataStore`, `defaultDomain`, `directory`, `dnsServer`, `generateDkimKeys`, `inMemoryStore`, `requestTlsCertificate`, `searchStore`, `secret` (server set), `serverHostname`, `tracer`, `username` (server set).

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": [
  "singleton"
 ]
}
```


### `x:Cache`

Configures in-memory cache sizes for data, DNS records, and authorization tokens. Kind: singleton. Status: live. Permissions: `sysCache*`.

Fields: `accessTokens`, `accounts`, `contacts`, `dkimSignatures`, `dnsIpv4`, `dnsIpv6`, `dnsMtaSts`, `dnsMx`, `dnsPtr`, `dnsRbl`, `dnsTlsa`, `dnsTxt`, `domainNames`, `domainNamesNegative`, `domains`, `emailAddresses`, `emailAddressesNegative`, `events`, `files`, `httpAuth`, `mailingLists`, `messages`, `negativeTtl`, `roles`, `scheduling`, `tenants`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "accessTokens": "[redacted]",
   "contacts": 10485760,
   "dnsIpv4": 5242880,
   "dnsIpv6": 5242880,
   "dnsMtaSts": 1048576,
   "dnsMx": 5242880,
   "dnsPtr": 1048576,
   "dnsRbl": 5242880,
   "dnsTlsa": 1048576,
   "dnsTxt": 5242880,
   "events": 10485760,
   "scheduling": 1048576,
   "files": 10485760,
   "httpAuth": 1048576,
   "messages": 52428800,
   "domains": 5242880,
   "domainNames": 10485760,
   "domainNamesNegative": 1048576,
   "emailAddresses": 10485760,
   "emailAddressesNegative": 2097152,
   "accounts": 20971520,
   "roles": 5242880,
   "tenants": 5242880,
   "mailingLists": 2097152,
   "dkimSignatures": 10485760,
   "negativeTtl"
…
```


### `x:Calendar`

Configures calendar settings including iCalendar limits and default names. Kind: singleton. Status: live. Permissions: `sysCalendar*`.

Fields: `defaultDisplayName`, `defaultHrefName`, `maxAttendees`, `maxCalendars`, `maxEventNotifications`, `maxEvents`, `maxICalendarSize`, `maxParticipantIdentities`, `maxRecurrenceExpansions`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "defaultDisplayName": "Stalwart Calendar",
   "defaultHrefName": "default",
   "maxAttendees": 20,
   "maxRecurrenceExpansions": 3000,
   "maxICalendarSize": 524288,
   "maxCalendars": 250,
   "maxEvents": null,
   "maxParticipantIdentities": 100,
   "maxEventNotifications": null,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:CalendarAlarm`

Configures calendar alarm email notifications. Kind: singleton. Status: live. Permissions: `sysCalendarAlarm*`.

Fields: `allowExternalRcpts`, `enable`, `fromEmail`, `fromName`, `minTriggerInterval`, `template`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "allowExternalRcpts": false,
   "enable": true,
   "fromEmail": null,
   "fromName": "Stalwart Calendar",
   "minTriggerInterval": 3600000,
   "template": null,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:CalendarScheduling`

Configures calendar scheduling, iTIP messaging, and HTTP RSVP settings. Kind: singleton. Status: live. Permissions: `sysCalendarScheduling*`.

Fields: `autoAddInvitations`, `emailTemplate`, `enable`, `httpRsvpEnable`, `httpRsvpLinkExpiry`, `httpRsvpTemplate`, `httpRsvpUrl`, `itipMaxSize`, `maxRecipients`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "enable": true,
   "httpRsvpEnable": true,
   "httpRsvpLinkExpiry": 7776000000,
   "httpRsvpUrl": null,
   "autoAddInvitations": false,
   "itipMaxSize": 524288,
   "maxRecipients": 100,
   "emailTemplate": null,
   "httpRsvpTemplate": null,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Certificate`

Defines a TLS certificate and its associated private key. Kind: object. Status: live. Permissions: `sysCertificate*`.

Fields: `certificate`, `issuer` (server set), `notValidAfter` (server set), `notValidBefore` (server set), `privateKey`, `subjectAlternativeNames` (server set).

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:ClusterNode`

Represents a node in the cluster Kind: object. Status: live. Permissions: `sysClusterNode*`.

Fields: `hostname`, `lastRenewal`, `nodeId`, `status`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "nodeId": 0,
   "hostname": "315cb1e47d17",
   "lastRenewal": "2026-10-21T07:13:56Z",
   "status": "active",
   "id": "a"
  },
  {
   "nodeId": 1,
   "hostname": "a16229c92540",
   "lastRenewal": "2026-10-21T07:16:10Z",
   "status": "active",
   "id": "b"
  }
 ],
 "notFound": []
}
```


### `x:ClusterRole`

Defines a cluster node role with enabled tasks and listeners. Kind: object. Status: live. Permissions: `sysClusterRole*`.

Fields: `description`, `listeners`, `name`, `tasks`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:Coordinator`

Configures the cluster coordinator for inter-node communication. Kind: singleton. Status: live. Permissions: `sysCoordinator*`.

Variants: `Disabled`, `Default`, `Kafka` (x:KafkaCoordinator), `Nats` (x:NatsCoordinator), `Zenoh` (x:ZenohCoordinator), `Redis` (x:RedisStore), `RedisCluster` (x:RedisClusterStore), `RedisSentinel` (x:RedisSentinelStore).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "@type": "Disabled",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:DataRetention`

Configures data retention policies, expunge schedules, and archival settings. Kind: singleton. Status: live. Permissions: `sysDataRetention*`.

Fields: `archiveDeletedAccountsFor`, `archiveDeletedItemsFor`, `blobCleanupSchedule`, `dataCleanupSchedule`, `expungeSchedule`, `expungeSchedulingInboxAfter`, `expungeShareNotifyAfter`, `expungeSubmissionsAfter`, `expungeTrashAfter`, `holdMetricsFor`, `holdMtaReportsFor`, `holdTracesFor`, `maxChangesHistory`, `metricsCollectionInterval`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "expungeTrashAfter": 2592000000,
   "expungeSubmissionsAfter": 259200000,
   "expungeShareNotifyAfter": 2592000000,
   "expungeSchedulingInboxAfter": 2592000000,
   "expungeSchedule": {
    "hour": 0,
    "minute": 0,
    "@type": "Daily"
   },
   "dataCleanupSchedule": {
    "hour": 2,
    "minute": 0,
    "@type": "Daily"
   },
   "blobCleanupSchedule": {
    "hour": 4,
    "minute": 0,
    "@type": "Daily"
   },
   "maxChangesHistory": 10000,
   "archiveDeletedItemsFor": null,
   "archiveDeletedAccountsFor": null,
   "holdMtaReportsFor": 2592000000,
   "holdTracesFor": 2592000000,
   "holdMetricsFor": 7776000000,
   "metricsCollectionInterval":
…
```


### `x:DataStore`

Configures the primary data store backend. Kind: singleton. Status: live. Permissions: `sysDataStore*`.

Variants: `RocksDb` (x:RocksDbStore), `Sqlite` (x:SqliteStore), `FoundationDb` (x:FoundationDbStore), `PostgreSql` (x:PostgreSqlStore), `MySql` (x:MySqlStore).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "path": "/var/lib/stalwart/",
   "blobSize": 16834,
   "bufferSize": 134217728,
   "poolWorkers": null,
   "cacheSize": 134217728,
   "@type": "RocksDb",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Directory`

Defines an external directory for account authentication and lookups. Kind: object. Status: live. Permissions: `sysDirectory*`.

Variants: `Ldap` (x:LdapDirectory), `Sql` (x:SqlDirectory), `Oidc` (x:OidcDirectory).

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:DkimReportSettings`

Configures DKIM authentication failure report generation. Kind: singleton. Status: live. Permissions: `sysDkimReportSettings*`.

Fields: `dkimSignDomain`, `fromAddress`, `fromName`, `sendFrequency`, `subject`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "fromAddress": {
    "match": {},
    "else": "'noreply-dkim@' + system('domain')"
   },
   "fromName": {
    "match": {},
    "else": "'Report Subsystem'"
   },
   "sendFrequency": {
    "match": {},
    "else": "[1, 1d]"
   },
   "dkimSignDomain": {
    "match": {},
    "else": "system('domain')"
   },
   "subject": {
    "match": {},
    "else": "'DKIM Authentication Failure Report'"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:DkimSignature`

Defines a DKIM signature used to sign outgoing email messages. Kind: object. Status: live. Permissions: `sysDkimSignature*`.

Variants: `Dkim1Ed25519Sha256` (x:Dkim1Signature), `Dkim1RsaSha256` (x:Dkim1Signature), `Dkim2Ed25519Sha256` (x:Dkim2Signature), `Dkim2RsaSha256` (x:Dkim2Signature).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "auid": null,
   "canonicalization": "relaxed/relaxed",
   "expire": null,
   "headers": {
    "From": true,
    "To": true,
    "Date": true,
    "Subject": true,
    "Message-ID": true
   },
   "privateKey": "[redacted]",
   "report": true,
   "thirdParty": null,
   "thirdPartyHash": null,
   "domainId": "b",
   "memberTenantId": null,
   "selector": "v1-rsa-20261021",
   "createdAt": "2026-10-21T07:13:58Z",
   "nextTransitionAt": null,
   "stage": "active",
   "@type": "Dkim1RsaSha256",
   "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyuA3rmZJTVLwN7HwueBpLhwr4dnb6vwK8CXA/KQTkr2fMSl7Hs99nevaLd8dIkwlmOa0HZql/vaTMDmn51NXfxY6IRU6aGjDRdh
…
```


### `x:DmarcExternalReport`

Stores a DMARC aggregate report received from an external source. Kind: object. Status: live. Permissions: `sysDmarcExternalReport*`.

Fields: `expiresAt`, `from`, `memberTenantId`, `receivedAt`, `report`, `subject`, `to`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:DmarcInternalReport`

Stores an outbound DMARC aggregate report pending delivery. Kind: object. Status: live. Permissions: `sysDmarcInternalReport*`.

Fields: `createdAt`, `deliverAt`, `domain`, `policyIdentifier`, `report`, `rua`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:DmarcReportSettings`

Configures DMARC aggregate and failure report generation. Kind: singleton. Status: live. Permissions: `sysDmarcReportSettings*`.

Fields: `aggregateContactInfo`, `aggregateDkimSignDomain`, `aggregateFromAddress`, `aggregateFromName`, `aggregateMaxReportSize`, `aggregateOrgName`, `aggregateSendFrequency`, `aggregateSubject`, `failureDkimSignDomain`, `failureFromAddress`, `failureFromName`, `failureSendFrequency`, `failureSubject`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "aggregateContactInfo": {
    "match": {},
    "else": "false"
   },
   "aggregateFromAddress": {
    "match": {},
    "else": "'noreply-dmarc@' + system('domain')"
   },
   "aggregateFromName": {
    "match": {},
    "else": "'Report Subsystem'"
   },
   "aggregateMaxReportSize": {
    "match": {},
    "else": "5242880"
   },
   "aggregateOrgName": {
    "match": {},
    "else": "system('domain')"
   },
   "aggregateSendFrequency": {
    "match": {},
    "else": "daily"
   },
   "aggregateDkimSignDomain": {
    "match": {},
    "else": "system('domain')"
   },
   "aggregateSubject": {
    "match": {},
    "else": "'DMARC Aggregate Report'"
   },

…
```


### `x:DnsResolver`

Configures the DNS resolver used for domain lookups. Kind: singleton. Status: live. Permissions: `sysDnsResolver*`.

Variants: `System` (x:DnsResolverCommon), `Custom` (x:DnsResolverCustom), `Cloudflare` (x:DnsResolverTls), `Quad9` (x:DnsResolverTls), `Google` (x:DnsResolverCommon).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "attempts": 2,
   "concurrency": 2,
   "enableEdns": true,
   "preserveIntermediates": true,
   "timeout": 5000,
   "tcpOnError": true,
   "@type": "System",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:DnsServer`

Defines a DNS server for automatic record management. Kind: object. Status: live. Permissions: `sysDnsServer*`.

Variants: `Tsig` (x:DnsServerTsig), `Deprecated1`, `Cloudflare` (x:DnsServerCloudflare), `DigitalOcean` (x:DnsServerCloud), `DeSEC` (x:DnsServerCloud), `Ovh` (x:DnsServerOvh), `Bunny` (x:DnsServerCloud), `Porkbun` (x:DnsServerPorkbun), `Dnsimple` (x:DnsServerDnsimple), `Spaceship` (x:DnsServerSpaceship), `Route53` (x:DnsServerRoute53), `GoogleCloudDns` (x:DnsServerGoogleCloudDns), `Alidns` (x:DnsServerAlidns), `ArvanCloud` (x:DnsServerCloud), `Autodns` (x:DnsServerAutodns), `AzureDns` (x:DnsServerAzureDns), `BaiduCloud` (x:DnsServerBaiduCloud), `BluecatV2` (x:DnsServerBluecatV2), `ClouDns` (x:DnsServerClouDns), `Constellix` (x:DnsServerConstellix), `Cpanel` (x:DnsServerCpanel), `Ddnss` (x:DnsServerCloud), `DnsMadeEasy` (x:DnsServerDnsMadeEasy), `Domeneshop` (x:DnsServerDomeneshop), `Dreamhost` (x:DnsServerCloud), `DuckDns` (x:DnsServerCloud), `Dynu` (x:DnsServerCloud), `EasyDns` (x:DnsServerEasyDns), `EdgeDns` (x:DnsServerEdgeDns), `Exoscale` (x:DnsServerExoscale), `FreeMyIp` (x:DnsServerCloud), `GandiV5` (x:DnsServerCloud), `Gcore` (x:DnsServerCloud), `Glesys` (x:DnsServerGlesys), `Godaddy` (x:DnsServerGodaddy), `Hetzner` (x:DnsServerCloud), `HostingDe` (x:DnsServerCloud), `Hostinger` (x:DnsServerCloud), `HuaweiCloud` (x:DnsServerHuaweiCloud), `Hurricane` (x:DnsServerHurricane), `IbmCloud` (x:DnsServerIbmCloud), `Infoblox` (x:DnsServerInfoblox), `Infomaniak` (x:DnsServerCloud), `Inwx` (x:DnsServerInwx), `Ionos` (x:DnsServerCloud), `Ipv64` (x:DnsServerCloud), `Joker` (x:DnsServerJoker), `Lightsail` (x:DnsServerLightsail), `Linode` (x:DnsServerCloud), `LuaDns` (x:DnsServerLuaDns), `MythicBeasts` (x:DnsServerMythicBeasts), `Namecheap` (x:DnsServerNamecheap), `NameDotCom` (x:DnsServerNameDotCom), `NameSilo` (x:DnsServerCloud), `Netcup` (x:DnsServerNetcup), `Netlify` (x:DnsServerCloud), `Nifcloud` (x:DnsServerNifcloud), `Ns1` (x:DnsServerCloud), `OracleCloud` (x:DnsServerOracleCloud), `Plesk` (x:DnsServerPlesk), `Safedns` (x:DnsServerCloud), `Scaleway` (x:DnsServerCloud), `TencentCloud` (x:DnsServerTencentCloud), `Transip` (x:DnsServerTransip), `UltraDns` (x:DnsServerUltraDns), `Vercel` (x:DnsServerVercel), `Volcengine` (x:DnsServerVolcengine), `Vultr` (x:DnsServerCloud), `WebSupport` (x:DnsServerWebSupport), `YandexCloud` (x:DnsServerYandexCloud), `PowerDns` (x:DnsServerPowerDns).

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:Domain`

Defines an email domain and its DNS, DKIM, and TLS certificate settings. Kind: object. Status: live. Permissions: `sysDomain*`.

Fields: `aliases`, `allowRelaying`, `allowScimProvisioning`, `catchAllAddress`, `certificateManagement`, `createdAt` (server set), `description`, `directoryId`, `dkimManagement`, `dnsManagement`, `dnsZoneFile` (server set), `isEnabled`, `logo`, `memberTenantId`, `name`, `reportAddressUri`, `subAddressing`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "name": "authfly.test",
   "aliases": {},
   "isEnabled": true,
   "createdAt": "2026-10-21T07:13:58Z",
   "description": null,
   "logo": null,
   "certificateManagement": {
    "@type": "Manual"
   },
   "dkimManagement": {
    "algorithms": {
     "Dkim1Ed25519Sha256": true,
     "Dkim1RsaSha256": true
    },
    "selectorTemplate": "v{version}-{algorithm}-{date-%Y%m%d}",
    "rotateAfter": 7776000000,
    "retireAfter": 604800000,
    "deleteAfter": 2592000000,
    "@type": "Automatic"
   },
   "dnsManagement": {
    "@type": "Manual"
   },
   "memberTenantId": null,
   "directoryId": null,
   "catchAllAddress": null,
   "subAddressing": {
   
…
```


### `x:DsnReportSettings`

Configures Delivery Status Notification (DSN) report generation. Kind: singleton. Status: live. Permissions: `sysDsnReportSettings*`.

Fields: `dkimSignDomain`, `fromAddress`, `fromName`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "fromAddress": {
    "match": {},
    "else": "'MAILER-DAEMON@' + system('domain')"
   },
   "fromName": {
    "match": {},
    "else": "'Mail Delivery Subsystem'"
   },
   "dkimSignDomain": {
    "match": {},
    "else": "system('domain')"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Email`

Configures email message limits, encryption, compression, and default folder settings. Kind: singleton. Status: live. Permissions: `sysEmail*`.

Fields: `compressionAlgorithm`, `defaultFolders`, `encryptAtRest`, `encryptOnAppend`, `maxAttachmentSize`, `maxIdentities`, `maxMailboxDepth`, `maxMailboxNameLength`, `maxMailboxes`, `maxMaskedAddresses`, `maxMessageSize`, `maxMessages`, `maxPublicKeys`, `maxSubmissions`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "maxAttachmentSize": 50000000,
   "maxMessageSize": 75000000,
   "maxMailboxDepth": 10,
   "maxMailboxNameLength": 255,
   "encryptOnAppend": false,
   "encryptAtRest": true,
   "compressionAlgorithm": "lz4",
   "defaultFolders": {},
   "maxMessages": null,
   "maxSubmissions": 500,
   "maxIdentities": 20,
   "maxMailboxes": 250,
   "maxMaskedAddresses": 5,
   "maxPublicKeys": 5,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Enterprise`

Configures enterprise licensing and branding settings. Kind: singleton. Status: live. Permissions: `sysEnterprise*`.

Fields: `apiKey`, `licenseKey`, `logoUrl`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "apiKey": "[redacted]",
   "licenseKey": {
    "@type": "None"
   },
   "logoUrl": null,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:EventTracingLevel`

Defines a custom logging level override for a specific event type. Kind: object. Status: live. Permissions: `sysEventTracingLevel*`.

Fields: `event`, `level`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:FileStorage`

Configures file storage limits. Kind: singleton. Status: live. Permissions: `sysFileStorage*`.

Fields: `maxFiles`, `maxFolders`, `maxSize`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "maxSize": 26214400,
   "maxFiles": null,
   "maxFolders": null,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Http`

Configures HTTP server settings including rate limiting, CORS, and security headers. Kind: singleton. Status: live. Permissions: `sysHttp*`.

Fields: `allowedEndpoints`, `enableHsts`, `rateLimitAnonymous`, `rateLimitAuthenticated`, `redirectRoot`, `responseHeaders`, `usePermissiveCors`, `useXForwarded`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "rateLimitAuthenticated": {
    "count": 1000,
    "period": 60000
   },
   "rateLimitAnonymous": {
    "count": 100,
    "period": 60000
   },
   "allowedEndpoints": {
    "match": {},
    "else": "200"
   },
   "enableHsts": false,
   "usePermissiveCors": false,
   "responseHeaders": {},
   "useXForwarded": false,
   "redirectRoot": null,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:HttpForm`

Configures the contact form submission endpoint. Kind: singleton. Status: live. Permissions: `sysHttpForm*`.

Fields: `defaultFromAddress`, `defaultName`, `defaultSubject`, `deliverTo`, `enable`, `fieldEmail`, `fieldHoneyPot`, `fieldName`, `fieldSubject`, `maxSize`, `rateLimit`, `validateDomain`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "deliverTo": {},
   "defaultFromAddress": "postmaster@localhost",
   "fieldEmail": null,
   "enable": false,
   "fieldHoneyPot": null,
   "maxSize": 102400,
   "defaultName": "Anonymous",
   "fieldName": null,
   "rateLimit": {
    "count": 5,
    "period": 3600000
   },
   "defaultSubject": "Contact form submission",
   "fieldSubject": null,
   "validateDomain": true,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:HttpLookup`

Defines an HTTP-based lookup list. Kind: object. Status: live. Permissions: `sysHttpLookup*`.

Fields: `enable`, `format`, `isGzipped`, `maxEntries`, `maxEntrySize`, `maxSize`, `namespace`, `refresh`, `retry`, `timeout`, `url`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "namespace": "stwt_disposable_domains",
   "enable": true,
   "format": {
    "@type": "List"
   },
   "isGzipped": false,
   "maxEntries": 900000,
   "maxEntrySize": 512,
   "maxSize": 104857600,
   "refresh": 86400000,
   "retry": 3600000,
   "timeout": 30000,
   "url": "https://disposable.github.io/disposable-email-domains/domains_mx.txt",
   "id": "jkr72e3uj3aa"
  },
  {
   "namespace": "stwt_phishtank",
   "enable": true,
   "format": {
    "indexKey": 1,
    "indexValue": null,
    "separator": ",",
    "skipFirst": true,
    "@type": "Csv"
   },
   "isGzipped": true,
   "maxEntries": 900000,
   "maxEntrySize": 512,
   "maxSize": 104857600,

…
```


### `x:Imap`

Configures IMAP protocol settings including authentication, timeouts, and rate limits. Kind: singleton. Status: live. Permissions: `sysImap*`.

Fields: `allowPlainTextAuth`, `maxAuthFailures`, `maxConcurrent`, `maxMessagesPerCommand`, `maxMessagesPerSave`, `maxRequestRate`, `maxRequestSize`, `maxUidBatches`, `minUidBatchSize`, `timeoutAnonymous`, `timeoutAuthenticated`, `timeoutIdle`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "allowPlainTextAuth": false,
   "maxAuthFailures": 3,
   "maxConcurrent": 16,
   "maxRequestRate": {
    "count": 2000,
    "period": 60000
   },
   "maxRequestSize": 52428800,
   "timeoutAnonymous": 60000,
   "timeoutAuthenticated": 1800000,
   "timeoutIdle": 1800000,
   "maxMessagesPerCommand": 1000000,
   "minUidBatchSize": 500,
   "maxUidBatches": 10000,
   "maxMessagesPerSave": 1000000,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:InMemoryStore`

Configures the in-memory cache and lookup store. Kind: singleton. Status: live. Permissions: `sysInMemoryStore*`.

Variants: `Default`, `Sharded` (x:ShardedInMemoryStore), `Redis` (x:RedisStore), `RedisCluster` (x:RedisClusterStore), `RedisSentinel` (x:RedisSentinelStore).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "@type": "Default",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Jmap`

Configures JMAP protocol limits for requests, uploads, and push notifications. Kind: singleton. Status: live. Permissions: `sysJmap*`.

Fields: `changesMaxResults`, `eventSourceThrottle`, `getMaxResults`, `maxConcurrentRequests`, `maxConcurrentUploads`, `maxMethodCalls`, `maxPushSize`, `maxRequestSize`, `maxSubscriptions`, `maxUploadCount`, `maxUploadSize`, `parseLimitContact`, `parseLimitEmail`, `parseLimitEvent`, `pushAttemptWait`, `pushMaxAttempts`, `pushRequestTimeout`, `pushRetryWait`, `pushShardsTotal`, `pushThrottle`, `pushVerifyTimeout`, `queryMaxResults`, `setMaxObjects`, `snippetMaxResults`, `uploadQuota`, `uploadTtl`, `webPushContact`, `webPushKey`, `websocketHeartbeat`, `websocketThrottle`, `websocketTimeout`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "parseLimitEvent": 10,
   "parseLimitContact": 10,
   "parseLimitEmail": 10,
   "changesMaxResults": 5000,
   "getMaxResults": 500,
   "queryMaxResults": 5000,
   "maxMethodCalls": 16,
   "maxConcurrentRequests": 4,
   "maxRequestSize": 10000000,
   "setMaxObjects": 500,
   "snippetMaxResults": 100,
   "maxConcurrentUploads": 4,
   "maxUploadSize": 50000000,
   "maxUploadCount": 1000,
   "uploadQuota": 50000000,
   "uploadTtl": 3600000,
   "eventSourceThrottle": 1000,
   "pushAttemptWait": 60000,
   "pushMaxAttempts": 3,
   "pushRetryWait": 1000,
   "pushThrottle": 1000,
   "pushRequestTimeout": 10000,
   "pushVerifyTimeout": 60000,
   "pushShards
…
```


### `x:Log`

Represents a server log entry. Kind: object. Status: live: store not configured. Permissions: `sysLog*`.

Fields: `details`, `event`, `level`, `timestamp`.

```json
{
 "type": "serverUnavailable",
 "description": "This server is temporarily unavailable. Attempting this same operation later may succeed."
}
```


### `x:MailingList`

Defines a mailing list that distributes messages to a group of recipients. Kind: object. Status: live. Permissions: `sysMailingList*`.

Fields: `aliases`, `description`, `domainId`, `emailAddress` (server set), `memberTenantId`, `name`, `recipients`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:MaskedEmail`

Defines a masked email address for privacy protection. Kind: object. Status: live: Enterprise only. Permissions: `sysMaskedEmail*`.

Fields: `accountId`, `createdAt` (server set), `createdBy`, `description`, `email` (server set), `emailDomain`, `emailPrefix`, `enabled`, `expiresAt`, `forDomain`, `url`.

```json
{
 "type": "forbidden",
 "description": "This feature is only available in the Enterprise edition. Obtain your trial license at https://license.stalw.art/trial."
}
```


### `x:MemoryLookupKey`

Defines an in-memory lookup key for fast data access. Kind: object. Status: live. Permissions: `sysMemoryLookupKey*`.

Fields: `isGlobPattern`, `key`, `namespace`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "namespace": "surbl-hashbl",
   "key": "[redacted]",
   "isGlobPattern": false,
   "id": "jkr72e3ukbaa"
  },
  {
   "namespace": "surbl-hashbl",
   "key": "[redacted]",
   "isGlobPattern": false,
   "id": "jkr72e3ukaqa"
  },
  {
   "namespace": "surbl-hashbl",
   "key": "[redacted]",
   "isGlobPattern": false,
   "id": "jkr72e3ukaaa"
  }
 ],
 "notFound": []
}
```


### `x:MemoryLookupKeyValue`

Defines an in-memory lookup key-value pair. Kind: object. Status: live. Permissions: `sysMemoryLookupKeyValue*`.

Fields: `isGlobPattern`, `key`, `namespace`, `value`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:Metric`

Stores a collected server metric data point. Kind: object. Status: live: Enterprise only. Permissions: `sysMetric*`.

Variants: `Counter` (x:MetricCount), `Gauge` (x:MetricCount), `Histogram` (x:MetricSum).

```json
{
 "type": "forbidden",
 "description": "This feature is only available in the Enterprise edition. Obtain your trial license at https://license.stalw.art/trial."
}
```


### `x:Metrics`

Configures metrics collection and export via OpenTelemetry and Prometheus. Kind: singleton. Status: live. Permissions: `sysMetrics*`.

Fields: `metrics`, `metricsPolicy`, `openTelemetry`, `prometheus`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "openTelemetry": {
    "@type": "Disabled"
   },
   "prometheus": {
    "@type": "Disabled"
   },
   "metrics": {},
   "metricsPolicy": "exclude",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:MetricsStore`

Configures the storage backend for metrics data. Kind: singleton. Status: live. Permissions: `sysMetricsStore*`.

Variants: `Disabled`, `Default`, `FoundationDb` (x:FoundationDbStore), `PostgreSql` (x:PostgreSqlStore), `MySql` (x:MySqlStore).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "@type": "Default",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:MtaConnectionStrategy`

Defines a connection strategy for outbound message delivery. Kind: object. Status: live. Permissions: `sysMtaConnectionStrategy*`.

Fields: `connectTimeout`, `dataTimeout`, `description`, `ehloHostname`, `ehloTimeout`, `greetingTimeout`, `mailFromTimeout`, `name`, `rcptToTimeout`, `sourceIps`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "name": "default",
   "description": "Default connection strategy",
   "ehloHostname": null,
   "sourceIps": {},
   "connectTimeout": 300000,
   "dataTimeout": 600000,
   "ehloTimeout": 300000,
   "greetingTimeout": 300000,
   "mailFromTimeout": 300000,
   "rcptToTimeout": 300000,
   "id": "jkr72dpuaeab"
  }
 ],
 "notFound": []
}
```


### `x:MtaDeliverySchedule`

Defines retry and notification intervals for message delivery. Kind: object. Status: live. Permissions: `sysMtaDeliverySchedule*`.

Fields: `description`, `expiry`, `name`, `notify`, `queueId`, `retry`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "name": "dsn",
   "description": "Delivery Status Notification delivery schedule",
   "expiry": {
    "maxAttempts": 10,
    "@type": "Attempts"
   },
   "notify": {
    "@type": "Default"
   },
   "queueId": "c",
   "retry": {
    "intervals": {
     "0": {
      "duration": 900000
     },
     "1": {
      "duration": 1800000
     },
     "2": {
      "duration": 3600000
     },
     "3": {
      "duration": 7200000
     }
    },
    "@type": "Custom"
   },
   "id": "c"
  },
  {
   "name": "remote",
   "description": "Remote delivery schedule",
   "expiry": {
    "expire": 259200000,
    "@type": "Ttl"
   },
   "notify": {
    "@type": "Default"
…
```


### `x:MtaExtensions`

Configures SMTP protocol extensions offered to clients. Kind: singleton. Status: live. Permissions: `sysMtaExtensions*`.

Fields: `chunking`, `deliverBy`, `dsn`, `expn`, `futureRelease`, `mtPriority`, `noSoliciting`, `pipelining`, `requireTls`, `vrfy`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "chunking": {
    "match": {},
    "else": "true"
   },
   "deliverBy": {
    "match": {
     "0": {
      "if": "!is_empty(authenticated_as)",
      "then": "15d"
     }
    },
    "else": "false"
   },
   "dsn": {
    "match": {
     "0": {
      "if": "!is_empty(authenticated_as)",
      "then": "true"
     }
    },
    "else": "false"
   },
   "expn": {
    "match": {
     "0": {
      "if": "!is_empty(authenticated_as)",
      "then": "true"
     }
    },
    "else": "false"
   },
   "futureRelease": {
    "match": {
     "0": {
      "if": "!is_empty(authenticated_as)",
      "then": "7d"
     }
    },
    "else": "false"
   },
   "mtPriorit
…
```


### `x:MtaHook`

Defines an MTA hook endpoint for message processing. Kind: object. Status: live. Permissions: `sysMtaHook*`.

Fields: `allowInvalidCerts`, `enable`, `httpAuth`, `httpHeaders`, `maxResponseSize`, `stages`, `tempFailOnError`, `timeout`, `url`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:MtaInboundSession`

Configures inbound SMTP session timeouts and transfer limits. Kind: singleton. Status: live. Permissions: `sysMtaInboundSession*`.

Fields: `maxDuration`, `timeout`, `transferLimit`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "maxDuration": {
    "match": {},
    "else": "10m"
   },
   "timeout": {
    "match": {},
    "else": "5m"
   },
   "transferLimit": {
    "match": {},
    "else": "262144000"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:MtaInboundThrottle`

Defines an inbound rate limit rule for SMTP connections. Kind: object. Status: live. Permissions: `sysMtaInboundThrottle*`.

Fields: `description`, `enable`, `key`, `match`, `rate`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "enable": true,
   "description": "Sender address to recipient throttle",
   "key": "[redacted]",
   "match": {
    "match": {},
    "else": "true"
   },
   "rate": {
    "count": 25,
    "period": 3600000
   },
   "id": "jkr72dpqabqb"
  },
  {
   "enable": true,
   "description": "Sender IP throttle",
   "key": "[redacted]",
   "match": {
    "match": {},
    "else": "true"
   },
   "rate": {
    "count": 5,
    "period": 1000
   },
   "id": "jkr72dpqabab"
  }
 ],
 "notFound": []
}
```


### `x:MtaMilter`

Defines a Milter filter endpoint for message processing. Kind: object. Status: live. Permissions: `sysMtaMilter*`.

Fields: `allowInvalidCerts`, `enable`, `flagsAction`, `flagsProtocol`, `hostname`, `maxResponseSize`, `port`, `protocolVersion`, `stages`, `tempFailOnError`, `timeoutCommand`, `timeoutConnect`, `timeoutData`, `useTls`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:MtaOutboundStrategy`

Configures outbound message delivery routing, scheduling, and TLS strategies. Kind: singleton. Status: live. Permissions: `sysMtaOutboundStrategy*`.

Fields: `connection`, `route`, `schedule`, `tls`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "connection": {
    "match": {},
    "else": "'default'"
   },
   "route": {
    "match": {
     "0": {
      "if": "is_local_domain(rcpt_domain)",
      "then": "'local'"
     }
    },
    "else": "'mx'"
   },
   "schedule": {
    "match": {
     "0": {
      "if": "is_local_domain(rcpt_domain)",
      "then": "'local'"
     },
     "1": {
      "if": "source == 'dsn'",
      "then": "'dsn'"
     },
     "2": {
      "if": "source == 'report'",
      "then": "'report'"
     }
    },
    "else": "'remote'"
   },
   "tls": {
    "match": {
     "0": {
      "if": "retry_num > 0 && last_error == 'tls'",
      "then": "'invalid-tls'"
     }
    },
  
…
```


### `x:MtaOutboundThrottle`

Defines an outbound rate limit rule for message delivery. Kind: object. Status: live. Permissions: `sysMtaOutboundThrottle*`.

Fields: `description`, `enable`, `key`, `match`, `rate`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:MtaQueueQuota`

Defines a quota rule for message queues. Kind: object. Status: live. Permissions: `sysMtaQueueQuota*`.

Fields: `description`, `enable`, `key`, `match`, `messages`, `size`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "enable": true,
   "description": "Global queue quota",
   "key": "[redacted]",
   "match": {
    "match": {},
    "else": ""
   },
   "messages": 100000,
   "size": 10737418240,
   "id": "jkr72dpqaaqb"
  }
 ],
 "notFound": []
}
```


### `x:MtaRoute`

Defines a routing rule for outbound message delivery. Kind: object. Status: live. Permissions: `sysMtaRoute*`.

Variants: `Mx` (x:MtaRouteMx), `Relay` (x:MtaRouteRelay), `Local` (x:MtaRouteCommon).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "name": "local",
   "description": "Local delivery route",
   "@type": "Local",
   "id": "jkr72dpuadqb"
  },
  {
   "ipLookupStrategy": "v4ThenV6",
   "maxMultihomed": 2,
   "maxMxHosts": 2,
   "name": "mx",
   "description": "MX delivery route",
   "@type": "Mx",
   "id": "jkr72dpuadab"
  }
 ],
 "notFound": []
}
```


### `x:MtaStageAuth`

Configures SMTP authentication requirements and error handling. Kind: singleton. Status: live. Permissions: `sysMtaStageAuth*`.

Fields: `maxFailures`, `mustMatchSender`, `require`, `saslMechanisms`, `waitOnFail`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "maxFailures": {
    "match": {},
    "else": "3"
   },
   "waitOnFail": {
    "match": {},
    "else": "5s"
   },
   "saslMechanisms": {
    "match": {
     "0": {
      "if": "local_port != 25 && is_tls",
      "then": "[plain, login, oauthbearer, xoauth2]"
     },
     "1": {
      "if": "local_port != 25",
      "then": "[oauthbearer, xoauth2]"
     }
    },
    "else": "false"
   },
   "mustMatchSender": {
    "match": {},
    "else": "true"
   },
   "require": {
    "match": {},
    "else": "local_port != 25"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:MtaStageConnect`

Configures SMTP connection greeting and hostname settings. Kind: singleton. Status: live. Permissions: `sysMtaStageConnect*`.

Fields: `hostname`, `script`, `smtpGreeting`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "smtpGreeting": {
    "match": {},
    "else": "system('hostname') + ' Stalwart ESMTP at your service'"
   },
   "hostname": {
    "match": {},
    "else": "system('hostname')"
   },
   "script": {
    "match": {},
    "else": "false"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:MtaStageData`

Configures message processing rules for the SMTP DATA stage. Kind: singleton. Status: live. Permissions: `sysMtaStageData*`.

Fields: `addAuthResultsHeader`, `addDateHeader`, `addDeliveredToHeader`, `addMessageIdHeader`, `addReceivedHeader`, `addReceivedSpfHeader`, `addReturnPathHeader`, `enableSpamFilter`, `maxMessageSize`, `maxMessages`, `maxReceivedHeaders`, `script`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "addAuthResultsHeader": {
    "match": {
     "0": {
      "if": "local_port == 25",
      "then": "true"
     }
    },
    "else": "false"
   },
   "addDateHeader": {
    "match": {
     "0": {
      "if": "local_port == 25",
      "then": "true"
     }
    },
    "else": "false"
   },
   "addDeliveredToHeader": true,
   "addMessageIdHeader": {
    "match": {
     "0": {
      "if": "local_port == 25",
      "then": "true"
     }
    },
    "else": "false"
   },
   "addReceivedHeader": {
    "match": {
     "0": {
      "if": "local_port == 25",
      "then": "true"
     }
    },
    "else": "false"
   },
   "addReceivedSpfHeader": {
    "match":
…
```


### `x:MtaStageEhlo`

Configures EHLO command requirements and validation. Kind: singleton. Status: live. Permissions: `sysMtaStageEhlo*`.

Fields: `rejectNonFqdn`, `require`, `script`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "rejectNonFqdn": {
    "match": {
     "0": {
      "if": "local_port == 25",
      "then": "true"
     }
    },
    "else": "false"
   },
   "require": {
    "match": {},
    "else": "true"
   },
   "script": {
    "match": {},
    "else": "false"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:MtaStageMail`

Configures MAIL FROM stage processing and sender validation. Kind: singleton. Status: live. Permissions: `sysMtaStageMail*`.

Fields: `isSenderAllowed`, `rewrite`, `script`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "isSenderAllowed": {
    "match": {},
    "else": "!is_empty(authenticated_as) || !key_exists('spam-block', sender_domain)"
   },
   "rewrite": {
    "match": {},
    "else": "false"
   },
   "script": {
    "match": {},
    "else": "false"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:MtaStageRcpt`

Configures RCPT TO stage processing and recipient validation. Kind: singleton. Status: live. Permissions: `sysMtaStageRcpt*`.

Fields: `allowRelaying`, `maxFailures`, `maxRecipients`, `rewrite`, `script`, `waitOnFail`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "maxFailures": {
    "match": {},
    "else": "5"
   },
   "waitOnFail": {
    "match": {},
    "else": "5s"
   },
   "maxRecipients": {
    "match": {},
    "else": "100"
   },
   "allowRelaying": {
    "match": {},
    "else": "!is_empty(authenticated_as)"
   },
   "rewrite": {
    "match": {},
    "else": "false"
   },
   "script": {
    "match": {},
    "else": "false"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:MtaSts`

Configures the MTA-STS policy for the server. Kind: singleton. Status: live. Permissions: `sysMtaSts*`.

Fields: `maxAge`, `mode`, `mxHosts`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "maxAge": 604800000,
   "mode": "testing",
   "mxHosts": {},
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:MtaTlsStrategy`

Defines a TLS security strategy for outbound connections. Kind: object. Status: live. Permissions: `sysMtaTlsStrategy*`.

Fields: `allowInvalidCerts`, `dane`, `description`, `mtaSts`, `mtaStsTimeout`, `name`, `startTls`, `tlsTimeout`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "name": "default",
   "allowInvalidCerts": false,
   "dane": "optional",
   "description": "Default TLS settings",
   "mtaSts": "optional",
   "startTls": "optional",
   "mtaStsTimeout": 300000,
   "tlsTimeout": 180000,
   "id": "jkr72dpsacqb"
  },
  {
   "name": "invalid-tls",
   "allowInvalidCerts": true,
   "dane": "optional",
   "description": "Allow invalid TLS certificates",
   "mtaSts": "optional",
   "startTls": "optional",
   "mtaStsTimeout": 300000,
   "tlsTimeout": 180000,
   "id": "jkr72dpsacab"
  }
 ],
 "notFound": []
}
```


### `x:MtaVirtualQueue`

Defines a virtual queue for organizing outbound message delivery. Kind: object. Status: live. Permissions: `sysMtaVirtualQueue*`.

Fields: `description`, `name`, `threadsPerNode`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "name": "dsn",
   "description": "Delivery Status Notification delivery queue",
   "threadsPerNode": 5,
   "id": "c"
  },
  {
   "name": "remote",
   "description": "Remote delivery queue",
   "threadsPerNode": 50,
   "id": "b"
  },
  {
   "name": "local",
   "description": "Local delivery queue",
   "threadsPerNode": 25,
   "id": "a"
  }
 ],
 "notFound": []
}
```


### `x:NetworkListener`

Defines a network listener for accepting incoming connections. Kind: object. Status: live. Permissions: `sysNetworkListener*`.

Fields: `bind`, `maxConnections`, `name`, `overrideProxyTrustedNetworks`, `protocol`, `socketBacklog`, `socketNoDelay`, `socketReceiveBufferSize`, `socketReuseAddress`, `socketReusePort`, `socketSendBufferSize`, `socketTosV4`, `socketTtl`, `tlsDisableCipherSuites`, `tlsDisableProtocols`, `tlsIgnoreClientOrder`, `tlsImplicit`, `tlsTimeout`, `useTls`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "name": "imaps",
   "bind": {
    "[::]:993": true
   },
   "protocol": "imap",
   "overrideProxyTrustedNetworks": {},
   "socketBacklog": 1024,
   "socketNoDelay": true,
   "socketReceiveBufferSize": null,
   "socketReuseAddress": true,
   "socketReusePort": true,
   "socketSendBufferSize": null,
   "socketTosV4": null,
   "socketTtl": null,
   "useTls": true,
   "tlsDisableCipherSuites": {},
   "tlsDisableProtocols": {},
   "tlsIgnoreClientOrder": true,
   "tlsImplicit": true,
   "tlsTimeout": 60000,
   "maxConnections": 8192,
   "id": "jkr72dq1afqb"
  },
  {
   "name": "submissions",
   "bind": {
    "[::]:465": true
   },
   "protocol": "smtp"
…
```


### `x:OAuthClient`

Defines a registered OAuth client application. Kind: object. Status: live. Permissions: `sysOAuthClient*`.

Fields: `clientId`, `contacts`, `createdAt` (server set), `description`, `expiresAt`, `logo`, `memberTenantId`, `redirectUris`, `secret`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "clientId": "adapters",
   "description": "Adapter test",
   "contacts": {},
   "createdAt": "2026-10-21T07:13:58Z",
   "expiresAt": null,
   "memberTenantId": null,
   "redirectUris": {
    "http://localhost:9999/callback": true
   },
   "logo": null,
   "id": "d"
  },
  {
   "clientId": "demo-react",
   "description": "Demo app (React)",
   "contacts": {},
   "createdAt": "2026-10-21T07:13:58Z",
   "expiresAt": null,
   "memberTenantId": null,
   "redirectUris": {
    "http://localhost:5173/callback": true
   },
   "logo": null,
   "id": "c"
  },
  {
   "clientId": "authfly",
   "description": "Authfly",
   "contacts": {},
   "createdAt": "2026-
…
```


### `x:OidcProvider`

Configures the OAuth and OpenID Connect provider settings. Kind: singleton. Status: live. Permissions: `sysOidcProvider*`.

Fields: `accessTokenExpiry`, `anonymousClientRegistration`, `authCodeExpiry`, `authCodeMaxAttempts`, `encryptionKey`, `idTokenExpiry`, `refreshTokenExpiry`, `refreshTokenRenewal`, `requireClientRegistration`, `signatureAlgorithm`, `signatureKey`, `userCodeExpiry`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "authCodeMaxAttempts": 3,
   "anonymousClientRegistration": false,
   "requireClientRegistration": true,
   "authCodeExpiry": 600000,
   "refreshTokenExpiry": "[redacted]",
   "refreshTokenRenewal": "[redacted]",
   "accessTokenExpiry": "[redacted]",
   "userCodeExpiry": 1800000,
   "idTokenExpiry": "[redacted]",
   "encryptionKey": {
    "secret": "[redacted]",
    "@type": "Value"
   },
   "signatureAlgorithm": "es256",
   "signatureKey": {
    "secret": "[redacted]",
    "@type": "Text"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:PublicKey`

Defines a public key for email encryption (OpenPGP or S/MIME). Kind: object. Status: live. Permissions: `sysPublicKey*`.

Fields: `accountId`, `createdAt` (server set), `description`, `emailAddresses`, `expiresAt`, `key`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:QueuedMessage`

Represents a queued email message pending delivery. Kind: object. Status: live. Permissions: `sysQueuedMessage*`.

Fields: `blobId` (server set), `createdAt` (server set), `envId`, `flags` (server set), `nextNotify` (server set), `nextRetry`, `priority`, `receivedFromIp` (server set), `receivedViaPort` (server set), `recipients`, `returnPath` (server set), `size` (server set).

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:ReportSettings`

Configures inbound report analysis and outbound report settings. Kind: singleton. Status: live. Permissions: `sysReportSettings*`.

Fields: `inboundReportAddresses`, `inboundReportForwarding`, `inboundReportMaxSize`, `outboundReportDomain`, `outboundReportSubmitter`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "inboundReportAddresses": {
    "postmaster@*": true
   },
   "inboundReportForwarding": true,
   "outboundReportDomain": null,
   "outboundReportSubmitter": {
    "match": {},
    "else": "system('hostname')"
   },
   "inboundReportMaxSize": 26214400,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Role`

Defines a named set of permissions that can be assigned to accounts, groups, or tenants. Kind: object. Status: live. Permissions: `sysRole*`.

Fields: `description`, `disabledPermissions`, `enabledPermissions`, `memberTenantId`, `roleIds`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "description": "Tenant Administrator",
   "memberTenantId": null,
   "roleIds": {},
   "enabledPermissions": {
    "authenticate": true,
    "authenticateWithAlias": true,
    "interactAi": true,
    "fetchAnyBlob": true,
    "liveDeliveryTest": true,
    "sysAccountGet": true,
    "sysAccountCreate": true,
    "sysAccountUpdate": true,
    "sysAccountDestroy": true,
    "sysAccountQuery": true,
    "sysAcmeProviderGet": true,
    "sysAcmeProviderCreate": true,
    "sysAcmeProviderUpdate": true,
    "sysAcmeProviderDestroy": true,
    "sysAcmeProviderQuery": true,
    "sysDkimSignatureGet": true,
    "sysDkimSignatureCreate": true,
    "sysDkimSig
…
```


### `x:Search`

Configures full-text search indexing for emails, calendars, contacts, and tracing. Kind: singleton. Status: live. Permissions: `sysSearch*`.

Fields: `defaultLanguage`, `indexBatchSize`, `indexCalendar`, `indexCalendarFields`, `indexContactFields`, `indexContacts`, `indexEmail`, `indexEmailFields`, `indexTelemetry`, `indexTracingFields`, `supportedLanguages`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "indexBatchSize": 100,
   "defaultLanguage": "en-US",
   "supportedLanguages": {
    "en-US": true
   },
   "indexCalendar": true,
   "indexCalendarFields": {
    "title": true,
    "description": true,
    "location": true,
    "owner": true,
    "attendee": true,
    "start": true,
    "uid": true
   },
   "indexContacts": true,
   "indexContactFields": {
    "member": true,
    "kind": true,
    "name": true,
    "nickname": true,
    "organization": true,
    "email": true,
    "phone": true,
    "onlineService": true,
    "address": true,
    "note": true,
    "uid": true
   },
   "indexEmail": true,
   "indexEmailFields": {
    "from": true,
…
```


### `x:SearchStore`

Configures the full-text search backend. Kind: singleton. Status: live. Permissions: `sysSearchStore*`.

Variants: `Default`, `ElasticSearch` (x:ElasticSearchStore), `Meilisearch` (x:MeilisearchStore), `FoundationDb` (x:FoundationDbStore), `PostgreSql` (x:PostgreSqlStore), `MySql` (x:MySqlStore).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "@type": "Default",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Security`

Configures automatic IP banning rules for abuse, authentication failures, and port scanning. Kind: singleton. Status: live. Permissions: `sysSecurity*`.

Fields: `abuseBanPeriod`, `abuseBanRate`, `authBanPeriod`, `authBanRate`, `loiterBanPeriod`, `loiterBanRate`, `scanBanPaths`, `scanBanPeriod`, `scanBanRate`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "abuseBanRate": {
    "count": 35,
    "period": 86400000
   },
   "abuseBanPeriod": null,
   "authBanRate": {
    "count": 100,
    "period": 86400000
   },
   "authBanPeriod": null,
   "loiterBanRate": {
    "count": 150,
    "period": 86400000
   },
   "loiterBanPeriod": null,
   "scanBanPaths": {
    "*.php*": true,
    "*.cgi*": true,
    "*.asp*": true,
    "*/wp-*": true,
    "*/php*": true,
    "*/cgi-bin*": true,
    "*xmlrpc*": true,
    "*../*": true,
    "*/..*": true,
    "*joomla*": true,
    "*wordpress*": true,
    "*drupal*": true
   },
   "scanBanRate": {
    "count": 30,
    "period": 86400000
   },
   "scanBanPeriod": null,
   
…
```


### `x:SenderAuth`

Configures sender authentication verification including DKIM, SPF, DMARC, and ARC. Kind: singleton. Status: live. Permissions: `sysSenderAuth*`.

Fields: `arcVerify`, `dkimSignDomain`, `dkimStrict`, `dkimVerify`, `dmarcVerify`, `reverseIpVerify`, `spfEhloVerify`, `spfFromVerify`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "dkimSignDomain": {
    "match": {
     "0": {
      "if": "is_local_domain(sender_domain) && !is_empty(authenticated_as)",
      "then": "sender_domain"
     }
    },
    "else": "false"
   },
   "dkimStrict": true,
   "dkimVerify": {
    "match": {},
    "else": "relaxed"
   },
   "spfEhloVerify": {
    "match": {
     "0": {
      "if": "local_port == 25",
      "then": "relaxed"
     }
    },
    "else": "disable"
   },
   "spfFromVerify": {
    "match": {
     "0": {
      "if": "local_port == 25",
      "then": "relaxed"
     }
    },
    "else": "disable"
   },
   "arcVerify": {
    "match": {},
    "else": "disable"
   },
   "dmarcVerify":
…
```


### `x:Sharing`

Configures sharing settings for calendars, address books, and files. Kind: singleton. Status: live. Permissions: `sysSharing*`.

Fields: `allowDirectoryQueries`, `maxShares`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "allowDirectoryQueries": false,
   "maxShares": 10,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:SieveSystemInterpreter`

Configures the system-level Sieve script interpreter settings and limits. Kind: singleton. Status: live. Permissions: `sysSieveSystemInterpreter*`.

Fields: `defaultFromAddress`, `defaultFromName`, `defaultReturnPath`, `dkimSignDomain`, `duplicateExpiry`, `maxCpuCycles`, `maxNestedIncludes`, `maxOutMessages`, `maxReceivedHeaders`, `maxRedirects`, `maxVarSize`, `messageIdHostname`, `noCapabilityCheck`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "defaultFromAddress": {
    "match": {},
    "else": "'MAILER-DAEMON@' + system('domain')"
   },
   "defaultFromName": {
    "match": {},
    "else": "'Automated Message'"
   },
   "messageIdHostname": null,
   "duplicateExpiry": 604800000,
   "noCapabilityCheck": true,
   "defaultReturnPath": {
    "match": {},
    "else": ""
   },
   "dkimSignDomain": {
    "match": {},
    "else": "system('domain')"
   },
   "maxCpuCycles": 1048576,
   "maxNestedIncludes": 5,
   "maxOutMessages": 5,
   "maxReceivedHeaders": 50,
   "maxRedirects": 3,
   "maxVarSize": 52428800,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:SieveSystemScript`

Defines a system Sieve script executed by the server. Kind: object. Status: live. Permissions: `sysSieveSystemScript*`.

Fields: `contents`, `description`, `isActive`, `name`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:SieveUserInterpreter`

Configures the user-level Sieve script interpreter settings and limits. Kind: singleton. Status: live. Permissions: `sysSieveUserInterpreter*`.

Fields: `allowedNotifyUris`, `defaultExpiryDuplicate`, `defaultExpiryVacation`, `defaultSubject`, `defaultSubjectPrefix`, `disableCapabilities`, `dkimSignDomain`, `maxCpuCycles`, `maxHeaderSize`, `maxIncludes`, `maxLocalVars`, `maxMatchVars`, `maxNestedBlocks`, `maxNestedForEvery`, `maxNestedIncludes`, `maxNestedTests`, `maxOutMessages`, `maxReceivedHeaders`, `maxRedirects`, `maxScriptNameLength`, `maxScriptSize`, `maxScripts`, `maxStringLength`, `maxVarNameLength`, `maxVarSize`, `protectedHeaders`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "defaultExpiryDuplicate": 604800000,
   "defaultExpiryVacation": 2592000000,
   "disableCapabilities": {},
   "allowedNotifyUris": {
    "mailto": true
   },
   "protectedHeaders": {
    "Original-Subject": true,
    "Original-From": true,
    "Received": true,
    "Auto-Submitted": true
   },
   "defaultSubject": "Automated reply",
   "defaultSubjectPrefix": "Auto: ",
   "maxCpuCycles": 5000,
   "maxHeaderSize": 1024,
   "maxIncludes": 3,
   "maxLocalVars": 128,
   "maxMatchVars": 30,
   "maxScriptNameLength": 512,
   "maxNestedBlocks": 15,
   "maxNestedForEvery": 3,
   "maxNestedIncludes": 3,
   "maxNestedTests": 15,
   "maxOutMessages": 3,
   "
…
```


### `x:SieveUserScript`

Defines a global Sieve script available for user imports. Kind: object. Status: live. Permissions: `sysSieveUserScript*`.

Fields: `contents`, `description`, `isActive`, `name`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:SpamClassifier`

Configures the spam classifier model, training parameters, and auto-learning settings. Kind: singleton. Status: live. Permissions: `sysSpamClassifier*`.

Fields: `holdSamplesFor`, `learnHamFromCard`, `learnHamFromReply`, `learnSpamFromRblHits`, `learnSpamFromTraps`, `minHamSamples`, `minSpamSamples`, `model`, `reservoirCapacity`, `trainFrequency`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "model": {
    "parameters": {
     "alpha": 2.0,
     "beta": 1.0,
     "numFeatures": "20",
     "l1Ratio": 0.001,
     "l2Ratio": 0.0001
    },
    "featureL2Normalize": true,
    "featureLogScale": true,
    "@type": "FtrlFh"
   },
   "learnHamFromCard": true,
   "learnSpamFromRblHits": 2,
   "learnSpamFromTraps": true,
   "holdSamplesFor": 15552000000,
   "minHamSamples": 100,
   "minSpamSamples": 100,
   "reservoirCapacity": 1024,
   "trainFrequency": 43200000,
   "learnHamFromReply": true,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:SpamDnsblServer`

Defines a DNSBL server used for spam filtering lookups. Kind: object. Status: live. Permissions: `sysSpamDnsblServer*`.

Variants: `Any` (x:SpamDnsblServerAny), `Url` (x:SpamDnsblServerUrl), `Domain` (x:SpamDnsblServerDomain), `Email` (x:SpamDnsblServerEmail), `Ip` (x:SpamDnsblServerIp), `Header` (x:SpamDnsblServerHeader), `Body` (x:SpamDnsblServerBody).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "tag": {
    "match": {
     "0": {
      "if": "octets[0] != 127",
      "then": "false"
     },
     "1": {
      "if": "octets[3] == 1",
      "then": "'RBL_SENDERSCORE_BOT'"
     },
     "2": {
      "if": "octets[3] == 2",
      "then": "'RBL_SENDERSCORE_NA'"
     },
     "3": {
      "if": "octets[3] == 3",
      "then": "'RBL_SENDERSCORE_NA_BOT'"
     },
     "4": {
      "if": "octets[3] == 4",
      "then": "'RBL_SENDERSCORE_PRST'"
     },
     "5": {
      "if": "octets[3] == 5",
      "then": "'RBL_SENDERSCORE_PRST_BOT'"
     },
     "6": {
      "if": "octets[3] == 6",
      "then": "'RBL_SENDERSCORE_PRST_NA'"
     },
     "7": {
     
…
```


### `x:SpamDnsblSettings`

Configures DNSBL query limits for spam filtering. Kind: singleton. Status: live. Permissions: `sysSpamDnsblSettings*`.

Fields: `domainLimit`, `emailLimit`, `ipLimit`, `urlLimit`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "domainLimit": 50,
   "emailLimit": 50,
   "ipLimit": 50,
   "urlLimit": 50,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:SpamFileExtension`

Defines a file extension classification rule for spam filtering. Kind: object. Status: live. Permissions: `sysSpamFileExtension*`.

Fields: `contentTypes`, `extension`, `isArchive`, `isBad`, `isNz`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "extension": "com",
   "isArchive": false,
   "isBad": true,
   "isNz": false,
   "contentTypes": {},
   "id": "jkr72e3ih0aa"
  },
  {
   "extension": "chm",
   "isArchive": false,
   "isBad": true,
   "isNz": false,
   "contentTypes": {},
   "id": "jkr72e3ih2qa"
  },
  {
   "extension": "bat",
   "isArchive": false,
   "isBad": true,
   "isNz": false,
   "contentTypes": {},
   "id": "jkr72e3ih2aa"
  }
 ],
 "notFound": []
}
```


### `x:SpamLlm`

Configures the LLM-based spam classifier. Kind: singleton. Status: live. Permissions: `sysSpamLlm*`.

Variants: `Disable`, `Enable` (x:SpamLlmProperties).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "@type": "Disable",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:SpamPyzor`

Configures the Pyzor collaborative spam detection service. Kind: singleton. Status: live. Permissions: `sysSpamPyzor*`.

Fields: `allowCount`, `blockCount`, `enable`, `host`, `port`, `ratio`, `timeout`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "blockCount": 5,
   "enable": true,
   "host": "public.pyzor.org",
   "port": 24441,
   "ratio": 0.2,
   "timeout": 5000,
   "allowCount": 10,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:SpamRule`

Defines a spam filter rule for message classification. Kind: object. Status: live. Permissions: `sysSpamRule*`.

Variants: `Any` (x:SpamRuleAny), `Url` (x:SpamRuleUrl), `Domain` (x:SpamRuleDomain), `Email` (x:SpamRuleEmail), `Ip` (x:SpamRuleIp), `Header` (x:SpamRuleHeader), `Body` (x:SpamRuleBody).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "condition": {
    "match": {
     "0": {
      "if": "$FORGED_SENDER && $MAILLIST",
      "then": "'FORGED_SENDER_MAILLIST'"
     }
    },
    "else": "false"
   },
   "name": "STWT_FORGED_SENDER_LIST",
   "description": null,
   "enable": true,
   "priority": 1002,
   "@type": "Any",
   "id": "jkr72e1eajqa"
  },
  {
   "condition": {
    "match": {
     "0": {
      "if": "$FORGED_RECIPIENTS && $MAILLIST",
      "then": "'FORGED_RECIPIENTS_MAILLIST'"
     }
    },
    "else": "false"
   },
   "name": "STWT_FORGED_RCPT_LIST",
   "description": null,
   "enable": true,
   "priority": 1001,
   "@type": "Any",
   "id": "jkr72e1eajaa"
  },
  {
   "co
…
```


### `x:SpamSettings`

Configures global spam filter thresholds, greylisting, and trust settings. Kind: singleton. Status: live. Permissions: `sysSpamSettings*`.

Fields: `enable`, `greylistFor`, `scoreDiscard`, `scoreReject`, `scoreSpam`, `spamFilterRulesUrl`, `trustContacts`, `trustReplies`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "trustContacts": true,
   "enable": true,
   "greylistFor": null,
   "scoreDiscard": 0.0,
   "scoreReject": 0.0,
   "scoreSpam": 5.0,
   "trustReplies": true,
   "spamFilterRulesUrl": "https://github.com/stalwartlabs/spam-filter/releases/latest/download/spam-filter-rules.json.gz",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:SpamTag`

Defines a score or action assigned to a spam classification tag. Kind: object. Status: live. Permissions: `sysSpamTag*`.

Variants: `Score` (x:SpamTagScore), `Discard` (x:SpamTagAction), `Reject` (x:SpamTagAction).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "tag": "ARC_ALLOW",
   "score": 0.0,
   "@type": "Score",
   "id": "jkr72e1mbtqa"
  },
  {
   "tag": "ABUSE_SURBL",
   "score": 5.0,
   "@type": "Score",
   "id": "jkr72e1mbtaa"
  },
  {
   "tag": "ABUSE_FROM_INJECTOR",
   "score": 2.0,
   "@type": "Score",
   "id": "jkr72e1mbsqa"
  }
 ],
 "notFound": []
}
```


### `x:SpamTrainingSample`

Stores an email sample used for spam classifier training. Kind: object. Status: live. Permissions: `sysSpamTrainingSample*`.

Fields: `accountId`, `blobId`, `deleteAfterUse`, `expiresAt` (server set), `from` (server set), `isSpam`, `subject` (server set).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "from": "noreply@authfly.test",
   "subject": "Your sign-in link",
   "blobId": "ebne3wgaqpcjt21p0nbv7f3lofjdvycychbigpre3k9tq7hswnhtz333333q333333333333333qc",
   "isSpam": true,
   "accountId": null,
   "expiresAt": "2027-04-19T07:14:23Z",
   "deleteAfterUse": false,
   "id": "jkr70zaoabaa"
  },
  {
   "from": "noreply@authfly.test",
   "subject": "Verify your email address",
   "blobId": "ea0ddzps1ano3vpu9wullraenpr7klfd0ooiwvgxaguqtbbydinll333333q333333333333333qc",
   "isSpam": true,
   "accountId": null,
   "expiresAt": "2027-04-19T07:14:18Z",
   "deleteAfterUse": false,
   "id": "jkr70pfsaaqa"
  },
  {
   "from": "noreply@authfly.test",
   
…
```


### `x:SpfReportSettings`

Configures SPF authentication failure report generation. Kind: singleton. Status: live. Permissions: `sysSpfReportSettings*`.

Fields: `dkimSignDomain`, `fromAddress`, `fromName`, `sendFrequency`, `subject`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "fromAddress": {
    "match": {},
    "else": "'noreply-spf@' + system('domain')"
   },
   "fromName": {
    "match": {},
    "else": "'Report Subsystem'"
   },
   "sendFrequency": {
    "match": {},
    "else": "[1, 1d]"
   },
   "dkimSignDomain": {
    "match": {},
    "else": "system('domain')"
   },
   "subject": {
    "match": {},
    "else": "'SPF Authentication Failure Report'"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:StoreLookup`

Defines an external store used for lookups. Kind: object. Status: live. Permissions: `sysStoreLookup*`.

Fields: `namespace`, `store`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:SystemSettings`

Configures core server settings including hostname, thread pool, and network services. Kind: singleton. Status: live. Permissions: `sysSystemSettings*`.

Fields: `defaultCertificateId`, `defaultDomainId`, `defaultHostname`, `mailExchangers`, `maxConnections`, `providerInfo`, `proxyTrustedNetworks`, `services`, `threadPoolSize`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "defaultHostname": "",
   "defaultDomainId": "p333333333333",
   "defaultCertificateId": null,
   "threadPoolSize": null,
   "maxConnections": 8192,
   "proxyTrustedNetworks": {},
   "mailExchangers": {
    "0": {
     "hostname": null,
     "priority": 10
    }
   },
   "services": {
    "caldav": {
     "hostname": null,
     "cleartext": false
    },
    "carddav": {
     "hostname": null,
     "cleartext": false
    },
    "imap": {
     "hostname": null,
     "cleartext": false
    },
    "jmap": {
     "hostname": null,
     "cleartext": false
    },
    "managesieve": {
     "hostname": null,
     "cleartext": false
    },
    "pop3": {
   
…
```


### `x:Task`

Represents a background task scheduled for execution. Kind: object. Status: live. Permissions: `sysTask*`.

Variants: `IndexDocument` (x:TaskIndexDocument), `UnindexDocument` (x:TaskIndexDocument), `IndexTrace` (x:TaskIndexTrace), `CalendarAlarmEmail` (x:TaskCalendarAlarmEmail), `CalendarAlarmNotification` (x:TaskCalendarAlarmNotification), `CalendarItipMessage` (x:TaskCalendarItipMessage), `MergeThreads` (x:TaskMergeThreads), `DmarcReport` (x:TaskDmarcReport), `TlsReport` (x:TaskTlsReport), `RestoreArchivedItem` (x:TaskRestoreArchivedItem), `DestroyAccount` (x:TaskDestroyAccount), `AccountMaintenance` (x:TaskAccountMaintenance), `TenantMaintenance` (x:TaskTenantMaintenance), `StoreMaintenance` (x:TaskStoreMaintenance), `SpamFilterMaintenance` (x:TaskSpamFilterMaintenance), `AcmeRenewal` (x:TaskDomainManagement), `DkimManagement` (x:TaskDomainManagement), `DnsManagement` (x:TaskDnsManagement).

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:TaskManager`

Configures task execution settings including retry strategies. Kind: singleton. Status: live. Permissions: `sysTaskManager*`.

Fields: `maxAttempts`, `strategy`, `totalDeadline`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "maxAttempts": 3,
   "strategy": {
    "factor": 2.0,
    "initialDelay": 60000,
    "maxDelay": 1800000,
    "jitter": true,
    "@type": "ExponentialBackoff"
   },
   "totalDeadline": 21600000,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Tenant`

Defines a tenant for multi-tenant environments with isolated resources and quotas. Kind: object. Status: live. Permissions: `sysTenant*`.

Fields: `createdAt` (server set), `logo`, `name`, `permissions`, `quotas`, `roles`, `usedDiskQuota` (server set).

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:TlsExternalReport`

Stores a TLS aggregate report received from an external source. Kind: object. Status: live. Permissions: `sysTlsExternalReport*`.

Fields: `expiresAt`, `from`, `memberTenantId`, `receivedAt`, `report`, `subject`, `to`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:TlsInternalReport`

Stores an outbound TLS aggregate report pending delivery. Kind: object. Status: live. Permissions: `sysTlsInternalReport*`.

Fields: `createdAt`, `deliverAt`, `domain`, `httpRua`, `mailRua`, `policyIdentifiers`, `report`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


### `x:TlsReportSettings`

Configures TLS aggregate report generation. Kind: singleton. Status: live. Permissions: `sysTlsReportSettings*`.

Fields: `contactInfo`, `dkimSignDomain`, `fromAddress`, `fromName`, `maxReportSize`, `orgName`, `sendFrequency`, `subject`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "contactInfo": {
    "match": {},
    "else": "false"
   },
   "fromAddress": {
    "match": {},
    "else": "'noreply-tls@' + system('domain')"
   },
   "fromName": {
    "match": {},
    "else": "'Report Subsystem'"
   },
   "maxReportSize": {
    "match": {},
    "else": "5242880"
   },
   "orgName": {
    "match": {},
    "else": "system('domain')"
   },
   "sendFrequency": {
    "match": {},
    "else": "daily"
   },
   "dkimSignDomain": {
    "match": {},
    "else": "system('domain')"
   },
   "subject": {
    "match": {},
    "else": "'TLS Aggregate Report'"
   },
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:Trace`

Stores a message delivery trace with associated events. Kind: object. Status: live: Enterprise only. Permissions: `sysTrace*`.

Fields: `events`, `from` (server set), `size` (server set), `timestamp` (server set), `to` (server set).

```json
{
 "type": "forbidden",
 "description": "This feature is only available in the Enterprise edition. Obtain your trial license at https://license.stalw.art/trial."
}
```


### `x:Tracer`

Defines a logging and tracing output method. Kind: object. Status: live. Permissions: `sysTracer*`.

Variants: `Log` (x:TracerLog), `Stdout` (x:TracerStdout), `Journal` (x:TracerCommon), `OtelHttp` (x:TracerOtelHttp), `OtelGrpc` (x:TracerOtelGrpc).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "path": "/var/log/stalwart",
   "prefix": "stalwart.log",
   "rotate": "daily",
   "ansi": false,
   "multiline": false,
   "enable": true,
   "level": "info",
   "lossy": false,
   "events": {},
   "eventsPolicy": "exclude",
   "@type": "Log",
   "id": "jkr72dq1aiab"
  }
 ],
 "notFound": []
}
```


### `x:TracingStore`

Configures the storage backend for tracing data. Kind: singleton. Status: live. Permissions: `sysTracingStore*`.

Variants: `Disabled`, `Default`, `FoundationDb` (x:FoundationDbStore), `PostgreSql` (x:PostgreSqlStore), `MySql` (x:MySqlStore).

```json
{
 "accountId": "d333333",
 "list": [
  {
   "@type": "Default",
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:WebDav`

Configures WebDAV protocol settings including property limits and locking. Kind: singleton. Status: live. Permissions: `sysWebDav*`.

Fields: `deadPropertyMaxSize`, `enableAssistedDiscovery`, `livePropertyMaxSize`, `maxLockTimeout`, `maxLocks`, `maxResults`, `requestMaxSize`.

```json
{
 "accountId": "d333333",
 "list": [
  {
   "enableAssistedDiscovery": true,
   "maxLockTimeout": 3600000,
   "maxLocks": 10,
   "deadPropertyMaxSize": 1024,
   "livePropertyMaxSize": 250,
   "requestMaxSize": 26214400,
   "maxResults": 2000,
   "id": "singleton"
  }
 ],
 "notFound": []
}
```


### `x:WebHook`

Defines a webhook endpoint for event notifications. Kind: object. Status: live. Permissions: `sysWebHook*`.

Fields: `allowInvalidCerts`, `discardAfter`, `enable`, `events`, `eventsPolicy`, `httpAuth`, `httpHeaders`, `level`, `lossy`, `signatureKey`, `throttle`, `timeout`, `url`.

```json
{
 "accountId": "d333333",
 "list": [],
 "notFound": []
}
```


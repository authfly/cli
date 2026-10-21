# GDPR

Authfly keeps personal data in two places: **Stalwart**, which holds the account, the mailbox, contacts and calendars, and **Authfly's store**, which holds the verification state, consent records and session revocations. Authfly also writes an **audit log**. The features below cover both places and were verified live (`bun e2e/gdpr.test.ts`, 11 steps).

| Right or duty | Feature | Status |
| --- | --- | --- |
| Access, portability (Art. 15, 20) | JSON export: `GET /api/v1/me/export` (the user), console "Download export" (the operator) | done, verified |
| Erasure (Art. 17) | `DELETE /api/v1/me` with the password; console "Erase" with typed confirmation | done, verified in Stalwart and Authfly |
| Consent (Art. 7(1)) | records of terms acceptance at sign-up and of every OIDC consent decision; `GET /api/v1/me/consents` | done |
| Accountability (Art. 5(2)) | hash-chained audit logs (Authfly and console) with no IP addresses | done |
| Storage limitation (Art. 5(1)(e)) | `AUTHFLY_AUDIT_RETENTION` (default 8760h), daily pruning, "Run retention now"; Stalwart `x:DataRetention` | done |
| Security (Art. 32) | lock-down ([Security](security.md)), per-account encryption at rest in Stalwart, disk encryption notes | documented, partly operator's job |
| Removing unverified accounts after N days | cleanup job | stub: not implemented, see below |
| Withdrawing an OIDC consent | revoke per client | stub: the record exists, but Stalwart has no per-client grant revocation API; "sign out everywhere" revokes Authfly sessions |

## Export

The export (`format: authfly-export/1`) contains:

- `account`: the Stalwart `x:Account` record without `credentials`. Password hashes never leave the server.
- `authfly`: when the address was verified, consent records, and when sessions were revoked.
- `audit`: every audit event about the person.
- `mailbox`: mailboxes, identities, and messages (headers, text bodies, attachment list with blob ids), read over JMAP. The service account uses `impersonate` with the account's id. Capped at 5000 messages with a `truncated` flag.

Each export is itself logged (`export`, actor `self` or `console:<admin>`).

## Erasure

`Service.Erase` (`server/core/gdpr.go`):

1. Samples the message ids, then runs `x:Account/set destroy`. Stalwart schedules a `DestroyAccount` task, which runs immediately in the community edition. Enterprise can delay it with `deleted_accounts_retention`; the console warns when `x:DataRetention.archiveDeletedAccountsFor` is set.
2. **Verifies** that the sampled messages are no longer readable (`Email/get` returns `notFound`), and reports `verified`.
3. Schedules a blob-store purge (`StoreMaintenance purgeBlob`) so that blob bytes go now instead of at the daily `blobCleanupSchedule`.
4. Deletes Authfly's records for the address and revokes every session. The revocation is kept under a pseudonym so that a stolen token cannot come back if the address is registered again.
5. Rewrites the audit log: the address becomes `erased:<sha256 prefix>` and the hash chain is re-anchored. Then it logs the erasure under the pseudonym.

What the e2e test checks after erasure:

- The account is gone: `x:Account/get` returns notFound, and a password login gets 401.
- The messages are gone: not readable by id, and not found by full-text or subject search.
- The old Authfly session token gets 401, and so does a sign-in.
- The address no longer appears anywhere in `store.json` or the audit log, while the pseudonym and the erase event do.
- A new sign-up with the same name gets a new, empty account.

Observed limitation: right after the destroy, an unfiltered `Email/query` on the old account id can still return a dangling id for a while. It is an index bitmap entry with no content: `Email/get` returns notFound and searches find nothing. It disappears with Stalwart's maintenance.

## Audit log

The log is JSON lines in `AUTHFLY_AUDIT_LOG` (default `<store>-audit.jsonl`). Each entry carries `prev` and `hash` (SHA-256 over the entry), so an edited or deleted line breaks the chain. The console shows whether the chain is intact. Events: sign_up, verify_email, sign_in (ok/denied, with the method), magic_link, password_reset, sign_out, sign_out_everywhere, consent, export, erase, retention. A failed sign-in for an address that has no account is logged under a pseudonym, so the log does not collect identifiers of non-users.

## Encryption at rest

- Mail: Stalwart supports per-account encryption of stored messages with the user's own key (`x:Account.encryptionAtRest`: OpenPGP or S/MIME, AES-128/256, ChaCha20-Poly1305). It is allowed server-wide (`x:Email.encryptAtRest`, true here). Authfly creates accounts with `Disabled`, because enabling it needs the user's public key. Note that encrypted mail cannot be searched or exported in plain text.
- Volumes: encrypt `stalwart-data`, `authfly-data` and `console-data` at the disk level (LUKS, or the cloud provider's encrypted disks). Neither Stalwart's RocksDB store nor Authfly's JSON store encrypts itself.
- In transit: use TLS for Authfly and the mail ports. Inside the compose network, Authfly talks to Stalwart in plain HTTP; on a shared host, keep them on one private network.

## Retention

- Authfly: `AUTHFLY_AUDIT_RETENTION` (Go duration, default `8760h` = 1 year; `0` keeps everything). Pruning runs daily and from the console. One-time tokens (verify, magic link, reset) expire with their own TTLs: 48 h, 15 min and 30 min.
- Stalwart: `x:DataRetention` (`expungeTrashAfter`, `archiveDeletedAccountsFor` = null so erasure is final, `holdTracesFor`, `holdMetricsFor`, ...), editable in the console.
- Stub: deleting accounts that were never verified after N days is not implemented. The console lists users with their verification state; erase them by hand or script it against the admin API.

## Self-service API

| Method and path | Auth | Result |
| --- | --- | --- |
| `GET /api/v1/me/export` | session cookie or `Authorization: Bearer <token>` | the export JSON |
| `GET /api/v1/me/consents` | same | consent records |
| `GET /api/v1/me/audit` | same | the user's last 200 audit events |
| `POST /api/v1/me/sign-out-everywhere` | same | revokes every session |
| `DELETE /api/v1/me` `{"password": "..."}` | same, plus the password | erasure report |

Internal admin API (console only, `AUTHFLY_ADMIN_ADDR`, header `X-Authfly-Admin-Key`): `GET /admin/v1/users/{addr}`, `GET .../export`, `POST .../erase`, `POST .../revoke`, `GET /admin/v1/audit`, `GET`/`POST /admin/v1/retention[/run]`.

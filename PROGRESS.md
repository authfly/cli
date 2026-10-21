# Authfly progress log

Times are Europe/Moscow (UTC+3).

- 2026-10-21 03:13 Start. No fitting repo in the ui8kit org (`gh repo list ui8kit`): no authfly-like repo. Local git repo at /workspace/authfly, ready to push once a URL is given.
- 03:15 Docker installed on the box (docker.io), dockerd running.
- 03:16 ui8kit/codegen read (README, docs/architecture.md, contract.md, runtimes.md, specs-guide.md; docs/bricks.md does not exist upstream). Real runtimes: svelte, react, vue, solid, templ, twig, latte, jinja2 (static HTML is not a separate runtime in 2.0). Bricks are `xgen/specs/ui/<name>.json` (+ variants), not `bricks/<name>/<name>.def.ts` (that was 0.1).
- 03:20 Stalwart v0.16.27 probed in a container: bootstrap via JMAP `x:Bootstrap/set`, account creation `x:Account/set`, password change, `POST /api/auth` + `/auth/token` PKCE, `/auth/userinfo`, SMTP delivery on 25, JMAP mail read. All verified live.
- 03:25 Authfly organisms (6) + blocks authored with the xgen builder in specs/, overlaid onto a pristine codegen checkout (.cache/codegen, pinned in codegen.lock) by tools/gen-ui.sh; `bun run check` of codegen: ok, including real-engine DOM parity of templ, solid, twig, jinja2, latte vs React (491 block cases incl. the Authfly ones).
- 03:33 Exported the generated widgets to packages/ui/<runtime> (8 runtimes).
- 03:37 Go core (server/core), templ hosted pages (server/web), JSON API, OIDC handoff, extension stubs (server/ext).
- 03:40 TS adapter (packages/adapters/ts), React demo (apps/demo-react), docker-compose stack (Stalwart v0.16 + authfly + demo-react).
- 03:42 Box quirk: a legacy iptables FORWARD DROP policy (other dockerd) blocked container-to-container and container DNS traffic; added narrow iptables-legacy DOCKER-USER accept rules for 172.16.0.0/12 (box only, not part of the repo).
- 03:46 e2e/flow.test.ts: 13/13 steps pass against the compose stack (sign-up, verification mail via JMAP, magic link, sign-out, username+password, email+password, wrong password, reset, OIDC SSO into the React demo with consent, deny, JSON API).
- 03:50 ui8px: repo policy in .ui8px (defaults + 5 utilities of upstream templ primitives); `npx ui8px@latest lint` → 0 violations.
- 03:55 PHP and Python adapters (JSON API + OIDC RP); e2e now 15/15 (adds Python and PHP OIDC + API steps).
- 04:00 Codegen fixes for `bun run verify`: typed identifier field, required confirm label, organism id prefix, codex status (tools/codex-status.py). `tools/gen-ui.sh --verify` → check ok (parity templ/solid/twig/jinja2/latte vs React), codex validate ok, typecheck ok, 839 tests pass, 0 fail.
- 04:05 Docs (docs/*.md, 8 runtime guides) and the static site (site/, Go templ → site/dist, 18 pages + index, 14 live previews). `bun run site`.
- NEXT: screenshots (390/1440, light/dark) into /workspace/authfly-shots, README, final report.
- 04:15 Rebuilt the stack with the regenerated widgets; e2e 15/15 again. e2e/screenshots.mjs: 44 screenshots (11 pages × light/dark × 390/1440) in /workspace/authfly-shots. README.

## Phase 2: API audit, lock-down, Authfly Console, GDPR

- 09:50 tools/stalwart-audit.py + tools/stalwart-api-doc.py → docs/stalwart-api.md: 117 x: objects (109 verified live with get/query, 8 restricted and explained), 29 HTTP endpoints probed, JMAP data methods, GDPR map. There is no REST management API in v0.16 (`/api/principal` gives 404); management is JMAP `x:*`.
- 10:05 Lock-down: Stalwart HTTP on 127.0.0.1:8080 only; Authfly proxies only the OIDC endpoints (discovery rewritten); `authfly init-stalwart` (compose stalwart-init): least-privilege role + service account, web UI off (UpdateApps), OIDC registration locked, clients registered. e2e/security.test.ts. Commit 4137ee0.
- 10:20 GDPR core: hash-chained audit log (server/core/audit.go), consent records, per-address session revocation, Export/Erase, retention, self-service API, internal admin API :4001. Commit 93c5ce3.
- 10:35 Authfly Console (apps/console): schema-driven smart configurator (143 views), users, request builder, scenarios, GDPR, logs; e2e/console.test.ts 19/19. Commit 9052555.
- 10:45 Finding: after x:Account destroy, Email/get gives notFound and searches find nothing, but an unfiltered Email/query can return a dangling id. Erasure now verifies the sampled messages are unreadable and schedules StoreMaintenance purgeBlob (service role + sysTaskCreate, taskStoreMaintenance). Failed sign-ins for non-accounts are logged under a pseudonym. e2e/gdpr.test.ts 11/11; security 11/11; flow 15/15. Commit 12f143d.
- 10:55 Console screenshots: 44 in /workspace/authfly-shots/console-*.png. Docs: security.md, gdpr.md, console.md, getting-started/stalwart/README updated, site nav (22 pages).

## Phase 3: deploy CLI (docker + incus), policy packs, rename to Authfly

- 11:49 Incus 6.0.4 (Debian LTS) installed; incusd started by hand (no systemd on the box). A dpkg conffile prompt (fuse.conf) had hung apt: fixed with --force-confold. OCI app containers need Incus ≥ 6.3 (verified: linuxcontainers.org news 2024-07-12), so the Incus target uses system containers + checksum-verified static binaries pushed from the host. Box quirk: the incus client blocks when stdin is an open pipe (always </dev/null).
- 12:00 Box quirks (not repo): box rebooted (docker reinstalled); containers on user-defined docker networks and on incus bridges have no internet; bridge-nf-call-iptables=1 dropped container↔container traffic → set to 0.
- 12:02 Rename Authkit → Authfly (commit 6b3c976); module github.com/authfly/authfly, LICENSE Auth Fly, @authfly/* packages (afdb806). `npm view authfly` → 404 (free). GitHub org authfly: repos authkit (private, EMPTY), website, authkit-ts (not empty). No authfly repo; the empty authfly/authkit is set as origin, NOT pushed.
- 12:15 server/deploy: authfly.yaml schema + validation, 0600 secrets, policy packs (gdpr, us-pii, ru-152fz) + templates, app kit, channel manifest with sha256, docker + incus drivers, nftables, AES-256-GCM backups, doctor, CLI + wizard, unit tests (f6ea91f).
- 12:50 Docker target deployed for real (React + GDPR): doctor all PASS except expected WARNs (tls off, no backup yet). Fixed on the way: stalwart file capability vs cap_drop, missing STALWART_PUBLIC_URL (doctor caught a wrong issuer), Pyzor off (privacy + ReloadSettings no longer needs DNS). (5f4933e)
- NEXT: e2e against docker deploy, upgrade 0.3.0→0.3.1 + rollback, backup/restore; incus deploy (templ + 152-FZ) + e2e; npm package `authfly`; docs/deploy.md, docs/policies.md.

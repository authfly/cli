# Authkit progress log

Times are Europe/Moscow (UTC+3).

- 2026-10-21 03:13 Start. No fitting repo in the ui8kit org (`gh repo list ui8kit`): no authkit-like repo. Local git repo at /workspace/authkit, ready to push once a URL is given.
- 03:15 Docker installed on the box (docker.io), dockerd running.
- 03:16 ui8kit/codegen read (README, docs/architecture.md, contract.md, runtimes.md, specs-guide.md; docs/bricks.md does not exist upstream). Real runtimes: svelte, react, vue, solid, templ, twig, latte, jinja2 (static HTML is not a separate runtime in 2.0). Bricks are `xgen/specs/ui/<name>.json` (+ variants), not `bricks/<name>/<name>.def.ts` (that was 0.1).
- 03:20 Stalwart v0.16.27 probed in a container: bootstrap via JMAP `x:Bootstrap/set`, account creation `x:Account/set`, password change, `POST /api/auth` + `/auth/token` PKCE, `/auth/userinfo`, SMTP delivery on 25, JMAP mail read. All verified live.
- 03:25 Authkit organisms (6) + blocks authored with the xgen builder in specs/, overlaid onto a pristine codegen checkout (.cache/codegen, pinned in codegen.lock) by tools/gen-ui.sh; `bun run check` of codegen: ok, including real-engine DOM parity of templ, solid, twig, jinja2, latte vs React (491 block cases incl. the Authkit ones).
- 03:33 Exported the generated widgets to packages/ui/<runtime> (8 runtimes).
- 03:37 Go core (server/core), templ hosted pages (server/web), JSON API, OIDC handoff, extension stubs (server/ext).
- 03:40 TS adapter (packages/adapters/ts), React demo (apps/demo-react), docker-compose stack (Stalwart v0.16 + authkit + demo-react).
- 03:42 Box quirk: a legacy iptables FORWARD DROP policy (other dockerd) blocked container-to-container and container DNS traffic; added narrow iptables-legacy DOCKER-USER accept rules for 172.16.0.0/12 (box only, not part of the repo).
- 03:46 e2e/flow.test.ts: 13/13 steps pass against the compose stack (sign-up, verification mail via JMAP, magic link, sign-out, username+password, email+password, wrong password, reset, OIDC SSO into the React demo with consent, deny, JSON API).
- 03:50 ui8px: repo policy in .ui8px (defaults + 5 utilities of upstream templ primitives); `npx ui8px@latest lint` → 0 violations.
- 03:55 PHP and Python adapters (JSON API + OIDC RP); e2e now 15/15 (adds Python and PHP OIDC + API steps).
- 04:00 Codegen fixes for `bun run verify`: typed identifier field, required confirm label, organism id prefix, codex status (tools/codex-status.py). `tools/gen-ui.sh --verify` → check ok (parity templ/solid/twig/jinja2/latte vs React), codex validate ok, typecheck ok, 839 tests pass, 0 fail.
- 04:05 Docs (docs/*.md, 8 runtime guides) and the static site (site/, Go templ → site/dist, 18 pages + index, 14 live previews). `bun run site`.
- NEXT: screenshots (390/1440, light/dark) into /workspace/authkit-shots, README, final report.

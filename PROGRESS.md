# Authkit progress log

Times are Europe/Moscow (UTC+3).

- 2026-10-21 03:13 Start. No fitting repo in the ui8kit org (`gh repo list ui8kit`): no authkit-like repo. Local git repo at /workspace/authkit, ready to push once a URL is given.
- 03:15 Docker installed on the box (docker.io), dockerd running.
- 03:16 ui8kit/codegen read (README, docs/architecture.md, contract.md, runtimes.md, specs-guide.md; docs/bricks.md does not exist upstream). Real runtimes: svelte, react, vue, solid, templ, twig, latte, jinja2 (static HTML is not a separate runtime in 2.0). Bricks are `xgen/specs/ui/<name>.json` (+ variants), not `bricks/<name>/<name>.def.ts` (that was 0.1).
- 03:20 Stalwart v0.16.27 probed in a container: bootstrap via JMAP `x:Bootstrap/set`, account creation `x:Account/set`, password change, `POST /api/auth` + `/auth/token` PKCE, `/auth/userinfo`, SMTP delivery on 25, JMAP mail read. All verified live.

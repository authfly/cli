# authfly/cli — `npx authfly`

The Authfly product: the server (hosted pages, JSON API, OIDC handoff, GDPR) and the CLI. The CLI deploys it with
Stalwart to **docker** or **incus**, applies a **policy pack** (GDPR, US PII, RU 152-FZ), and covers upgrade,
rollback, backup, restore and doctor.

    npx authfly init      # wizard → authfly.yaml (provider: stalwart)
    npx authfly deploy    # then status | doctor | backup | restore | upgrade | rollback | down

Latest release: [v0.4.2](https://github.com/authfly/cli/releases/tag/v0.4.2) (signed `channel.json`, images
`ghcr.io/authfly/authfly` and `ghcr.io/authfly/console` for linux/amd64 + linux/arm64).

Docs: `docs/getting-started.md`, `docs/deploy.md` (CLI, targets, security model), `docs/policies.md` (packs,
citations, not legal advice), `docs/architecture.md`, `docs/security.md`, `docs/gdpr.md`, `docs/oidc.md`,
`docs/extensions.md`, `docs/release.md` (public release channel), `docs/SOURCES.md` (sources of truth, mirrors,
pins, release order), `docs/changelog.md`.

## Related repos

| Repo | Role | How this repo uses it |
|---|---|---|
| **authfly/cli** (this) | server, CLI, deploy, policy packs, user docs, deploy e2e | — |
| authfly/authkit | widgets for 9 runtimes (UI8Kit 3) + docs site | pinned in `deps.lock` → `.deps/authkit`. The hosted pages render its templ blocks; the React demo imports its React blocks |
| authfly/authfly | `@authfly/core` contract, providers, server SDKs, contract tests | pinned → `.deps/authfly`. The demo uses `@authfly/node`; the e2e drives the Python/PHP SDKs. `provider: stalwart` = `@authfly/provider-stalwart` |
| authfly/stalwart | internal: Stalwart dev stack, JMAP audit, Console, compat e2e | imports this repo's `server/core` (owner of the Go JMAP client). The release ships its Console binary |
| authfly/codegen | generators for the widgets and the UI middle layer (9 targets) | indirect: pinned by authkit, whose generated files this repo consumes |

Mirrors (read-only): `authfly/twig`, `authfly/latte` (from authkit), `authfly/sdk-php` (from authfly). See `docs/SOURCES.md`.

## Build and test

```sh
bun install && bash tools/deps.sh     # check out the pinned repos into .deps/ (sibling checkouts preferred)
go build ./... && go vet ./... && go test ./...
npx ui8px@0.2.5 lint                  # = part of bun run test
bash tools/release.sh 0.4.2           # local release: dist/<v> binaries + SHA256SUMS + images + dist/channel.json
bash tools/release-public.sh 0.4.2    # public channel (dry run by default): dist/release/<v>, see docs/release.md
bash tools/e2e-deploy.sh <deploy dir> # flow / security / gdpr suites against a deployment
bash tools/e2e-cross.sh               # cross-repo e2e: deploy via CLI → widgets → Stalwart adapter → magic link
```

## License

Apache-2.0, © Authfly

## UI (UI8Kit 3)

`server/web` renders with UI8Kit 3 templ primitives and Authfly widgets from `github.com/authfly/authkit/packages/ui/templ` (pinned in `deps.lock`, `go.mod` replace → `./.deps/authkit/packages/ui/templ`). `apps/demo-react` uses `@authfly/react` primitives (`src/ui/*`) and widgets (`src/authfly`). After `.templ` edits: `templ generate`, rebuild `server/web/assets/app.css`, `go vet ./... && go test ./...`.

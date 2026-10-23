# authfly/cli — `npx authfly`

The Authfly product: the server (hosted pages, JSON API, OIDC handoff, GDPR) and the CLI. The CLI deploys it with
Stalwart to **docker** or **incus**, applies a **policy pack** (GDPR, US PII, RU 152-FZ), and covers upgrade,
rollback, backup, restore and doctor.

    npx authfly init      # wizard → authfly.yaml (provider: stalwart)
    npx authfly deploy    # then status | doctor | backup | restore | upgrade | rollback | down

Docs: `docs/deploy.md` (CLI, targets, security model), `docs/policies.md` (packs, citations, not legal advice),
`docs/getting-started.md`, `docs/architecture.md`, `docs/security.md`, `docs/gdpr.md`, `docs/oidc.md`.

## The four repos

| Repo | Role | How this repo uses it |
|---|---|---|
| **authfly/cli** (this) | server, CLI, deploy, policy packs, user docs, deploy e2e | — |
| authfly/authkit | widgets for 8 runtimes + docs site | pinned in `deps.lock` → `.deps/authkit`. The hosted pages render its templ blocks; the React demo imports its React blocks |
| authfly/authfly | `@authfly/core` contract, providers, server SDKs, contract tests | pinned → `.deps/authfly`. The demo uses `@authfly/node`; the e2e drives the Python/PHP SDKs. `provider: stalwart` = `@authfly/provider-stalwart` |
| authfly/stalwart | internal: Stalwart dev stack, JMAP audit, Console, compat e2e | imports this repo's `server/core` (owner of the Go JMAP client). The release ships its Console binary |

## Build and test

```sh
bun install && bash tools/deps.sh     # check out the pinned repos into .deps/ (sibling checkouts preferred)
go build ./... && go vet ./... && go test ./...
npx ui8px@latest lint
bash tools/release.sh 0.3.1           # dist/<v> binaries + SHA256SUMS + images + dist/channel.json
bash tools/e2e-deploy.sh <deploy dir> # flow / security / gdpr suites against a deployment
bash tools/e2e-cross.sh               # cross-repo e2e: deploy via CLI → widgets → Stalwart adapter → magic link
```

## License

MIT, © Auth Fly

## UI (UI8Kit 3)

`server/web` renders with UI8Kit 3 templ primitives and Authfly widgets from `github.com/authfly/authkit/widgets/templ` (pinned in `deps.lock`, `go.mod` replace → `./.deps/authkit/packages/ui/templ`). `apps/demo-react` uses `@authfly/react` primitives (`src/ui/*`) and widgets (`src/authfly`). After `.templ` edits: `templ generate`, rebuild `server/web/assets/app.css`, `go vet ./... && go test ./...`.

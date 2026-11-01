# Sources of truth, mirrors, pins, versions, release order

One place per artifact. Edit only the **source**; everything else is generated, mirrored or pinned.

## Artifacts

| Artifact | Source (edit here) | Derived / published | Sync |
|---|---|---|---|
| CLI, hosted pages, `authfly` npm, GitHub Release, `channel.json` | `authfly/cli` | npm `authfly`, `@authfly/cli-*` | `tools/release*.sh` (owner only) |
| Authfly Console | `authfly/stalwart` | Console binary in the CLI release | built by `cli/tools/release.sh` from the pinned commit |
| Widgets, 9 runtimes (React, Vue 3, Svelte 5, Solid, Web Components, templ, Twig, Latte, Jinja2) | `authfly/authkit` `packages/ui/*` | `authfly/twig`, `authfly/latte` (Composer mirrors) | `authkit/.github/workflows/mirror.yml` (= `tools/split.sh`) |
| Authfly code generation (shared skin/types/icons, widget specs → 9 targets, brand registry manifests) | `authfly/codegen` | generated files committed in `authkit` (checked by `tools/codegen.sh all --check`) | — |
| Authfly brand registry (built) | `authfly/authkit` `packages/registry` via `authfly/codegen` | `ui8kit/site` `r/authfly/<rt>/` → https://registry.buildy.tw/authfly/<rt>/index.json | `tools/codegen.sh publish <site>` (manual, owner-approved) |
| Contract `@authfly/core`, providers, server SDKs | `authfly/authfly` | npm `@authfly/*`, `authfly/sdk-php` (Composer mirror) | `authfly/.github/workflows/mirror.yml` (= `tools/split.sh`) |
| Website | `authfly/website` | — | — |
| Browser SDK (legacy) | `authfly/authkit-ts` | — | not developed since 2026-04 |

Mirrors are **read-only**: no commits, no PRs, no force-push. The split is deterministic, so a mirror only fast-forwards.
CI job `mirror-drift` (authkit, authfly) fails when a mirror tree differs from its source folder.

## Pins (`deps.lock`)

- `cli/deps.lock`: authkit, authfly (build + tests), stalwart (release only: the Console build).
- `stalwart/deps.lock`: cli (Go JMAP client `server/core`), authkit (templ widgets).
- `authkit/deps.lock`: codegen (the generators; widget specs live there, generated code is committed in authkit).
- **Rule:** `cli` and `stalwart` pin **the same authkit commit**. Every pin must be a commit on the dependency's `main`.
  Checked by `tools/deps.sh --check` in CI (stalwart compares its authkit pin with cli's `deps.lock`).
- **cli ↔ stalwart cycle (known, kept):** stalwart builds on cli's `server/core`; cli needs stalwart only to build the
  Console at release time. Bump order: stalwart (`--bump cli`, `--bump authkit`) → cli (`--bump stalwart`). After that
  stalwart's cli pin is one commit behind cli `main` by design; it must still be on `main` (`--check`).
- `DEPS_SKIP="name ..."` skips pins (not used in CI: all repos are public).

## Version policy

- Versions live in **git tags** (no `version` fields in the source repos' manifests).
- **Contract line** `1.x` (semver, breaking = major): `@authfly/core`, `@authfly/provider-*`, `@authfly/contract-tests`,
  `@authfly/node`, `authfly/sdk-php` (tag `vX.Y.Z` in the mirror = the npm version).
- **Product line** `0.x` (semver while 0.x: visual/behaviour breaks = minor): `authfly` CLI/npm, GitHub Release, and the
  widget mirrors `authfly/twig` / `authfly/latte` tagged with **the same `v0.x.y` as the CLI release that ships them**.
  authkit itself is tagged per runtime only when a runtime is published as its own Go module (`packages/ui/templ/vX.Y.Z`).
- Docker images (if any) use the CLI version tag; never `latest` alone.
- License: Apache-2.0, © Authfly, in every repo and every package manifest.

## Release order

1. `authfly/authfly`: contract/SDK changes merged, CI green; tag the contract line if it changed; mirror synced (sdk-php).
2. `authfly/codegen` → `authfly/authkit`: codegen change merged (its CI checks authkit main), authkit `tools/deps.sh --bump codegen` + `tools/codegen.sh all`; CI green (ui8px lint + HTML/ARIA gates over 9 runtimes); twig/latte mirrors synced (`mirror-drift` green).
3. `authfly/stalwart`: `tools/deps.sh --bump authkit` (+ `--bump cli` if server/core changed), CI green.
4. `authfly/cli`: `--bump authkit` (same commit as stalwart), `--bump authfly`, `--bump stalwart`; CI green; changelog.
5. Owner: version decision, tag, npm + GitHub Release from the **same** binaries, `channel.json` signature (YubiKey).
6. Tag twig/latte mirrors with the same version. Publication only on the owner's "публикуй".

## Branches and CI

- Only `main`. Short-lived branches only for PRs; delete after merge.
- Each repo has `.github/workflows/ci.yml`, job `check` = the required status check on `main` (where the plan allows).
- `main` protection: required check `check`, no force-push, no deletion. PRs are not required (bots push directly).

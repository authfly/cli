# AGENTS.md — authfly/cli

- Web UI (`server/web`) = authkit UI8Kit 3 templ primitives + `blocks` (package `authfly`); className/tokens only, no xgen/kit.css.
- Demo (`apps/demo-react`) = `@authfly/react` 0.4.0 primitives/widgets.
- Pins via `tools/deps.sh --bump <authkit|stalwart>`; e2e: `tools/e2e-cross.sh` (needs docker).
- Don't touch `.ui8px` policy; never hand-edit `ui8kit.lock.json` or CLI-owned ui/utils.
- Push only when asked; never force-push or rewrite history.

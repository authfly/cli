#!/usr/bin/env bash
# Generate the Authfly widgets for the eight ui8kit runtimes the codegen way, without touching ui8kit/codegen upstream:
# a pristine checkout of the pinned commit (codegen.lock) in .cache/codegen, the Authfly overlay, xgen build, then export.
#   tools/gen-ui.sh            build + export
#   tools/gen-ui.sh --check    build + export + bun run check (parity of templ, solid, twig, jinja2, latte vs React)
#   tools/gen-ui.sh --verify   build + export + bun run verify (check, codex validate, typecheck, unit tests)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SHA=$(cat "$ROOT/codegen.lock")
CG="$ROOT/.cache/codegen"
SRC=${CODEGEN_SRC:-https://github.com/ui8kit/codegen}
if [ ! -d "$CG/.git" ]; then git clone -q "$SRC" "$CG"; fi
git -C "$CG" fetch -q origin 2>/dev/null || true
git -C "$CG" checkout -q -f "$SHA" && git -C "$CG" clean -qfd -e node_modules
( cd "$CG" && bun install --frozen-lockfile >/dev/null 2>&1 || bun install >/dev/null )
python3 "$ROOT/tools/overlay.py" "$CG"
ESC="python3 $ROOT/tools/escape-cyrillic.py xgen/content/ui/en.json"
( cd "$CG" && bun xgen/screens/tools/author-block-texts.ts >/dev/null && bun xgen/screens/tools/author-theme-texts.ts >/dev/null && $ESC )
( cd "$CG" && bun run build && $ESC )
( cd "$CG" && bun run codex:manifest >/dev/null && bun run codex:blocks >/dev/null && python3 "$ROOT/tools/codex-status.py" . && bun run codex:blocks >/dev/null && bun run rules:baseline >/dev/null )
bun "$ROOT/tools/export-ui.ts" "$CG" "$ROOT/packages/ui"
case "${1:-}" in --check) ( cd "$CG" && bun run check ) ;; --verify) ( cd "$CG" && bun run verify ) ;; esac

#!/usr/bin/env bash
# Generate the Authkit widgets for the eight ui8kit runtimes the codegen way, without touching ui8kit/codegen upstream:
# a pristine checkout of the pinned commit (codegen.lock) in .cache/codegen, the Authkit overlay, xgen build, then export.
#   tools/gen-ui.sh            build + export
#   tools/gen-ui.sh --check    build + export + bun run check (parity of templ, solid, twig, jinja2, latte vs React)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SHA=$(cat "$ROOT/codegen.lock")
CG="$ROOT/.cache/codegen"
SRC=${CODEGEN_SRC:-https://github.com/ui8kit/codegen}
if [ ! -d "$CG/.git" ]; then git clone -q "$SRC" "$CG"; fi
git -C "$CG" fetch -q origin 2>/dev/null || true
git -C "$CG" checkout -q -f "$SHA" && git -C "$CG" clean -qfd
( cd "$CG" && bun install --frozen-lockfile >/dev/null 2>&1 || bun install >/dev/null )
python3 "$ROOT/tools/overlay.py" "$CG"
( cd "$CG" && bun xgen/screens/tools/author-block-texts.ts >/dev/null && bun xgen/screens/tools/author-theme-texts.ts >/dev/null 2>&1 || true )
( cd "$CG" && bun run build )
( cd "$CG" && bun run rules:baseline >/dev/null )
bun "$ROOT/tools/export-ui.ts" "$CG" "$ROOT/packages/ui"
if [ "${1:-}" = "--check" ]; then ( cd "$CG" && bun run check ); fi

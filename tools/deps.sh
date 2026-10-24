#!/usr/bin/env bash
# Check out the repos pinned in deps.lock into .deps/<name> (gitignored).
#   tools/deps.sh               sync every pin (no-op when already at the pinned commit)
#   tools/deps.sh --bump <name> move the pin to the source's current HEAD
# Source: $AUTHFLY_DEPS_SRC/authfly-<name> when that checkout exists (default: the parent directory, i.e. sibling
# checkouts), else the GitHub URL in deps.lock. Exact commit pins: nothing floats.
#   authkit: widgets (9 runtimes) — the hosted pages render its templ blocks, the React demo imports its React blocks
#   stalwart: (release only) the Authfly Console, built by tools/release.sh against THIS checkout's server/core
#   authfly: @authfly/core contract, providers, server SDKs (the demo uses @authfly/node, the e2e the PHP/Python SDKs)
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
src_base=${AUTHFLY_DEPS_SRC:-$(dirname "$root")}
lock=${DEPS_LOCK:-deps.lock}
src_of() { if [ -d "$src_base/authfly-$1/.git" ]; then echo "$src_base/authfly-$1"; else echo "$2"; fi; }
if [ "${1:-}" = "--bump" ]; then
  name=${2:?name}; url=$(awk -v n="$name" '$1==n{print $2}' "$lock"); src=$(src_of "$name" "$url")
  [ -d "$src/.git" ] || { echo "no local checkout for $name to bump from" >&2; exit 1; }
  new=$(git -C "$src" rev-parse HEAD)
  awk -v n="$name" -v c="$new" '$1==n{$3=c; printf "%-10s %-43s %s\n",$1,$2,$3; next}{print}' "$lock" > "$lock.tmp" && mv "$lock.tmp" "$lock"
  echo "$name -> $new"; exit 0
fi
grep -vE '^\s*(#|$)' "$lock" | while read -r name url commit _; do
  dir=.deps/$name
  if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD)" = "$commit" ]; then echo "deps: $name @ ${commit:0:7} (ok)"; continue; fi
  src=$(src_of "$name" "$url")
  rm -rf "$dir"; mkdir -p .deps
  git clone -q --no-checkout "$src" "$dir"
  git -C "$dir" -c advice.detachedHead=false checkout -q "$commit"
  echo "deps: $name @ ${commit:0:7} from $src"
  if [ "$name" = authkit ]; then  # the templ blocks are generated (*_templ.go is not committed)
    (cd "$dir" && go run github.com/a-h/templ/cmd/templ@v0.3.1070 generate -path packages/ui/templ >/dev/null 2>&1)
  fi
done

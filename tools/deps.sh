#!/usr/bin/env bash
# Check out the repos pinned in deps.lock into .deps/<name> (gitignored).
#   tools/deps.sh               sync every pin (no-op when already at the pinned commit)
#   tools/deps.sh --bump <name> move the pin to the source's current HEAD
#   tools/deps.sh --check [peer] verify pins are on each dep's main (and equal to a peer lock's shared pins)
#   DEPS_SKIP="name ..."        skip pins (e.g. the private stalwart in public CI)
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
if [ "${1:-}" = "--check" ]; then
  # Every pin must be a commit on the dep's main; with a peer lock (path or URL) the shared pins must be identical.
  #   tools/deps.sh --check [peer-deps.lock]     (DEPS_SKIP="a b" skips names, e.g. a private repo without access)
  peer=${2:-}; rc=0; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  while read -r name url commit _; do
    case " ${DEPS_SKIP:-} " in *" $name "*) echo "check: $name skipped"; continue;; esac
    git clone -q --bare --filter=blob:none --single-branch -b main "$url" "$tmp/$name" || { echo "check: $name clone failed" >&2; rc=1; continue; }
    if git -C "$tmp/$name" merge-base --is-ancestor "$commit" main 2>/dev/null; then
      echo "check: $name ${commit:0:7} on main ($(git -C "$tmp/$name" rev-list --count "$commit..main") behind)"
    else echo "check: $name ${commit:0:7} is NOT on $url main" >&2; rc=1; fi
  done < <(grep -vE '^\s*(#|$)' "$lock")
  if [ -n "$peer" ]; then
    case "$peer" in http*) curl -fsSL "$peer" > "$tmp/peer.lock" || { echo "check: cannot read $peer" >&2; exit 1; };; *) cp "$peer" "$tmp/peer.lock";; esac
    while read -r name _ commit _; do
      other=$(awk -v n="$name" '$1==n{print $3}' "$tmp/peer.lock")
      [ -z "$other" ] && continue
      if [ "$other" = "$commit" ]; then echo "check: $name pin matches peer"; else echo "check: $name pin ${commit:0:7} != peer ${other:0:7}" >&2; rc=1; fi
    done < <(grep -vE '^\s*(#|$)' "$lock")
  fi
  exit $rc
fi
grep -vE '^\s*(#|$)' "$lock" | while read -r name url commit _; do
  case " ${DEPS_SKIP:-} " in *" $name "*) echo "deps: $name skipped"; continue;; esac
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

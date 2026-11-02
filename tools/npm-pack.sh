#!/usr/bin/env bash
# Build the npm packages (NOT published — the maintainer runs `npm publish` for each tarball):
#   authfly (bin authfly, runs the verified platform binary) + @authfly/cli-<os>-<arch> (one Go binary each).
#   tools/npm-pack.sh 0.4.1   -> dist/npm/*.tgz
# Packs the binaries of the GitHub release (dist/release/<v>/ from tools/release-public.sh --prepare, SHA256SUMS
# re-checked), so npm and the release ship byte-identical files.
set -euo pipefail
v=${1:?version}
root=$(cd "$(dirname "$0")/.." && pwd)
rel=$root/dist/release/$v
[ -f "$rel/SHA256SUMS" ] || { echo "npm-pack: $rel/SHA256SUMS missing: run tools/release-public.sh $v --prepare (or --dry-run) first" >&2; exit 1; }
(cd "$rel" && sha256sum -c --quiet SHA256SUMS) || { echo "npm-pack: $rel changed since it was built" >&2; exit 1; }
out=$root/dist/npm; rm -rf "$out"; mkdir -p "$out"
declare -A sums
for p in linux/amd64/linux-x64 linux/arm64/linux-arm64 darwin/amd64/darwin-x64 darwin/arm64/darwin-arm64 windows/amd64/win32-x64; do
  IFS=/ read -r goos goarch np <<<"$p"
  d=$out/src/cli-$np; mkdir -p "$d/bin"
  exe=authfly; [ "$goos" = windows ] && exe=authfly.exe
  src=authfly-$goos-$goarch; [ "$goos" = windows ] && src=$src.exe
  cp "$rel/$src" "$d/bin/$exe" && chmod +x "$d/bin/$exe"
  os=${np%-*}; cpu=${np#*-}
  cat > "$d/package.json" <<JSON
{ "name": "@authfly/cli-$np", "version": "$v", "description": "authfly binary for $np (used by the authfly package)", "license": "Apache-2.0",
  "repository": { "type": "git", "url": "git+https://github.com/authfly/cli.git" }, "os": ["$os"], "cpu": ["$cpu"], "files": ["bin"] }
JSON
  sums[$np]=$(sha256sum "$d/bin/$exe" | cut -d' ' -f1)
  (cd "$out" && npm pack --silent "$d" >/dev/null)
done
m=$out/src/authfly; cp -r "$root/packages/npm/authfly" "$m"
{ echo "{"; first=1; for k in "${!sums[@]}"; do [ $first = 1 ] || echo ","; first=0; printf '  "%s": "%s"' "$k" "${sums[$k]}"; done; echo; echo "}"; } > "$m/checksums.json"
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$v\"/; s/\(\"@authfly\/cli-[a-z0-9-]*\": \)\"[^\"]*\"/\1\"$v\"/g" "$m/package.json"
(cd "$out" && npm pack --silent "$m" >/dev/null)
ls -1 "$out"/*.tgz

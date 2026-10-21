#!/usr/bin/env bash
# Build the npm packages (NOT published — the maintainer runs `npm publish` for each tarball):
#   authfly (bin authfly, runs the verified platform binary) + @authfly/cli-<os>-<arch> (one Go binary each).
#   tools/npm-pack.sh 0.3.0   -> dist/npm/*.tgz
set -euo pipefail
v=${1:?version}
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/dist/npm; rm -rf "$out"; mkdir -p "$out"
declare -A sums
for p in linux/amd64/linux-x64 linux/arm64/linux-arm64 darwin/amd64/darwin-x64 darwin/arm64/darwin-arm64 windows/amd64/win32-x64; do
  IFS=/ read -r goos goarch np <<<"$p"
  d=$out/src/cli-$np; mkdir -p "$d/bin"
  exe=authfly; [ "$goos" = windows ] && exe=authfly.exe
  (cd "$root" && CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags="-s -w -X main.Version=$v" -o "$d/bin/$exe" ./cmd/authfly)
  os=${np%-*}; cpu=${np#*-}
  cat > "$d/package.json" <<JSON
{ "name": "@authfly/cli-$np", "version": "$v", "description": "authfly binary for $np (used by the authfly package)", "license": "MIT",
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

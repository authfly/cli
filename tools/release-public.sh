#!/usr/bin/env bash
# Public release channel for authfly/cli (GitHub Releases + a container registry).
#   tools/release-public.sh <version> [--dry-run] [--registry R] [--base-url URL] [--previous URL|file] [--push-images] [--publish]
#
# Builds into dist/release/<version>/:
#   authfly-<os>-<arch>[.exe]  CLI/server binaries for linux/darwin amd64+arm64 and windows amd64 (static, -trimpath)
#   console-linux-amd64        the Console (authfly/stalwart, pinned in deps.lock; built against THIS checkout)
#   SHA256SUMS                 sha256 of every binary above
#   channel.json               the channel manifest (format: server/deploy/channel.go), previous releases kept
# and the images <R>/authfly:<v>, <R>/console:<v> from deploy/release.Dockerfile (FROM the linux-amd64 binaries).
#
# Images are pinned by registry digest (ref@sha256:…), which only exists after a push:
#   --dry-run (default)  build everything, push nothing; channel.json pins the images by local image ID (works only on
#                        this host) and the script prints the commands of the real run.
#   --push-images        push the images to --registry and pin them by registry digest (use a local registry:2 to test).
#   --publish            real release: push the images, write channel.json with the registry digests and run
#                        `gh release create v<version>` with all assets. Only the maintainer runs this.
# Defaults: --registry ghcr.io/authfly (owner's choice, change freely),
#           --base-url https://github.com/authfly/cli/releases/download/v<version>,
#           --previous https://github.com/authfly/cli/releases/latest/download/channel.json (missing = new channel).
# The CLI's default channel is https://github.com/authfly/cli/releases/latest/download/channel.json, so the newest
# GitHub release must carry the full channel.json (upgrade/rollback look up older versions in it).
set -euo pipefail
v=${1:?usage: tools/release-public.sh <version> [--dry-run] [--registry R] [--base-url URL] [--previous URL|file] [--push-images] [--publish]}
shift
registry=ghcr.io/authfly; base=""; prev=https://github.com/authfly/cli/releases/latest/download/channel.json
push=0; publish=0
while [ $# -gt 0 ]; do
  case $1 in
    --dry-run) push=0; publish=0 ;;
    --registry) registry=$2; shift ;;
    --base-url) base=$2; shift ;;
    --previous) prev=$2; shift ;;
    --push-images) push=1 ;;
    --publish) push=1; publish=1 ;;
    *) echo "release-public: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
base=${base:-https://github.com/authfly/cli/releases/download/v$v}
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
out=dist/release/$v; rm -rf "$out"; mkdir -p "$out"
DOCKER=${DOCKER:-docker}

echo "== binaries ($v)"
for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  goos=${p%/*}; goarch=${p#*/}; exe=authfly-$goos-$goarch; [ "$goos" = windows ] && exe=$exe.exe
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags="-s -w -X main.Version=$v" -o "$out/$exe" ./cmd/authfly
done
# Console from the pinned authfly/stalwart, against this checkout's server/core and the pinned authkit (as release.sh).
bash tools/deps.sh >/dev/null
mkdir -p .deps/stalwart/.deps && ln -sfn "$PWD" .deps/stalwart/.deps/cli && ln -sfn "$PWD/.deps/authkit" .deps/stalwart/.deps/authkit
(cd .deps/stalwart && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$root/$out/console-linux-amd64" ./apps/console)
(cd "$out" && sha256sum authfly-* console-linux-amd64 > SHA256SUMS)

echo "== images ($registry)"
for b in authfly console; do
  $DOCKER build -q --build-arg BIN=$b -t "$registry/$b:$v" -f deploy/release.Dockerfile "$out" >/dev/null
done
declare -A img
for b in authfly console; do
  if [ $push = 1 ]; then
    $DOCKER push -q "$registry/$b:$v" >/dev/null
    d=$($DOCKER image inspect -f '{{range .RepoDigests}}{{.}} {{end}}' "$registry/$b:$v" | tr ' ' '\n' | grep "^$registry/$b@sha256:" | head -1)
    [ -n "$d" ] || { echo "release-public: no registry digest for $registry/$b:$v after push" >&2; exit 1; }
    img[$b]="$registry/$b:$v@${d#*@}"
  else
    img[$b]="$registry/$b:$v@$($DOCKER image inspect -f '{{.Id}}' "$registry/$b:$v")"
  fi
done

# Stalwart: the upstream release, pinned by its published sha256 (same pins as tools/release.sh).
SW_URL=https://github.com/stalwartlabs/stalwart/releases/download/v0.16.27/stalwart-x86_64-unknown-linux-gnu.tar.gz
SW_SHA=3d4548053e7130cdc6288134e28aecc5004f22549cc52a1dbda0ca48ff0b301a
SW_IMG=stalwartlabs/stalwart:v0.16.27@sha256:c429b311c93db5606598abc1c68225a85a6953183848ae01bee9c6a98885836c

echo "== channel.json"
prevfile=$out/.previous.json; rm -f "$prevfile"
case $prev in
  http://*|https://*) curl -fsSL "$prev" -o "$prevfile" 2>/dev/null || rm -f "$prevfile" ;;
  "") ;;
  *) [ -f "$prev" ] && cp "$prev" "$prevfile" ;;
esac
python3 - "$v" "$out" "$base" "${img[authfly]}" "${img[console]}" "$SW_URL" "$SW_SHA" "$SW_IMG" "$prevfile" <<'PY'
import json, os, sys
v, out, base, ia, ic, swurl, swsha, swimg, prevfile = sys.argv[1:]
sums = dict(reversed(l.split()) for l in open(f"{out}/SHA256SUMS"))
files = {n: {"url": f"{base}/{n}", "sha256": sums[n]} for n in ("authfly-linux-amd64", "console-linux-amd64")}
files["stalwart-linux-amd64"] = {"url": swurl, "sha256": swsha}
rel = {"version": v, "files": files, "images": {"authfly": ia, "console": ic, "stalwart": swimg}}
m = {"channel": "stable", "releases": []}
if os.path.exists(prevfile):
    m = json.load(open(prevfile))
    os.remove(prevfile)
m["releases"] = [r for r in m.get("releases", []) if r["version"] != v] + [rel]
json.dump(m, open(f"{out}/channel.json", "w"), indent=2)
print(f"channel.json: {len(m['releases'])} release(s), newest {v}")
PY

assets=$(cd "$out" && ls authfly-* console-linux-amd64 SHA256SUMS channel.json | sed "s#^#$out/#" | tr '\n' ' ')
if [ $publish = 1 ]; then
  echo "== gh release create v$v"
  gh release create "v$v" --repo authfly/cli --title "authfly $v" --notes "authfly $v. Channel: channel.json; images: ${img[authfly]}, ${img[console]}" $assets
  exit 0
fi
echo
if [ $push = 1 ]; then
  echo "images pushed to $registry (pinned by registry digest); nothing else was uploaded."
else
  echo "dry run: nothing was pushed or uploaded. channel.json pins the images by local image ID (this host only)."
fi
echo "Real release (maintainer):"
echo "  docker login ${registry%%/*}"
echo "  bash tools/release-public.sh $v --publish      # docker push $registry/{authfly,console}:$v, then:"
echo "  gh release create v$v --repo authfly/cli --title \"authfly $v\" --notes \"…\" $assets"

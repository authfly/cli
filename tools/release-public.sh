#!/usr/bin/env bash
# Public release channel for authfly/cli (GitHub Releases + a container registry).
#   tools/release-public.sh <version> [--dry-run] [--registry R] [--base-url URL] [--previous URL|file] [--push-images] [--publish]
#
# Builds into dist/release/<version>/:
#   authfly-<os>-<arch>[.exe]  CLI/server binaries for linux/darwin amd64+arm64 and windows amd64 (static, -trimpath)
#   console-linux-{amd64,arm64}  the Console (authfly/stalwart, pinned in deps.lock; built against THIS checkout)
#   SHA256SUMS                 sha256 of every binary above
#   channel.json               the channel manifest (format: server/deploy/channel.go), previous releases kept
#   channel.json.sig           Ed25519 signature of channel.json (server/deploy/sign.go, tools/channelsign)
# and the multi-arch images <R>/authfly:<v>, <R>/console:<v> (linux/amd64 + linux/arm64, docker buildx) from
# deploy/release.Dockerfile, FROM the Go cross-compiled linux binaries (no emulation).
#
# Images are pinned by the registry digest of their multi-arch index (ref@sha256:…), which only exists after a push:
#   --dry-run (default)  build everything (both platforms), push nothing; channel.json pins the host-arch images by
#                        local image ID (works only on this host) and the script prints the commands of the real run.
#   --push-images        push the images to --registry and pin them by index digest (use a local registry:2 to test).
#   --publish            real release: push the images, write + sign channel.json and run `gh release create v<version>`
#                        with all assets. Only the maintainer runs this.
# Signing key: $AUTHFLY_SIGNING_KEY (default ~/.config/authfly/release-signing.key, PKCS#8 PEM, 0600; never in the
# repository). Required for --push-images/--publish; a dry run without it leaves channel.json unsigned. The signature
# is checked with the keys built into this checkout's CLI, so a key the CLI does not trust fails the release.
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
for a in amd64 arm64; do
  (cd .deps/stalwart && CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -trimpath -ldflags="-s -w" -o "$root/$out/console-linux-$a" ./apps/console)
done
(cd "$out" && sha256sum authfly-* console-linux-* > SHA256SUMS)

key=${AUTHFLY_SIGNING_KEY:-$HOME/.config/authfly/release-signing.key}
if [ $push = 1 ] && [ ! -f "$key" ]; then
  echo "release-public: signing key $key not found (set AUTHFLY_SIGNING_KEY): refusing to push an unsigned channel" >&2; exit 1
fi

echo "== images ($registry, linux/amd64 + linux/arm64)"
platforms=linux/amd64,linux/arm64
# Multi-platform images need a BuildKit container builder. Plain-http local registries (localhost:5000) get a
# buildkitd config that allows http for that host.
builder=${BUILDX_BUILDER:-}
if [ -z "$builder" ]; then
  host=${registry%%/*}; builder=authfly-release
  case $host in localhost:*|127.0.0.1:*) builder=authfly-release-local ;; esac
  if ! $DOCKER buildx inspect "$builder" >/dev/null 2>&1; then
    cfg=()
    if [ $builder = authfly-release-local ]; then
      printf '[registry."%s"]\n  http = true\n  insecure = true\n' "$host" > "$root/dist/buildkitd-local.toml"
      cfg=(--config "$root/dist/buildkitd-local.toml")
    fi
    $DOCKER buildx create --name "$builder" --driver docker-container --driver-opt network=host "${cfg[@]}" >/dev/null
  fi
fi
declare -A img
for b in authfly console; do
  bx=($DOCKER buildx build --builder "$builder" --platform $platforms --build-arg BIN=$b -t "$registry/$b:$v" -f deploy/release.Dockerfile)
  if [ $push = 1 ]; then
    meta=$out/.meta-$b.json
    "${bx[@]}" --push --metadata-file "$meta" -q "$out" >/dev/null
    d=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$meta"); rm -f "$meta"
    [[ $d == sha256:* ]] || { echo "release-public: no index digest for $registry/$b:$v after push" >&2; exit 1; }
    img[$b]="$registry/$b:$v@$d"
  else
    "${bx[@]}" -q "$out" >/dev/null   # both platforms build (cache only)
    $DOCKER buildx build --builder "$builder" --load --build-arg BIN=$b -t "$registry/$b:$v" -f deploy/release.Dockerfile -q "$out" >/dev/null
    img[$b]="$registry/$b:$v@$($DOCKER image inspect -f '{{.Id}}' "$registry/$b:$v")"
  fi
done

# Stalwart: the upstream release, pinned by its published sha256 (GitHub release asset digests) and the image by
# the digest of its multi-arch index (linux/amd64, linux/arm64, arm/v6, arm/v7).
SW_BASE=https://github.com/stalwartlabs/stalwart/releases/download/v0.16.27
SW_AMD64=3d4548053e7130cdc6288134e28aecc5004f22549cc52a1dbda0ca48ff0b301a   # stalwart-x86_64-unknown-linux-gnu.tar.gz
SW_ARM64=215301c8449e3bf8efd4c39cd557dc65dc37ec5bedab47f15c22ef24631100d7   # stalwart-aarch64-unknown-linux-gnu.tar.gz
SW_IMG=stalwartlabs/stalwart:v0.16.27@sha256:c429b311c93db5606598abc1c68225a85a6953183848ae01bee9c6a98885836c

echo "== channel.json"
prevfile=$out/.previous.json; rm -f "$prevfile"
case $prev in
  http://*|https://*) curl -fsSL "$prev" -o "$prevfile" 2>/dev/null || rm -f "$prevfile" ;;
  "") ;;
  *) [ -f "$prev" ] && cp "$prev" "$prevfile" ;;
esac
python3 - "$v" "$out" "$base" "${img[authfly]}" "${img[console]}" "$SW_BASE" "$SW_AMD64" "$SW_ARM64" "$SW_IMG" "$prevfile" <<'PY'
import json, os, sys
v, out, base, ia, ic, swbase, swamd, swarm, swimg, prevfile = sys.argv[1:]
sums = dict(reversed(l.split()) for l in open(f"{out}/SHA256SUMS"))
files = {f"{b}-linux-{a}": {"url": f"{base}/{b}-linux-{a}", "sha256": sums[f"{b}-linux-{a}"]} for b in ("authfly", "console") for a in ("amd64", "arm64")}
files["stalwart-linux-amd64"] = {"url": f"{swbase}/stalwart-x86_64-unknown-linux-gnu.tar.gz", "sha256": swamd}
files["stalwart-linux-arm64"] = {"url": f"{swbase}/stalwart-aarch64-unknown-linux-gnu.tar.gz", "sha256": swarm}
rel = {"version": v, "files": files, "images": {"authfly": ia, "console": ic, "stalwart": swimg}}
m = {"channel": "stable", "releases": []}
if os.path.exists(prevfile):
    m = json.load(open(prevfile))
    os.remove(prevfile)
m["releases"] = [r for r in m.get("releases", []) if r["version"] != v] + [rel]
json.dump(m, open(f"{out}/channel.json", "w"), indent=2)
print(f"channel.json: {len(m['releases'])} release(s), newest {v}")
PY

# The signature covers the exact bytes of channel.json (all releases in it); channel.json is not touched after this.
if [ -f "$key" ]; then
  go run ./tools/channelsign sign -key "$key" "$out/channel.json"
  go run ./tools/channelsign verify "$out/channel.json"   # with the keys built into this CLI
else
  echo "dry run: no signing key at $key; channel.json is NOT signed (deploys need channel.allow_unsigned)"
fi

assets=$(cd "$out" && ls authfly-* console-linux-* SHA256SUMS channel.json channel.json.sig 2>/dev/null | sed "s#^#$out/#" | tr '\n' ' ')
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

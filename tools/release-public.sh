#!/usr/bin/env bash
# Public release channel for authfly/cli (GitHub Releases + a container registry). Two phases, because the channel
# is signed by the maintainer's FIDO2 security key (YubiKey) on their own machine:
#
#   tools/release-public.sh <v> [--dry-run]                build everything locally, push/upload nothing
#   tools/release-public.sh <v> --prepare                  build, push the images, write dist/release/<v>/channel.json
#                                                          and print the exact signing command for the maintainer
#     (maintainer: ssh-keygen -Y sign -f <sk key> -n authfly-channel channel.json  -> channel.json.sig, touch the key)
#   tools/release-public.sh <v> --attach  --sig <file>...  verify the signature(s) with the CLI's built-in keys and
#                                                          install them as dist/release/<v>/channel.json.sig (no upload)
#   tools/release-public.sh <v> --publish --sig <file>...  --attach, then `gh release create v<v>` with all assets
# Options (dry-run/prepare): [--registry R] [--base-url URL] [--previous URL|file]
#
# dist/release/<version>/:
#   authfly-<os>-<arch>[.exe]    CLI/server binaries for linux/darwin amd64+arm64 and windows amd64 (static, -trimpath)
#   console-linux-{amd64,arm64}  the Console (authfly/stalwart, pinned in deps.lock; built against THIS checkout)
#   SHA256SUMS                   sha256 of every binary above
#   channel.json                 the channel manifest (format: server/deploy/channel.go), previous releases kept
#   channel.json.sig             SSHSIG signature(s) of channel.json (server/deploy/sign.go), added by --attach/--publish
# and the multi-arch images <R>/authfly:<v>, <R>/console:<v> (linux/amd64 + linux/arm64, docker buildx) from
# deploy/release.Dockerfile, FROM the Go cross-compiled linux binaries (no emulation).
#
# Images are pinned by the registry digest of their multi-arch index, which only exists after a push: --prepare pushes
# them (harmless: nobody pulls them without a signed channel), the dry run pins host-arch images by local image ID.
# --attach/--publish never rebuild: they ship exactly what --prepare wrote (SHA256SUMS is re-checked).
# Defaults: --registry ghcr.io/authfly, --base-url https://github.com/authfly/cli/releases/download/v<version>,
#           --previous https://github.com/authfly/cli/releases/latest/download/channel.json (missing = new channel).
# The CLI's default channel is https://github.com/authfly/cli/releases/latest/download/channel.json, so the newest
# GitHub release must carry the full channel.json (upgrade/rollback look up older versions in it).
set -euo pipefail
usage="usage: tools/release-public.sh <version> [--dry-run|--prepare|--attach --sig F|--publish --sig F] [--registry R] [--base-url URL] [--previous URL|file]"
v=${1:?$usage}
shift
registry=ghcr.io/authfly; base=""; prev=https://github.com/authfly/cli/releases/latest/download/channel.json
mode=dry-run; sigs=()
while [ $# -gt 0 ]; do
  case $1 in
    --dry-run) mode=dry-run ;;
    --prepare) mode=prepare ;;
    --attach) mode=attach ;;
    --publish) mode=publish ;;
    --sig) sigs+=("$2"); shift ;;
    --registry) registry=$2; shift ;;
    --base-url) base=$2; shift ;;
    --previous) prev=$2; shift ;;
    *) echo "release-public: unknown option $1 ($usage)" >&2; exit 2 ;;
  esac
  shift
done
base=${base:-https://github.com/authfly/cli/releases/download/v$v}
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
out=dist/release/$v
DOCKER=${DOCKER:-docker}
die() { echo "release-public: $*" >&2; exit 1; }
# authfly_e2ekeys builds trust an extra test key (server/deploy/e2ekeys.go): never for release binaries.
if [[ "${GOFLAGS:-}" == *authfly_e2ekeys* ]] && [ $mode != attach ]; then
  die "GOFLAGS has the authfly_e2ekeys test tag: refusing to $mode (only --attach may verify with test keys)"
fi

build() {
rm -rf "$out"; mkdir -p "$out"
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
  if [ $mode = prepare ]; then
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
}

if [ $mode = dry-run ] || [ $mode = prepare ]; then
  build
  sum=$(sha256sum "$out/channel.json" | cut -d' ' -f1)
  echo "$sum  channel.json" > "$out/channel.json.sha256"
  echo
  if [ $mode = dry-run ]; then
    echo "dry run: nothing was pushed or uploaded. channel.json pins the images by local image ID (this host only)."
    echo "Real release: docker login ${registry%%/*}; bash tools/release-public.sh $v --prepare"
    exit 0
  fi
  cat <<EOF
Images pushed to $registry (pinned by index digest); nothing else was uploaded.

== Maintainer: sign channel.json with the YubiKey (Windows PowerShell, built-in OpenSSH 8.9+)
Copy $root/$out/channel.json to the Windows machine, e.g. to \$HOME\Downloads\authfly-$v\channel.json, then:

  Set-Location "\$HOME\Downloads\authfly-$v"
  if ((Get-FileHash -Algorithm SHA256 .\channel.json).Hash -eq '$sum') { 'channel.json OK' } else { 'MISMATCH: do not sign' }
  & "\$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -Y sign -f "\$HOME\.ssh\authfly_release_sk" -n authfly-channel .\channel.json

Touch the YubiKey when it blinks (and enter the FIDO2 PIN if asked). Result: .\channel.json.sig
(macOS/Linux: ssh-keygen -Y sign -f ~/.ssh/authfly_release_sk -n authfly-channel channel.json)

Then copy channel.json.sig back to this box and run:
  bash tools/release-public.sh $v --publish --sig <path to channel.json.sig>
EOF
  exit 0
fi

# --attach / --publish: ship exactly what --prepare built.
[ ${#sigs[@]} -gt 0 ] || die "--$mode needs --sig <channel.json.sig> (one per signer)"
[ -f "$out/channel.json" ] && [ -f "$out/channel.json.sha256" ] || die "$out/channel.json missing: run --prepare first"
(cd "$out" && sha256sum -c --quiet channel.json.sha256 && sha256sum -c --quiet SHA256SUMS) || die "$out changed since --prepare"
echo "== verify signatures (keys built into this CLI)"
for s in "${sigs[@]}"; do
  [ -f "$s" ] || die "signature $s not found"
  go run ./tools/channelverify verify "$out/channel.json" "$s"   # every given signature must be by a trusted key
done
if command -v ssh-keygen >/dev/null; then   # cross-check with OpenSSH itself
  allowed=$(mktemp); go run ./tools/channelverify allowed-signers > "$allowed"
  for s in "${sigs[@]}"; do
    ssh-keygen -Y verify -f "$allowed" -I authfly-release -n authfly-channel -s "$s" < "$out/channel.json" || { rm -f "$allowed"; die "ssh-keygen -Y verify refused $s"; }
  done
  rm -f "$allowed"
fi
cat "${sigs[@]}" > "$out/channel.json.sig.tmp" && mv "$out/channel.json.sig.tmp" "$out/channel.json.sig"
go run ./tools/channelverify verify "$out/channel.json"   # the combined asset, as the CLI will fetch it
assets=$(cd "$out" && ls authfly-* console-linux-* SHA256SUMS channel.json channel.json.sig | sed "s#^#$out/#" | tr '\n' ' ')
if [ $mode = attach ]; then
  echo "attached: $out/channel.json.sig (nothing uploaded)"; exit 0
fi
images=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["releases"][-1]; print(" ".join(r["images"][b] for b in ("authfly","console")))' "$out/channel.json")
for i in $images; do
  case $i in localhost*|127.0.0.1*) die "channel.json pins $i: a local test registry; --prepare again for the real registry" ;; esac
  [[ $i == *@sha256:* ]] || die "$i is not pinned by registry digest"
  $DOCKER buildx imagetools inspect "${i%%:*}@${i#*@}" >/dev/null || die "$i is not in the registry"
done
echo "== gh release create v$v"
gh release create "v$v" --repo authfly/cli --title "authfly $v" --notes "authfly $v. Channel: channel.json (+ channel.json.sig, SSHSIG namespace authfly-channel); images: $images" $assets

#!/usr/bin/env bash
# Build a LOCAL release (file:// URLs, local image IDs) into dist/<version>; the public channel is tools/release-public.sh.
# Build a local release into dist/<version> and add it to dist/channel.json (the channel manifest).
#   tools/release.sh 0.3.0
# Static binaries + SHA256SUMS, docker images authfly/authfly:<v> and authfly/console:<v> built FROM those binaries,
# and the upstream Stalwart release pinned by its published sha256. The local channel is NOT signed: deploy it with
# channel.allow_unsigned: true (authfly init --allow-unsigned-channel); public releases are signed (docs/release.md).
set -euo pipefail
v=${1:?version}
cd "$(dirname "$0")/.."
out=dist/$v
mkdir -p "$out"
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
go build -trimpath -ldflags="-s -w -X main.Version=$v" -o "$out/authfly-linux-amd64" ./cmd/authfly
# The Console lives in authfly/stalwart (.deps/stalwart, pinned). Its .deps/cli and .deps/authkit are pointed at THIS
# checkout and our pinned authkit, so the release never mixes two versions of the JMAP client (server/core).
bash tools/deps.sh >/dev/null
mkdir -p .deps/stalwart/.deps && ln -sfn "$PWD" .deps/stalwart/.deps/cli && ln -sfn "$PWD/.deps/authkit" .deps/stalwart/.deps/authkit
(cd .deps/stalwart && go build -trimpath -ldflags="-s -w" -o "$OLDPWD/$out/console-linux-amd64" ./apps/console)
(cd "$out" && sha256sum authfly-linux-amd64 console-linux-amd64 > SHA256SUMS)
DOCKER=${DOCKER:-docker}
for b in authfly console; do
  $DOCKER build -q --build-arg BIN=$b -t authfly/$b:$v -f deploy/release.Dockerfile "$out" >/dev/null
done
SW_URL=https://github.com/stalwartlabs/stalwart/releases/download/v0.16.27/stalwart-x86_64-unknown-linux-gnu.tar.gz
SW_SHA=3d4548053e7130cdc6288134e28aecc5004f22549cc52a1dbda0ca48ff0b301a   # GitHub release asset digest
SW_IMG=stalwartlabs/stalwart:v0.16.27@sha256:c429b311c93db5606598abc1c68225a85a6953183848ae01bee9c6a98885836c
aid=$($DOCKER image inspect -f '{{.Id}}' authfly/authfly:$v); cid=$($DOCKER image inspect -f '{{.Id}}' authfly/console:$v)
python3 - "$v" "$out" "$aid" "$cid" "$SW_URL" "$SW_SHA" "$SW_IMG" <<'PY'
import json, os, sys
v, out, aid, cid, swurl, swsha, swimg = sys.argv[1:]
sums = dict(reversed(l.split()) for l in open(f"{out}/SHA256SUMS"))
base = "file://" + os.path.abspath(out)
rel = {"version": v, "files": {
         "authfly-linux-amd64": {"url": f"{base}/authfly-linux-amd64", "sha256": sums["authfly-linux-amd64"]},
         "console-linux-amd64": {"url": f"{base}/console-linux-amd64", "sha256": sums["console-linux-amd64"]},
         "stalwart-linux-amd64": {"url": swurl, "sha256": swsha}},
       "images": {"authfly": f"authfly/authfly:{v}@{aid}", "console": f"authfly/console:{v}@{cid}", "stalwart": swimg}}
p = "dist/channel.json"
m = json.load(open(p)) if os.path.exists(p) else {"channel": "stable", "releases": []}
m["releases"] = [r for r in m["releases"] if r["version"] != v] + [rel]
json.dump(m, open(p, "w"), indent=2)
print(f"release {v}: {p}")
PY

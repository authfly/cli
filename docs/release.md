# Releasing (public channel)

`npx authfly deploy` reads the channel manifest from
`https://github.com/authfly/cli/releases/latest/download/channel.json` (override: `authfly init --channel <url|file>`).
The manifest format is `server/deploy/channel.go`: per release a `version`, `files` (`authfly-linux-{amd64,arm64}`,
`console-linux-{amd64,arm64}`, `stalwart-linux-{amd64,arm64}`, each `{url, sha256}`; the Incus driver takes the
files of the host's architecture) and `images` (`authfly`, `console`, `stalwart`, each `ref@sha256:<digest>` of the
multi-arch index, so `docker pull` picks linux/amd64 or linux/arm64). Deploy and upgrade refuse any binary whose
sha256 differs and pull images **by digest** (`docker pull repo@sha256:…`); `authfly doctor` re-checks both. The
manifest is signed: see [Signing](#signing). Releases up to 0.4.0 are amd64 only (their entries have no arm64 files
and single-platform images).

## Tool

`tools/release-public.sh <version>` builds into `dist/release/<version>/`:

| Asset | What |
|---|---|
| `authfly-{linux,darwin}-{amd64,arm64}`, `authfly-windows-amd64.exe` | the `authfly` binary (CLI + server), static, `-trimpath` |
| `console-linux-{amd64,arm64}` | the Console from the pinned authfly/stalwart, built against this checkout (as `tools/release.sh`) |
| `SHA256SUMS` | sha256 of every binary |
| `channel.json` | the manifest: the previous `channel.json` of the latest GitHub release plus this version (newest last) |
| `channel.json.sig` | Ed25519 signature of `channel.json` ([Signing](#signing)) |

and the multi-arch images `<registry>/authfly:<v>` and `<registry>/console:<v>` (linux/amd64 + linux/arm64,
`docker buildx` with a `docker-container` builder, `deploy/release.Dockerfile`). The binaries are cross-compiled by
Go; the Dockerfile copies `<bin>-linux-$TARGETARCH` and runs nothing on the target platform, so no QEMU/binfmt is
needed. Asset URLs are `https://github.com/authfly/cli/releases/download/v<version>/<asset>`.

| Mode | Does |
|---|---|
| `--dry-run` (default) | builds everything (both platforms), pushes and uploads nothing; host-arch images pinned by local image ID (usable only on this host); signs if the key is there; prints the real commands |
| `--push-images` | also pushes the images to `--registry` and pins them by index digest (for a local `registry:2` test); needs the signing key |
| `--publish` | the real release: push, signed `channel.json` with index digests, `gh release create v<version>` with all assets |

Options: `--registry` (default `ghcr.io/authfly`, change if you publish elsewhere), `--base-url` (asset URL prefix),
`--previous` (manifest to extend; default the latest release's `channel.json`, empty = new channel).
Env: `AUTHFLY_SIGNING_KEY` (default `~/.config/authfly/release-signing.key`), `BUILDX_BUILDER` (default: a
`docker-container` builder `authfly-release`, or `authfly-release-local` with plain http allowed for a
`localhost:<port>` registry).

## Signing

`channel.json` is signed with Ed25519 (Go `crypto/ed25519`, no new dependency) into a detached `channel.json.sig`:

```json
{"format": "authfly-channel-sig/1",
 "signatures": [{"key_id": "16c52cedac5309c6", "alg": "ed25519", "sig": "<base64>"}]}
```

- **What is signed:** the exact bytes of `channel.json`, i.e. the whole manifest with every release in it. No
  canonical JSON is needed, and the file is byte-identical to what CLI 0.4.0 reads (it ignores the `.sig`), so one
  channel serves old and new CLIs: the channel of 0.4.1 lists 0.4.0 and 0.4.1 and is fully covered.
- **Why detached and not a field inside channel.json:** a field cannot sign the document that contains it without a
  canonicalization rule, and changing the manifest shape would risk the 0.4.0 parser. **Why not minisign/cosign:**
  minisign is Ed25519 too but needs a dependency or a reimplementation of its file format for the same guarantee;
  cosign keyless needs Sigstore (Fulcio/Rekor, OIDC) at release and verification time and a large dependency tree in
  a CLI that runs on servers. A pinned Ed25519 key in the binary is the smallest trust root.
- **Trusted keys:** `TrustedKeys` in `server/deploy/sign.go`, `key_id -> base64 public key`; the id is the first 8
  bytes of `sha256(public key)` and is checked against the key. `LoadManifest` (deploy, upgrade, rollback, doctor)
  verifies before parsing: missing `.sig` on https, unknown key id, or any modified byte is an error
  (`doctor`: `FAIL channel`).
- **Dev channels:** `channel.allow_unsigned: true` / `authfly init --allow-unsigned-channel` accepts a channel
  without `.sig` (local files, `file://`, `http://` test servers; `tools/release.sh` channels are unsigned). Off by
  default, rejected by `Validate` for `https://`, and a present but invalid signature is still refused.
- **Tool:** `go run ./tools/channelsign keygen|pubkey|sign|verify` (`release-public.sh` calls `sign` and then
  `verify` with the keys built into the checkout, so a release signed by a key the CLI does not trust fails).
- **Key:** PKCS#8 PEM, mode 0600, outside the repository (`~/.config/authfly/release-signing.key` on the release box).
  Keep an offline backup: losing it means a rotation, leaking it means a rotation *and* a CLI release that drops the
  old id.
- **Rotation:** `channelsign keygen <new>`, add the new id to `TrustedKeys`, release a CLI with both ids. Sign the
  channel with both keys (`channelsign sign -key old -key new`) while old CLIs are in use, then sign with the new key
  only and remove the old id in a later CLI. A bad signature by any trusted key is refused even if another verifies.

## Release

```sh
bash tools/deps.sh && bun run test                       # pins in deps.lock, green tests
bash tools/release-public.sh 0.4.1 --dry-run             # inspect dist/release/0.4.1/ (signed if the key is present)
echo "$GHCR_TOKEN" | docker login ghcr.io -u <user> --password-stdin   # token with write:packages
bash tools/release-public.sh 0.4.1 --publish             # buildx push (amd64+arm64), sign, gh release create v0.4.1
docker buildx imagetools inspect ghcr.io/authfly/authfly:0.4.1   # index with linux/amd64 + linux/arm64
```

After the first push, make the `authfly` and `console` packages on ghcr.io **public** (package settings), or
`docker pull` by digest fails on servers without credentials. Then publish the npm packages (`tools/npm-pack.sh`):
the GitHub release first, because a new CLI refuses the channel of an older release that has no `channel.json.sig`.

## Test without publishing

Serve `dist/release/<v>/` under the GitHub Releases paths and push the images to a local registry:

```sh
docker run -d --name afreg -p 127.0.0.1:5000:5000 registry:2
bash tools/release-public.sh 0.4.1 --registry localhost:5000/authfly --push-images \
  --base-url http://127.0.0.1:8099/authfly/cli/releases/download/v0.4.1     # signed with the release key
mkdir -p /tmp/ghsrv/authfly/cli/releases/download /tmp/ghsrv/authfly/cli/releases/latest
ln -s "$PWD/dist/release/0.4.1" /tmp/ghsrv/authfly/cli/releases/download/v0.4.1
ln -s "$PWD/dist/release/0.4.1" /tmp/ghsrv/authfly/cli/releases/latest/download
python3 -m http.server 8099 --bind 127.0.0.1 -d /tmp/ghsrv &
docker buildx imagetools inspect localhost:5000/authfly/authfly:0.4.1       # linux/amd64 + linux/arm64
authfly init ... --channel http://127.0.0.1:8099/authfly/cli/releases/latest/download/channel.json && authfly deploy
bash tools/e2e-deploy.sh <deploy dir>                     # flow / security / gdpr
```

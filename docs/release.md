# Releasing (public channel)

`npx authfly deploy` reads the channel manifest from
`https://github.com/authfly/cli/releases/latest/download/channel.json` (override: `authfly init --channel <url|file>`).
The manifest format is `server/deploy/channel.go`: per release a `version`, `files` (`authfly-linux-amd64`,
`console-linux-amd64`, `stalwart-linux-amd64`, each `{url, sha256}`) and `images` (`authfly`, `console`, `stalwart`,
each `ref@sha256:<digest>`). Deploy and upgrade refuse any binary whose sha256 differs and pull images **by digest**
(`docker pull repo@sha256:…`); `authfly doctor` re-checks both. The manifest itself is not signed yet (see
[Deploy](deploy.md#security-model)).

## Tool

`tools/release-public.sh <version>` builds into `dist/release/<version>/`:

| Asset | What |
|---|---|
| `authfly-{linux,darwin}-{amd64,arm64}`, `authfly-windows-amd64.exe` | the `authfly` binary (CLI + server), static, `-trimpath` |
| `console-linux-amd64` | the Console from the pinned authfly/stalwart, built against this checkout (as `tools/release.sh`) |
| `SHA256SUMS` | sha256 of every binary |
| `channel.json` | the manifest: the previous `channel.json` of the latest GitHub release plus this version (newest last) |

and the images `<registry>/authfly:<v>` and `<registry>/console:<v>` (`deploy/release.Dockerfile`, linux/amd64, FROM
the binaries above). Asset URLs are `https://github.com/authfly/cli/releases/download/v<version>/<asset>`.

| Mode | Does |
|---|---|
| `--dry-run` (default) | builds everything, pushes and uploads nothing; images pinned by local image ID (usable only on this host); prints the real commands |
| `--push-images` | also pushes the images to `--registry` and pins them by registry digest (for a local `registry:2` test) |
| `--publish` | the real release: `docker push`, `channel.json` with registry digests, `gh release create v<version>` with all assets |

Options: `--registry` (default `ghcr.io/authfly`, change if you publish elsewhere), `--base-url` (asset URL prefix),
`--previous` (manifest to extend; default the latest release's `channel.json`, empty = new channel).

## Release

```sh
bash tools/deps.sh && bun run test                       # pins in deps.lock, green tests
bash tools/release-public.sh 0.4.0 --dry-run             # inspect dist/release/0.4.0/
echo "$GHCR_TOKEN" | docker login ghcr.io -u <user> --password-stdin   # token with write:packages
bash tools/release-public.sh 0.4.0 --publish             # docker push + gh release create v0.4.0
```

After the first push, make the `authfly` and `console` packages on ghcr.io **public** (package settings), or
`docker pull` by digest fails on servers without credentials. Then publish the npm packages (`tools/npm-pack.sh`).

## Test without publishing

Serve `dist/release/<v>/` under the GitHub Releases paths and push the images to a local registry:

```sh
docker run -d --name afreg -p 127.0.0.1:5000:5000 registry:2
bash tools/release-public.sh 0.4.0 --registry localhost:5000/authfly --push-images \
  --base-url http://127.0.0.1:8099/authfly/cli/releases/download/v0.4.0 --previous ""
mkdir -p /tmp/ghsrv/authfly/cli/releases/download /tmp/ghsrv/authfly/cli/releases/latest
ln -s "$PWD/dist/release/0.4.0" /tmp/ghsrv/authfly/cli/releases/download/v0.4.0
ln -s "$PWD/dist/release/0.4.0" /tmp/ghsrv/authfly/cli/releases/latest/download
python3 -m http.server 8099 --bind 127.0.0.1 -d /tmp/ghsrv &
docker rmi localhost:5000/authfly/authfly:0.4.0 localhost:5000/authfly/console:0.4.0   # force pull by digest
authfly init ... --channel http://127.0.0.1:8099/authfly/cli/releases/latest/download/channel.json && authfly deploy
bash tools/e2e-deploy.sh <deploy dir>                     # flow / security / gdpr
```

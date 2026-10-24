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
| `channel.json.sig` | SSHSIG signature(s) of `channel.json` by the release YubiKey ([Signing](#signing)) |

and the multi-arch images `<registry>/authfly:<v>` and `<registry>/console:<v>` (linux/amd64 + linux/arm64,
`docker buildx` with a `docker-container` builder, `deploy/release.Dockerfile`). The binaries are cross-compiled by
Go; the Dockerfile copies `<bin>-linux-$TARGETARCH` and runs nothing on the target platform, so no QEMU/binfmt is
needed. Asset URLs are `https://github.com/authfly/cli/releases/download/v<version>/<asset>`.

The release is two-phase, because the signing key never leaves the maintainer's security key:

| Mode | Does |
|---|---|
| `--dry-run` (default) | builds everything (both platforms), pushes and uploads nothing; host-arch images pinned by local image ID (usable only on this host) |
| `--prepare` | builds, **pushes the images** (pinned by index digest; harmless: nothing pulls them without a signed channel), writes `channel.json` + `channel.json.sha256` and prints the exact signing command for the maintainer |
| `--attach --sig F [--sig F2]` | no rebuild: re-checks `SHA256SUMS` and the prepared `channel.json`, verifies every signature with the keys built into this CLI (`tools/channelverify`) and with `ssh-keygen -Y verify` if installed, writes `channel.json.sig`; uploads nothing |
| `--publish --sig F [--sig F2]` | `--attach`, checks that the images are registry digests that exist (`buildx imagetools inspect`), then `gh release create v<version>` with all assets |

Options (dry-run/prepare): `--registry` (default `ghcr.io/authfly`), `--base-url` (asset URL prefix), `--previous`
(manifest to extend; default the latest release's `channel.json`, empty = new channel). Env: `BUILDX_BUILDER`
(default: a `docker-container` builder `authfly-release`, or `authfly-release-local` with plain http allowed for a
`localhost:<port>` registry). The script refuses to build or publish when `GOFLAGS` carries the `authfly_e2ekeys`
test tag.

## Signing

The release key is a FIDO2 security key: YubiKey Security Key NFC (firmware 5.7.4), SSH key type
`sk-ssh-ed25519@openssh.com`, application `ssh:authfly-release`, resident, fingerprint
`SHA256:dhhWLt7kJTEad+0i8nBdu8MHeA5SgPDYQNXQmL8oPGc`. The maintainer signs with OpenSSH:

    ssh-keygen -Y sign -f <key handle> -n authfly-channel channel.json      # touch the key -> channel.json.sig

- **Format:** `channel.json.sig` is OpenSSH SSHSIG ([PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)),
  armored (`-----BEGIN SSH SIGNATURE-----`), namespace `authfly-channel`, hash `sha512` (the `ssh-keygen` default).
  It signs the exact bytes of `channel.json` — the whole manifest with every release in it — so no canonical JSON is
  needed and the file stays byte-identical to what CLI 0.4.0 reads (0.4.0 ignores the `.sig`): one channel serves
  old and new CLIs, and the channel of 0.4.1 (listing 0.4.0 and 0.4.1) is covered entirely.
- **Several signers:** the asset holds one armored block per signer, i.e. the `channel.json.sig` files written by
  `ssh-keygen` concatenated (`--publish --sig a.sig --sig b.sig`). The maintainer still makes one ordinary file per
  key; the CLI fetches one URL and does not probe for numbered files. One valid signature by a trusted key is
  enough; a trusted key whose block does not verify fails the channel; `--attach` requires every given file to be by
  a trusted key.
- **Checks** (`server/deploy/sign.go`, before anything in the manifest is parsed or trusted): magic and version,
  namespace `authfly-channel`, hash `sha512`, the embedded public key is one of `TrustedKeys`, the signature
  algorithm matches the key, and the signature verifies. For `sk-ssh-ed25519` the authenticator signed
  `sha256(application) || flags || counter || sha256(SSHSIG signed data)`; the application comes from the trusted
  public key, so a signature made under another application fails. The user-presence flag (touch) is required —
  stricter than `ssh-keygen -Y verify`, which only logs the flags for SSHSIG. The counter is reported (`doctor`) but
  not enforced: OpenSSH keeps no counter state for SSHSIG either. Plain `ssh-ed25519` keys are accepted too (tests,
  a spare key kept offline).
- **Library:** `golang.org/x/crypto/ssh` (already a dependency of the CLI, an official Go subrepository) parses the
  keys and verifies ed25519 and sk-ed25519 signatures. The SSHSIG envelope (about 60 lines) is parsed in
  `sign.go`; x/crypto has no SSHSIG package. Tests cross-check both directions with `ssh-keygen`.
- **Trusted keys:** `TrustedKeys` in `server/deploy/sign.go`, `authorized_keys` lines (no options; only
  `ssh-ed25519` and `sk-ssh-ed25519@openssh.com`, sk applications must start with `ssh:`).
  `go run ./tools/channelverify allowed-signers` prints them as an `ssh-keygen` allowed_signers file. Missing `.sig`
  on https, an unknown key, a wrong namespace, a missing touch or any modified byte is an error (`doctor`:
  `FAIL channel`).
- **Dev channels:** `channel.allow_unsigned: true` / `authfly init --allow-unsigned-channel` accepts a channel
  without `.sig` (local files, `file://`, `http://` test servers; `tools/release.sh` channels are unsigned). Off by
  default, rejected by `Validate` for `https://`, and a present but invalid signature is still refused.
- **Test builds:** `go build -tags authfly_e2ekeys` additionally trusts the `authorized_keys` line in
  `AUTHFLY_E2E_TRUSTED_KEY` (and says so on stderr). Only for the release e2e, where no YubiKey can sign.

### Signing on each OS

Copy the prepared `channel.json` to the machine with the YubiKey and compare its sha256 with the value
`--prepare` printed before signing.

- **Windows (PowerShell, built-in OpenSSH):** FIDO keys need Win32-OpenSSH **8.9 or newer**
  (`& "$env:WINDIR\System32\OpenSSH\ssh.exe" -V`); Windows talks to the key through its WebAuthn API, no
  `SSH_SK_PROVIDER` and no elevation are needed for signing (elevation is only needed for `ssh-keygen -K`). Call the
  built-in `ssh-keygen.exe` by path, because Git for Windows ships another one that may come first on `PATH` (if you
  installed a newer Win32-OpenSSH MSI, use `& "$env:ProgramFiles\OpenSSH\ssh-keygen.exe"` instead):

  ```powershell
  if ((Get-FileHash -Algorithm SHA256 .\channel.json).Hash -eq '<sha256 from --prepare>') { 'channel.json OK' } else { 'MISMATCH: do not sign' }
  & "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -Y sign -f "$HOME\.ssh\authfly_release_sk" -n authfly-channel .\channel.json
  ```

  Windows Security asks to touch the key (and for the FIDO2 PIN if the key was created with `verify-required`).
  Result: `.\channel.json.sig`. If the key handle file is missing on this PC, recover it from the resident key in an
  elevated prompt: `ssh-keygen -K` (writes `id_ed25519_sk_rk_authfly-release`, rename it to `authfly_release_sk`).
- **macOS:** Apple's bundled OpenSSH has no FIDO support: `brew install openssh` and use that `ssh-keygen`
  (`/opt/homebrew/bin/ssh-keygen` or `/usr/local/bin/ssh-keygen`):
  `ssh-keygen -Y sign -f ~/.ssh/authfly_release_sk -n authfly-channel channel.json`.
- **Linux:** OpenSSH 8.2+ with built-in FIDO (libfido2; Debian/Ubuntu `openssh-client`); the user needs access to
  the hidraw device (udev rules from `libfido2-1`/`yubikey-manager`). Same command as macOS.

Check locally before sending the signature back (Windows PowerShell 5 has no `<` input redirection and would
re-encode a pipe, hence `cmd /c`; the file is written with LF and no BOM). Expected: `Good "authfly-channel" signature
for authfly-release with ED25519-SK key SHA256:dhhWLt7k…`.

```powershell
[IO.File]::WriteAllText("$PWD\allowed_signers", 'authfly-release namespaces="authfly-channel" sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEE96BHnD/bfSH23hMnp6FiXGdWq0sDOTZzZW4PUSCpEAAAAE3NzaDphdXRoZmx5LXJlbGVhc2U=' + "`n")
cmd /c "%WINDIR%\System32\OpenSSH\ssh-keygen.exe -Y verify -f allowed_signers -I authfly-release -n authfly-channel -s channel.json.sig < channel.json"
```

```sh
go run ./tools/channelverify allowed-signers > allowed_signers           # macOS / Linux / the release box
ssh-keygen -Y verify -f allowed_signers -I authfly-release -n authfly-channel -s channel.json.sig < channel.json
go run ./tools/channelverify verify channel.json channel.json.sig        # what the CLI checks (incl. touch)
```

### Spare key, loss and rotation

- **Get a second YubiKey now** (`ssh-keygen -t ed25519-sk -O resident -O application=ssh:authfly-release-2 -f
  authfly_release_2_sk`), keep it offline, and add its `.pub` line to `TrustedKeys` in the next CLI release. Then
  losing one key costs nothing: sign with the other.
- **Rotation:** add the new key to `TrustedKeys` and release a CLI with both keys. While older CLIs are in use, sign
  every channel with both keys (`--sig old.sig --sig new.sig`); later drop the old key from `TrustedKeys`.
- **Lost key, no spare:** CLIs that only trust the lost key can no longer verify new channels. Generate a new key,
  release a CLI that trusts it (the release with the new CLI is signed by the new key), and tell users to update
  with `npx authfly@latest`: installs keep running, only `deploy`/`upgrade`/`doctor` against the new channel fail
  until the CLI is updated. A FIDO credential cannot be exported, so there is no backup of the key itself — only a
  second key.
- **Stolen key:** the thief also needs the touch (and the PIN if set): set a FIDO2 PIN. Treat it like a leak anyway:
  rotate and remove the old key from `TrustedKeys` in the next CLI.

## Release

```sh
bash tools/deps.sh && bun run test                       # pins in deps.lock, green tests
bash tools/release-public.sh 0.4.1 --dry-run             # inspect dist/release/0.4.1/
echo "$GHCR_TOKEN" | docker login ghcr.io -u <user> --password-stdin   # token with write:packages
bash tools/release-public.sh 0.4.1 --prepare             # buildx push (amd64+arm64), channel.json, signing command
# maintainer: sign channel.json with the YubiKey (above), copy channel.json.sig back
bash tools/release-public.sh 0.4.1 --publish --sig /path/to/channel.json.sig   # verify, gh release create v0.4.1
docker buildx imagetools inspect ghcr.io/authfly/authfly:0.4.1   # index with linux/amd64 + linux/arm64
```

After the first push, make the `authfly` and `console` packages on ghcr.io **public** (package settings), or
`docker pull` by digest fails on servers without credentials. Then publish the npm packages (`tools/npm-pack.sh`):
the GitHub release first, because a new CLI refuses the channel of an older release that has no `channel.json.sig`.

## Test without publishing

No YubiKey on a test box: sign with a throwaway `ssh-ed25519` key and use a CLI built with the `authfly_e2ekeys`
tag that also trusts it. Serve `dist/release/<v>/` under the GitHub Releases paths and push the images to a local
registry:

```sh
docker run -d --name afreg -p 127.0.0.1:5000:5000 registry:2
bash tools/release-public.sh 0.4.1 --registry localhost:5000/authfly --prepare \
  --base-url http://127.0.0.1:8097/authfly/cli/releases/download/v0.4.1
ssh-keygen -q -t ed25519 -N '' -f /tmp/e2e-key
ssh-keygen -Y sign -f /tmp/e2e-key -n authfly-channel dist/release/0.4.1/channel.json   # -> channel.json.sig
mv dist/release/0.4.1/channel.json.sig /tmp/e2e.sig
export AUTHFLY_E2E_TRUSTED_KEY="$(cat /tmp/e2e-key.pub)"
GOFLAGS=-tags=authfly_e2ekeys bash tools/release-public.sh 0.4.1 --attach --sig /tmp/e2e.sig
go build -tags authfly_e2ekeys -o /tmp/authfly-e2e ./cmd/authfly           # test CLI (never shipped)
mkdir -p /tmp/ghsrv/authfly/cli/releases/download /tmp/ghsrv/authfly/cli/releases/latest
ln -s "$PWD/dist/release/0.4.1" /tmp/ghsrv/authfly/cli/releases/download/v0.4.1
ln -s "$PWD/dist/release/0.4.1" /tmp/ghsrv/authfly/cli/releases/latest/download
python3 -m http.server 8097 --bind 127.0.0.1 -d /tmp/ghsrv &
docker buildx imagetools inspect localhost:5000/authfly/authfly:0.4.1       # linux/amd64 + linux/arm64
/tmp/authfly-e2e init ... --channel http://127.0.0.1:8097/authfly/cli/releases/latest/download/channel.json
sudo -E /tmp/authfly-e2e deploy && bash tools/e2e-deploy.sh <deploy dir>  # flow / security / gdpr
```

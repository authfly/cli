# Deploying Authfly — `npx authfly`

    npx authfly init          # 6-step wizard → authfly.yaml (or non-interactive: -y plus flags)
    npx authfly deploy        # idempotent: secrets, policy docs, firewall, containers, init-stalwart, health
    npx authfly status | doctor [--json]
    npx authfly backup | restore <file>
    npx authfly upgrade [--to <version>] | rollback
    npx authfly secrets | down [--purge]

The `authfly` npm package carries no install script and downloads nothing. Its platform binary comes through
`optionalDependencies` (`@authfly/cli-<os>-<arch>`). `bin/authfly.js` checks the binary's sha256 against the
`checksums.json` shipped inside the package and refuses to run a binary that doesn't match.

## Wizard (`authfly init`)

1. **App:** runtime (react, vue, svelte, solid, templ, twig, latte, jinja2; the web-component widgets are used directly from authfly/authkit), name, and adapter (node, go, php, python).
2. **Domain:** mail domain, public URL, TLS mode (`acme` / `manual` / `off` for localhost), and ports.
3. **Sign-in:** methods (magic link and/or password) and OIDC clients (`id:Name=redirect_uri;…`).
4. **Policy:** pack (gdpr / us-pii / ru-152fz / none), operator, host country, and US states.
5. **Target:** `docker` (compose) or `incus` (system containers), firewall, and encryption at rest.
6. **Channel:** update-channel URL or path, then a review and write.

Non-interactive example:

    authfly init -y --runtime templ --adapter go --policy ru-152fz --host-country RU --target incus \
      --domain example.ru --public-url https://auth.example.ru --tls acme \
      --client "web:Web app=https://example.ru/callback" --channel https://…/channel.json

## Targets

**docker.** Writes the compose file `.authfly/compose.yml`, with images pinned by digest and verified against the
channel. Every service runs `read_only`, `cap_drop: ALL` (Stalwart adds back only NET_BIND_SERVICE), and
`no-new-privileges`. Secrets are compose file secrets. Management ports are bound to `127.0.0.1`.

**incus.** Creates the network `authfly0` (10.118.42.0/24) and the profile `authfly-<name>`. It then starts
unprivileged `images:debian/13` system containers `<name>-stalwart`, `-authfly` and `-console`, running systemd
units. Release binaries are pushed from the host after a checksum check, so the containers need no egress. Public
ports use proxy devices. Upgrades take snapshots. `incus.no_limits` exists for hosts without cgroup memory
delegation. Incus 6.3 or later can run OCI images, but this target does not need it.

## Security model

- **Secrets.** Kept in `.authfly/secrets/` (directory 0700, files 0600): the Stalwart admin password, the service
  password, the Authfly secret, the admin key, the console password and secret, and the backup key. Secrets are
  never passed in env vars: the server reads `*_FILE`. `authfly secrets` lists names only.
- **Least privilege.** init-stalwart creates a service account with only the permissions Authfly uses. It turns
  off Stalwart's web admin and self-service UI (the doctor checks for a 404). It also turns off Pyzor (DNS
  egress, privacy) and dynamic client registration.
- **Exposure.** Only the public Authfly port and the mail ports listen publicly. Management (:8080) and the console
  listen on loopback only; the doctor probes every local address. nftables rules are generated and checked with
  `nft -c`.
- **TLS.** `acme` (autocert), `manual` (cert/key files) or `off` (localhost only). Mail ACME is **stubbed**.
- **Backups.** `AFBK1`: AES-256-GCM in 1 MiB chunks with a counter nonce and last-chunk AAD, so truncation and
  tampering are detected. Copy the `backup_key` off the server.
- **Updates.** The channel manifest lists the version, the binary sha256 and the image digests (multi-arch index
  digests). Anything that doesn't match is refused. The manifest itself is signed (OpenSSH SSHSIG by the release
  YubiKey, detached `channel.json.sig`, trusted keys built into the CLI): deploy, upgrade, rollback and doctor refuse an unsigned, tampered
  or unknown-key channel before reading any digest from it. `channel.allow_unsigned` (dev only, never for https)
  accepts an unsigned local channel. See [Releasing](release.md#signing).
- **Rollback safety.** `upgrade` takes a backup or snapshot first and rolls back automatically if health or doctor
  fails. `rollback` restores the pre-upgrade data and release.

## Verified on this box (2026-10-21)

| Combo | Deploy | e2e flow / security / gdpr | Upgrade 0.3.0→0.3.1 | Rollback |
|---|---|---|---|---|
| React + GDPR + docker | ok | 15/15, 11/11, 11/11 | ok (44 s, digests verified) | ok (43 s; data from after the upgrade gone; doctor 0 FAIL) |
| templ/Go + 152-FZ + incus | ok (46 s, doctor 0 FAIL) | 15/15, 11/11, 11/11 | ok (15 s, digests verified). The first try hit "text file busy" and auto-rolled back; fixed with an atomic push | ok (12 s; data from after the upgrade gone; doctor 0 FAIL) |

## Not wired / stubbed

- sqlite and postgres stores: `store: json` only.
- Mail ACME.
- Stalwart's upstream sigstore bundles are not verified (its tarballs and image are pinned by sha256 / index digest
  inside the signed channel).
- The username toggle is coarse.
- Firewall rules are generated and validated but were not loaded on the test box (it shares its netns with other
  workloads).

# apps/yself — YSELF on yself.link

The YSELF app: the welcome page (`/`), public link pages (`/<handle>`, Taplink/Linktree style) and the page editor
(`/me`) for users signed in through accounts.yself.link. It is an OIDC relying party of the Authfly IdP
(`server/rp`), `sub` = the Stalwart account id.

Why here (authfly/cli, not a new repo): it reuses `server/rp` (OIDC client, back-channel logout), `server/rpui`
(shared templ chrome), AuthFly's reserved names (`core.DefaultReservedNames` + `AUTHFLY_RESERVED_NAMES_FILE`) and the
pinned authkit UI8Kit 3 templ primitives; one module, one CI, one deploy pipeline. `examples/rp` stays the minimal
reference RP (test.yself.link).

- UI: templ + UI8Kit 3 primitives (`box`, `text`, `button`, `link`, `input`, `textarea`, `select`, `radio`,
  `checkbox`, `image`, `disclosure`, `form`) and the Authfly layer (Card, Stack, Group, Field, Alert, Badge, Title).
  Tokens only, 8px layout step, `npx ui8px lint` = 0. Public pages need no JavaScript (CSP without script-src).
- Handle: `[a-z0-9-]`, 3–30, no leading/trailing/double hyphen; not an app route; not an AuthFly reserved name
  unless it is your own mailbox local part (wmaster → wmaster). Default = mailbox local part.
- Links: `https://` (with host, no userinfo) and `mailto:` only; up to 30; reorder up/down, hide/show, icon from a
  Lucide allowlist; rendered with `rel="noopener nofollow ugc"`.
- Avatar: multipart ≤ 4 MB, ≤ 40 MP, JPEG/PNG/GIF/WebP → centre crop, 256×256 JPEG (metadata dropped by the
  re-encode), random 128-bit file name under `$YSELF_DATA/avatars`; served only for `^[a-f0-9]{32}\.jpg$`.
- Storage: SQLite (`modernc.org/sqlite`, pure Go, WAL) `$YSELF_DATA/yself.db`. On fra-ypanel `$YSELF_DATA` =
  `/var/lib/yself` inside web/site, covered by the nightly restic `incus export` of every instance.
- Security: PRG with a one-time flash cookie; CSRF = same Origin + per-session synchronizer token; rate limits per IP
  (X-Forwarded-For trusted only from `YSELF_TRUSTED_PROXY`) and per account: 60 POST/min, 10 uploads/10 min.

Run: see `yself.service`. Seed: `yself seed -sub 2 -handle wmaster -name … -bio … -link "Title|https://…|icon"`.
Preview for screenshots: `YSELF_PREVIEW=127.0.0.1:18090 YSELF_PREVIEW_COOKIE=/tmp/c go test -run TestServe ./apps/yself`.

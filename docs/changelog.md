# Changelog

## 2026-10-30 — UI8Kit 3 everywhere, cabinet UX, YSELF pages

- **accounts.yself.link cabinet**: sidebar navigation with icons and the signed-in user (wrapped row on phones),
  skip link, every section in its own card with an icon title, dashboard tiles on Home, empty states (app passwords,
  activity, apps, sessions), destructive actions behind a native `details` confirmation (revoke app / app password,
  sign out others / everywhere, delete account in a red "danger zone"), TOTP status badge, otpauth URL in a read-only
  field, consistent outline-danger buttons. PRG + CSRF unchanged; e2e unchanged and all-pass. `ui8px lint` 0 (was 13).
- **server/rp**: the OIDC relying party extracted from examples/rp into a library (PKCE S256, state, nonce, RFC 9207
  iss, back-channel logout by sid or sub, session-bound CSRF token, `SafeNext` against open redirects).
- **server/rpui**: shared templ document/header/theme/language chrome and assets for the relying-party apps.
- **examples/rp** (test.yself.link): plain `html/template` page replaced by templ + UI8Kit 3.
- **apps/yself** (yself.link): new — welcome page, public link pages `yself.link/<handle>`, editor `/me`
  (see apps/yself/README.md). Replaces the `rp` service on web/site :8080 (`yself.service`).

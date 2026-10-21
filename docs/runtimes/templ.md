# templ

The templ widgets live in `packages/ui/templ`: a plain local set (primitives, helpers, styles and the six Authkit widgets), no registry and no CDN. Copy the folder into your app or import it by path. The Authkit server's hosted pages are this set: `server/web` renders every page with it. The Go module is `github.com/ui8kit/codegen/packages/templ/ui`; point it at the local copy with a `replace` directive.

::preview sign-in

The preview is rendered by the templ set; the templ set renders the same DOM (codegen parity gate).

## Module

```text
require github.com/ui8kit/codegen/packages/templ/ui v0.0.0
replace github.com/ui8kit/codegen/packages/templ/ui => ./packages/ui/templ
```

## Render a widget

```go
import blocks "github.com/ui8kit/codegen/packages/templ/ui/blocks"

c := blocks.AuthkitSignIn(blocks.AuthkitSignInProps{
	Id: "signin", Title: "Sign in", Text: "Welcome back.", Action: "/auth/sign-in", Csrf: csrf,
	Method: "password", Identifier: "any", Social: "none",
	Labels: map[string]any{"identifier": "Email or username", "password": "Password", "submit": "Sign in"},
})
_ = c.Render(ctx, w)
```

## Embed the whole server

The core is a Go package: `core.Service` (Stalwart, mailer, signer, store) and `web.New(svc, registry, clients, secure).Handler()` give you every hosted route and the JSON API in your own `http.ServeMux`. `cmd/authkit/main.go` shows the wiring from environment variables.

## Styles

Tailwind v4 over the templ set (see `server/web/app.css`):

```css
@import "../../packages/ui/react/src/styles/theme.css";
@import "../../packages/ui/react/src/styles/kit.css";
@source "../../packages/ui/templ/ui";
@source "../../packages/ui/templ/blocks";
```

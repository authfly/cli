# Solid

The Solid widgets live in `packages/ui/solid`: a plain local set (primitives, helpers, styles and the six Authkit widgets), no registry and no CDN. Copy the folder into your app or import it by path. Solid components; server rendering works with SolidStart.

::preview sign-in

The preview is rendered by the templ set; the Solid set renders the same DOM (codegen parity gate).

## Styles

```css
@import "../packages/ui/solid/src/styles/index.css";
@source "./";
```

## Render a widget

```tsx
import { AuthkitSignIn } from "../packages/ui/solid/src/authkit";

export function SignIn(props: { csrf: string; error?: string }) {
  return (
    <AuthkitSignIn id="signin" title="Sign in" text="Welcome back." action="/auth/sign-in" csrf={props.csrf} error={props.error}
      method="password" identifier="any" social="none"
      labels={{ identifier: "Email or username", password: "Password", submit: "Sign in", forgot: "Forgot password?", forgotHref: "/forgot" }} />
  );
}
```
## Backend

The widgets only render forms. Pick one:

- **Hosted pages**: link to the Authkit server (`/auth/sign-in` and friends) and use [OIDC](../oidc.md) to sign in to your app. Nothing to wire.
- **Your own routes**: render the widgets in your app with `action` pointing at your route, and call the [JSON API](../contract.md) from your server with the adapter.

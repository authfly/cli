# React

The React widgets live in `packages/ui/react`: a plain local set (primitives, helpers, styles and the six Authfly widgets), no registry and no CDN. Copy the folder into your app or import it by path. Imports resolve React, `clsx` and `tailwind-merge` from your app (with Vite, list them in `resolve.dedupe`).

::preview sign-in

The preview is rendered by the templ set; the React set renders the same DOM (codegen parity gate).

## Styles

```css
/* app.css, Tailwind v4 */
@import "../packages/ui/react/src/styles/index.css";
@source "./";
```

## Render a widget

```tsx
import { AuthflySignIn } from "../packages/ui/react/src/authfly";

export function SignIn({ csrf, error }: { csrf: string; error?: string }) {
  return (
    <AuthflySignIn id="signin" title="Sign in" text="Welcome back." action="/auth/sign-in" csrf={csrf} error={error}
      method="password" identifier="any" social="none"
      labels={{ identifier: "Email or username", password: "Password", submit: "Sign in", forgot: "Forgot password?", forgotHref: "/forgot" }} />
  );
}
```
## Backend

The widgets only render forms. Pick one:

- **Hosted pages**: link to the Authfly server (`/auth/sign-in` and friends) and use [OIDC](../oidc.md) to sign in to your app. Nothing to wire.
- **Your own routes**: render the widgets in your app with `action` pointing at your route, and call the [JSON API](../contract.md) from your server with the adapter.

## Sign in to a React app with OIDC

`apps/demo-react` is a complete example: a Bun server (`server.ts`) with `/login`, `/callback`, `/logout` and `/api/me` on `@authfly/node`, and the React app showing `AuthflyNotice` signed out and `AuthflyAccount` signed in.

```ts
import { Authfly, cookie, setCookie } from "@authfly/node";
const auth = new Authfly({ authflyUrl, stalwartUrl, clientId: "demo-react", redirectUri, sessionSecret });
const { url, pending } = await auth.authorizeUrl();
const { user } = await auth.callback(new URL(req.url).searchParams, pending);
```

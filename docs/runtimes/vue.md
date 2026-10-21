# Vue

The Vue widgets live in `packages/ui/vue`: a plain local set (primitives, helpers, styles and the six Authkit widgets), no registry and no CDN. Copy the folder into your app or import it by path. Single-file components with typed props (`defineProps`).

::preview sign-in

The preview is rendered by the templ set; the Vue set renders the same DOM (codegen parity gate).

## Styles

```css
@import "../packages/ui/vue/src/styles/index.css";
@source "./";
```

## Render a widget

```vue
<script setup lang="ts">
import { AuthkitSignIn } from "../packages/ui/vue/src/authkit";
defineProps<{ csrf: string; error?: string }>();
</script>

<template>
  <AuthkitSignIn id="signin" title="Sign in" text="Welcome back." action="/auth/sign-in" :csrf="csrf" :error="error"
    method="password" identifier="any" social="none"
    :labels="{ identifier: "Email or username", password: "Password", submit: "Sign in", forgot: "Forgot password?", forgotHref: "/forgot" }" />
</template>
```
## Backend

The widgets only render forms. Pick one:

- **Hosted pages**: link to the Authkit server (`/auth/sign-in` and friends) and use [OIDC](../oidc.md) to sign in to your app. Nothing to wire.
- **Your own routes**: render the widgets in your app with `action` pointing at your route, and call the [JSON API](../contract.md) from your server with the adapter.

With Nuxt or a Node server, use `@authkit/node` (`packages/adapters/ts`) for OIDC as in the [React guide](react.md).

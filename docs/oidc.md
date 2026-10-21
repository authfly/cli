# Configure OIDC

Stalwart is the OpenID provider: it issues the authorization codes, ID tokens (ES256, published at `/auth/jwks.json`) and access tokens, and answers `/auth/userinfo`. Authkit is the sign-in front end in between: your app sends the user to Authkit, Authkit shows the hosted sign-in and consent, gets the authorization code from Stalwart with your app's own `client_id`, `redirect_uri` and PKCE challenge, and redirects back. Your app exchanges the code at Stalwart's token endpoint and verifies the ID token against Stalwart's keys.

::preview consent

## The flow

1. Your app creates `state`, `nonce` and a PKCE verifier, and redirects to `AUTHKIT_PUBLIC_URL/oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid%20email%20profile&state=...&nonce=...&code_challenge=...&code_challenge_method=S256`.
2. Authkit checks the client and redirect URI against `AUTHKIT_CLIENTS`, shows the sign-in (password; a magic link cannot mint Stalwart tokens, see below), then the consent widget.
3. On allow, Authkit calls Stalwart `POST /api/auth` (type `authCode`) with the account, the password just entered and your app's parameters, and redirects to your `redirect_uri` with `code` and `state`. On deny it redirects with `error=access_denied`.
4. Your server posts `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier` to Stalwart's `token_endpoint` (from `STALWART_URL/.well-known/openid-configuration`).
5. Verify the `id_token`: ES256 signature from `jwks_uri`, `iss` (the Stalwart public URL), `aud` (your client id), `nonce`, `exp`. Claims seen in v0.16: `sub`, `email`, `preferred_username`, `description` (the display name).

## Register your app

Add it to `AUTHKIT_CLIENTS`:

```sh
AUTHKIT_CLIENTS='[{"id":"my-app","name":"My app","redirect_uris":["https://app.example.com/callback"]}]'
```

In the tested v0.16 setup Stalwart accepted any `client_id` and `http` redirect URIs without registering a client, so the allow list in Authkit is the gate. If you register OAuth clients in Stalwart, use the same id and redirect URIs there.

## Node and Bun

```ts
import { Authkit } from "@authkit/node";

const auth = new Authkit({
  authkitUrl: "https://auth.example.com",
  stalwartUrl: "https://mail.example.com",
  clientId: "my-app",
  redirectUri: "https://app.example.com/callback",
  sessionSecret: process.env.SESSION_SECRET!,
});

// GET /login
const { url, pending } = await auth.authorizeUrl(); // keep `pending` in a sealed cookie
// GET /callback
const { user } = await auth.callback(new URL(req.url).searchParams, pending);
```

`apps/demo-react/server.ts` is the complete example: login, callback, logout and `/api/me` with sealed cookies.

## Limits

- **Magic link and SSO**: Stalwart issues codes only for a password it can check. A user signed in to Authkit by magic link is asked for the password once when an app starts SSO. Magic links sign in to Authkit itself and to apps that use the Authkit session or JSON API.
- **Stalwart's own login page**: set `loginVia: "stalwart"` in the Node adapter to skip Authkit and use Stalwart's `/login` page instead.

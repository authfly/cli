package deploy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

// widgetSet: what to install for each widget runtime (the six Authfly blocks: sign-in, sign-up, request, notice,
// account, consent).
var widgetSet = map[string]string{
	"react":  "npm i @authfly/react      # import { AuthflySignIn, AuthflySignUp, ... } from \"@authfly/react/blocks/...\"",
	"vue":    "npm i @authfly/vue        # .vue blocks under @authfly/vue/blocks",
	"svelte": "npm i @authfly/svelte     # .svelte blocks under @authfly/svelte/blocks",
	"solid":  "npm i @authfly/solid      # .tsx blocks under @authfly/solid/blocks",
	"templ":  "authfly/authkit packages/ui/templ: require github.com/authfly/authkit/packages/ui/templ + replace it with your checkout   # authfly.AuthflySignIn(...)",
	"twig":   "copy authfly/authkit packages/ui/twig (blocks/, authfly/, ui/, runtime/, src/; composer autoload) into your templates path",
	"latte":  "copy authfly/authkit packages/ui/latte (blocks/, authfly/, ui/, runtime/, src/; composer autoload) into your templates path",
	"jinja2": "copy authfly/authkit packages/ui/jinja2 (blocks/, authfly/, ui/, authfly_jinja/, ui8kit_jinja/) into your templates folder",
}

func adapterSnippet(c *Config, cl Client) string {
	redirect := cl.RedirectURIs[0]
	switch c.App.Adapter {
	case "node", "bun":
		return fmt.Sprintf(`// npm i @authfly/node
import { Authfly } from "@authfly/node";
export const auth = new Authfly({
  authflyUrl: %q,
  stalwartUrl: %q,      // OIDC endpoints are served by Authfly's proxy
  clientId: %q,
  redirectUri: %q,
  sessionSecret: process.env.SESSION_SECRET!, // 32+ chars, keep it out of git
});
// GET /login    -> const { url, pending } = await auth.authorizeUrl(); keep pending in a signed cookie; redirect(url)
// GET /callback -> const { user } = await auth.callback(new URL(req.url).searchParams, pending);
`, c.PublicURL, c.PublicURL, cl.ID, redirect)
	case "php":
		return fmt.Sprintf(`<?php // composer: authfly/authfly (sdk/php)
require 'vendor/autoload.php';
$auth = new \Authfly\Authfly(%q, %q, %q, %q);
// /login: [$url, $pending] = $auth->authorizeUrl(); $_SESSION['pending'] = $pending; header("Location: $url");
// /callback: $user = $auth->callback($_GET, $_SESSION['pending']);
`, c.PublicURL, c.PublicURL, cl.ID, redirect)
	case "python":
		return fmt.Sprintf(`# pip install authfly (authfly/authfly sdk/python)
from authfly import Authfly
auth = Authfly(%q, %q, %q, %q)
# /login: url, pending = auth.authorize_url(); session["pending"] = pending; redirect(url)
# /callback: user = auth.callback(request.args, session["pending"])
`, c.PublicURL, c.PublicURL, cl.ID, redirect)
	default: // go
		return fmt.Sprintf(`// Go: Authfly is a standard OIDC provider (authorization code + PKCE). With golang.org/x/oauth2 + coreos/go-oidc:
provider, _ := oidc.NewProvider(ctx, %q)
conf := oauth2.Config{ClientID: %q, RedirectURL: %q, Endpoint: oauth2.Endpoint{AuthURL: %q + "/oauth/authorize", TokenURL: provider.Endpoint().TokenURL},
	Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
`, c.PublicURL, cl.ID, redirect, c.PublicURL)
	}
}

// WriteAppKit writes .authfly/app: the widget set, the adapter snippet and the client config for the chosen runtime.
func (c *Config) WriteAppKit() error {
	cl := Client{ID: c.Name + "-app", Name: c.Name, RedirectURIs: []string{"https://" + c.Domain + "/callback"}}
	if len(c.App.Clients) > 0 {
		cl = c.App.Clients[0]
	}
	cfg, _ := json.MarshalIndent(map[string]any{"authflyUrl": c.PublicURL, "issuer": c.PublicURL, "clientId": cl.ID, "redirectUri": cl.RedirectURIs[0],
		"signIn": map[string]bool{"magicLink": c.SignIn.MagicLink, "password": c.SignIn.Password, "username": c.SignIn.Username}, "policy": c.Policy.Pack}, "", "  ")
	ext := map[string]string{"node": "ts", "bun": "ts", "php": "php", "python": "py", "go": "go"}[c.App.Adapter]
	dir := filepath.Join(c.State(), "app")
	readme := "# Your app kit (" + c.App.Runtime + " widgets + " + c.App.Adapter + " adapter)\n\n" +
		"1. Widgets: `" + widgetSet[c.App.Runtime] + "`\n2. Adapter: `adapter." + ext + "` (sign-in redirect + callback)\n3. Config: `authfly.json`\n" +
		"4. Register more apps under app.clients in authfly.yaml and run `authfly deploy`.\n"
	for p, d := range map[string]string{"README.md": readme, "adapter." + ext: adapterSnippet(c, cl), "authfly.json": string(cfg) + "\n"} {
		if err := writeFile(filepath.Join(dir, p), d); err != nil {
			return err
		}
	}
	return nil
}

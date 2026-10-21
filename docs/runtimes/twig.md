# Twig

The Twig widgets live in `packages/ui/twig`: a plain local set (primitives, helpers, styles and the six Authkit widgets), no registry and no CDN. Copy the folder into your app or import it by path. Templates take their props as `p`; the `UI8Kit\Twig\Extension` adds the `ui_*` helpers. Requires `twig/twig` ^3.21 and PHP 8.2.

::preview sign-in

The preview is rendered by the templ set; the Twig set renders the same DOM (codegen parity gate).

## Set up

```php
require 'vendor/autoload.php';           // twig/twig
require 'packages/ui/twig/php/CnMerge.php';
require 'packages/ui/twig/php/Runtime.php';
require 'packages/ui/twig/php/Extension.php';

$twig = UI8Kit\Twig\Extension::environment(__DIR__ . '/packages/ui/twig');
echo $twig->render('blocks/authkit-sign-in.html.twig', ['p' => [
    'id' => 'signin', 'title' => 'Sign in', 'text' => 'Welcome back.', 'action' => '/sign-in', 'csrf' => $csrf,
    'method' => 'password', 'identifier' => 'any', 'social' => 'none',
    'labels' => ['identifier' => 'Email or username', 'password' => 'Password', 'submit' => 'Sign in'],
]]);
```

In Symfony, register the extension as a service and add `packages/ui/twig` as a Twig path.

## Backend

```php
require 'packages/adapters/php/src/Authkit.php';
$api = new Authkit\AuthkitApi('http://localhost:4000');
$session = $api->signIn($_POST['identifier'], $_POST['password']);   // ['token', 'user']
```

For SSO use `Authkit\Authkit` (OIDC with PKCE), see [Adapters](../adapters.md).

## Styles

The server-side sets ship templates only. Build the CSS with Tailwind v4 from the shared theme and scan the templates:

```css
@import "../packages/ui/react/src/styles/theme.css";
@import "../packages/ui/react/src/styles/kit.css";
@source "../packages/ui/twig";
```

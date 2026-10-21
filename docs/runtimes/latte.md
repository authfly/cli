# Latte

The Latte widgets live in `packages/ui/latte`: a plain local set (primitives, helpers, styles and the six Authfly widgets), no registry and no CDN. Copy the folder into your app or import it by path. Templates take their props as `$p`; `UI8Kit\Latte\Extension::engine()` gives a ready engine. Requires `latte/latte` ^3 and PHP 8.2.

::preview sign-in

The preview is rendered by the templ set; the Latte set renders the same DOM (codegen parity gate).

## Set up

```php
require 'vendor/autoload.php';           // latte/latte
require 'packages/ui/latte/php/CnMerge.php';
require 'packages/ui/latte/php/Runtime.php';
require 'packages/ui/latte/php/Extension.php';

$latte = UI8Kit\Latte\Extension::engine(__DIR__ . '/packages/ui/latte', sys_get_temp_dir());
$latte->render('blocks/authfly-sign-in.latte', ['p' => [
    'id' => 'signin', 'title' => 'Sign in', 'text' => 'Welcome back.', 'action' => '/sign-in', 'csrf' => $csrf,
    'method' => 'password', 'identifier' => 'any', 'social' => 'none',
    'labels' => ['identifier' => 'Email or username', 'password' => 'Password', 'submit' => 'Sign in'],
]]);
```

In Nette, add the extension to the Latte factory.

## Backend

The PHP adapter (`packages/adapters/php`) covers the JSON API and OIDC, see [Adapters](../adapters.md).

## Styles

The server-side sets ship templates only. Build the CSS with Tailwind v4 from the shared theme and scan the templates:

```css
@import "../packages/ui/react/src/styles/theme.css";
@import "../packages/ui/react/src/styles/kit.css";
@source "../packages/ui/latte";
```

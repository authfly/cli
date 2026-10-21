# ui8kit/authkit (PHP)

No dependencies. `require 'src/Authkit.php';` or add the folder as a Composer path repository.

```php
use Authkit\{Authkit, AuthkitApi};

$api = new AuthkitApi('http://localhost:4000');
$session = $api->signIn('alice@example.com', 'a long password'); // ['token' => ..., 'user' => ...]

$oidc = new Authkit('http://localhost:4000', 'http://localhost:8080', 'my-app', 'http://localhost:8000/callback');
[$url, $pending] = $oidc->authorizeUrl();       // redirect; keep $pending in the session
$result = $oidc->callback($_GET, $pending);       // ['user' => claims, 'tokens' => ...]
```

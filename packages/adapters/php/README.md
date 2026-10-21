# ui8kit/authfly (PHP)

No dependencies. `require 'src/Authfly.php';` or add the folder as a Composer path repository.

```php
use Authfly\{Authfly, AuthflyApi};

$api = new AuthflyApi('http://localhost:4000');
$session = $api->signIn('alice@example.com', 'a long password'); // ['token' => ..., 'user' => ...]

$oidc = new Authfly('http://localhost:4000', 'http://localhost:8080', 'my-app', 'http://localhost:8000/callback');
[$url, $pending] = $oidc->authorizeUrl();       // redirect; keep $pending in the session
$result = $oidc->callback($_GET, $pending);       // ['user' => claims, 'tokens' => ...]
```

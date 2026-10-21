<?php
// e2e helper: drives the PHP adapter. argv[1]: authorize | callback; JSON config on stdin; JSON result on stdout.
require __DIR__ . '/../packages/adapters/php/src/Authkit.php';
use Authkit\{Authkit, AuthkitApi};

$cfg = json_decode(stream_get_contents(STDIN), true);
$oidc = new Authkit($cfg['authkit'], $cfg['stalwart'], $cfg['client'], $cfg['redirect']);
if ($argv[1] === 'authorize') {
    [$url, $pending] = $oidc->authorizeUrl();
    echo json_encode(['url' => $url, 'pending' => $pending]);
} else {
    $res = $oidc->callback($cfg['params'], $cfg['pending']);
    $api = new AuthkitApi($cfg['authkit']);
    $tok = $api->signIn($cfg['identifier'], $cfg['password'])['token'];
    echo json_encode(['user' => $res['user'], 'me' => $api->me($tok)['user']]);
}

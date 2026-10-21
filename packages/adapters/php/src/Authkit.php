<?php
// Authkit adapter for PHP apps (Symfony, Nette, plain PHP): no dependencies beyond ext-json and allow_url_fopen.
// - AuthkitApi: client of the Authkit JSON API (server to server).
// - Authkit: OpenID Connect relying party through the Authkit hosted sign-in (authorization code + PKCE, tokens from
//   Stalwart). The ID token comes straight from Stalwart's token endpoint over the back channel, so its claims are checked
//   (iss, aud, nonce, exp) without a signature check, as OpenID Connect Core 3.1.3.7 allows for that case.
declare(strict_types=1);

namespace Authkit;

final class AuthkitException extends \RuntimeException
{
    public function __construct(public readonly int $status, public readonly string $error, string $message)
    {
        parent::__construct($message !== '' ? $message : $error);
    }
}

function request(string $method, string $url, ?string $body = null, array $headers = []): array
{
    $ctx = stream_context_create(['http' => [
        'method' => $method, 'header' => implode("\r\n", $headers), 'content' => $body ?? '',
        'ignore_errors' => true, 'timeout' => 20,
    ]]);
    $raw = file_get_contents($url, false, $ctx);
    $status = 0;
    foreach ($http_response_header ?? [] as $h) {
        if (preg_match('#^HTTP/\S+ (\d{3})#', $h, $m)) {
            $status = (int) $m[1];
        }
    }
    $out = json_decode($raw === false ? '{}' : ($raw ?: '{}'), true) ?? [];
    if ($status >= 400 || $status === 0) {
        throw new AuthkitException($status, (string) ($out['error'] ?? $status), (string) ($out['message'] ?? $out['error_description'] ?? ''));
    }
    return $out;
}

function b64url(string $b): string
{
    return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
}

final class AuthkitApi
{
    public function __construct(private string $baseUrl, private string $apiKey = '')
    {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    private function call(string $method, string $path, ?array $body = null, string $token = ''): array
    {
        $h = ['Content-Type: application/json'];
        if ($this->apiKey !== '') $h[] = 'X-Authkit-Key: ' . $this->apiKey;
        if ($token !== '') $h[] = 'Authorization: Bearer ' . $token;
        return request($method, $this->baseUrl . '/api/v1' . $path, $body === null ? null : json_encode($body), $h);
    }

    public function signUp(string $name, string $username, string $password): array { return $this->call('POST', '/sign-up', compact('name', 'username', 'password')); }
    public function signIn(string $identifier, string $password): array { return $this->call('POST', '/sign-in', compact('identifier', 'password')); }
    public function requestMagicLink(string $identifier): array { return $this->call('POST', '/magic-link', compact('identifier')); }
    public function verifyMagicLink(string $token): array { return $this->call('POST', '/magic-link/verify', compact('token')); }
    public function verifyEmail(string $token): array { return $this->call('POST', '/verify-email', compact('token')); }
    public function forgot(string $email): array { return $this->call('POST', '/forgot', compact('email')); }
    public function reset(string $token, string $password): array { return $this->call('POST', '/reset', compact('token', 'password')); }
    public function me(string $token): array { return $this->call('GET', '/me', null, $token); }
    public function config(): array { return $this->call('GET', '/config'); }
}

final class Authkit
{
    private ?array $disc = null;

    public function __construct(private string $authkitUrl, private string $stalwartUrl, private string $clientId, private string $redirectUri, private string $scope = 'openid email profile')
    {
        $this->authkitUrl = rtrim($authkitUrl, '/');
        $this->stalwartUrl = rtrim($stalwartUrl, '/');
    }

    public function discovery(): array
    {
        return $this->disc ??= request('GET', $this->stalwartUrl . '/.well-known/openid-configuration');
    }

    /** @return array{0: string, 1: array{state: string, nonce: string, verifier: string}} the URL and the values to keep until the callback */
    public function authorizeUrl(): array
    {
        $p = ['state' => b64url(random_bytes(16)), 'nonce' => b64url(random_bytes(16)), 'verifier' => b64url(random_bytes(32))];
        $q = http_build_query(['response_type' => 'code', 'client_id' => $this->clientId, 'redirect_uri' => $this->redirectUri, 'scope' => $this->scope,
            'state' => $p['state'], 'nonce' => $p['nonce'], 'code_challenge_method' => 'S256', 'code_challenge' => b64url(hash('sha256', $p['verifier'], true))], '', '&', PHP_QUERY_RFC3986);
        return [$this->authkitUrl . '/oauth/authorize?' . $q, $p];
    }

    /** @return array{user: array, tokens: array} */
    public function callback(array $params, array $pending): array
    {
        if (!empty($params['error'])) throw new AuthkitException(400, (string) $params['error'], (string) ($params['error_description'] ?? ''));
        if (($params['state'] ?? '') !== $pending['state']) throw new AuthkitException(400, 'invalid_state', 'state mismatch');
        $tokens = request('POST', $this->stalwartUrl . '/auth/token', http_build_query(['grant_type' => 'authorization_code', 'code' => $params['code'] ?? '',
            'redirect_uri' => $this->redirectUri, 'client_id' => $this->clientId, 'code_verifier' => $pending['verifier']]), ['Content-Type: application/x-www-form-urlencoded']);
        $claims = json_decode(base64_decode(strtr(explode('.', $tokens['id_token'])[1], '-_', '+/')), true);
        $aud = $claims['aud'] ?? null;
        if (($claims['iss'] ?? '') !== $this->discovery()['issuer'] || !($aud === $this->clientId || (is_array($aud) && in_array($this->clientId, $aud, true)))
            || ($claims['nonce'] ?? '') !== $pending['nonce'] || ($claims['exp'] ?? 0) < time()) {
            throw new AuthkitException(400, 'invalid_id_token', 'id token claims do not match');
        }
        return ['user' => $claims, 'tokens' => $tokens];
    }
}

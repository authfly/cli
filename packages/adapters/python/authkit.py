"""Authkit adapter for Python apps (Flask, FastAPI, Django): standard library only.

- AuthkitApi: client of the Authkit JSON API (server to server).
- Authkit: OpenID Connect relying party through the Authkit hosted sign-in (authorization code + PKCE, tokens from
  Stalwart). The ID token comes straight from Stalwart's token endpoint over the back channel, so its claims are checked
  (iss, aud, nonce, exp) without a signature check, as OpenID Connect Core 3.1.3.7 allows for that case; use a JOSE
  library with the jwks_uri if you pass ID tokens around.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request


class AuthkitError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message or code)
        self.status, self.code = status, code


def _request(method: str, url: str, body: bytes | None = None, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            return json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as e:
        out = json.loads(e.read() or b"{}")
        raise AuthkitError(e.code, out.get("error", str(e.code)), out.get("message") or out.get("error_description", "")) from None


class AuthkitApi:
    def __init__(self, base_url: str, api_key: str = ""):
        self.base_url, self.api_key = base_url.rstrip("/"), api_key

    def _call(self, method: str, path: str, body: dict | None = None, token: str = "") -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-Authkit-Key"] = self.api_key
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return _request(method, f"{self.base_url}/api/v1{path}", json.dumps(body).encode() if body is not None else None, headers)

    def sign_up(self, name: str, username: str, password: str) -> dict: return self._call("POST", "/sign-up", {"name": name, "username": username, "password": password})
    def sign_in(self, identifier: str, password: str) -> dict: return self._call("POST", "/sign-in", {"identifier": identifier, "password": password})
    def request_magic_link(self, identifier: str) -> dict: return self._call("POST", "/magic-link", {"identifier": identifier})
    def verify_magic_link(self, token: str) -> dict: return self._call("POST", "/magic-link/verify", {"token": token})
    def verify_email(self, token: str) -> dict: return self._call("POST", "/verify-email", {"token": token})
    def forgot(self, email: str) -> dict: return self._call("POST", "/forgot", {"email": email})
    def reset(self, token: str, password: str) -> dict: return self._call("POST", "/reset", {"token": token, "password": password})
    def me(self, token: str) -> dict: return self._call("GET", "/me", token=token)
    def config(self) -> dict: return self._call("GET", "/config")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Authkit:
    def __init__(self, authkit_url: str, stalwart_url: str, client_id: str, redirect_uri: str, scope: str = "openid email profile"):
        self.authkit_url, self.stalwart_url = authkit_url.rstrip("/"), stalwart_url.rstrip("/")
        self.client_id, self.redirect_uri, self.scope = client_id, redirect_uri, scope
        self._disc: dict | None = None

    def discovery(self) -> dict:
        if self._disc is None:
            self._disc = _request("GET", f"{self.stalwart_url}/.well-known/openid-configuration")
        return self._disc

    def authorize_url(self) -> tuple[str, dict]:
        """The URL to redirect to, and the pending values to keep (signed session or cookie) until the callback."""
        pending = {"state": _b64(secrets.token_bytes(16)), "nonce": _b64(secrets.token_bytes(16)), "verifier": _b64(secrets.token_bytes(32))}
        q = urllib.parse.urlencode({"response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri, "scope": self.scope,
                                    "state": pending["state"], "nonce": pending["nonce"], "code_challenge_method": "S256",
                                    "code_challenge": _b64(hashlib.sha256(pending["verifier"].encode()).digest())})
        return f"{self.authkit_url}/oauth/authorize?{q}", pending

    def callback(self, params: dict, pending: dict) -> dict:
        """Exchange the code at Stalwart and return {"user": claims, "tokens": ...}."""
        if params.get("error"):
            raise AuthkitError(400, params["error"], params.get("error_description", ""))
        if params.get("state") != pending["state"]:
            raise AuthkitError(400, "invalid_state", "state mismatch")
        body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": params.get("code", ""), "redirect_uri": self.redirect_uri,
                                       "client_id": self.client_id, "code_verifier": pending["verifier"]}).encode()
        tokens = _request("POST", self.discovery()["token_endpoint"], body, {"Content-Type": "application/x-www-form-urlencoded"})
        claims = json.loads(base64.urlsafe_b64decode(tokens["id_token"].split(".")[1] + "=="))
        aud = claims.get("aud")
        if claims.get("iss") != self.discovery()["issuer"] or (aud != self.client_id and self.client_id not in (aud or [])) \
                or claims.get("nonce") != pending["nonce"] or claims.get("exp", 0) < time.time():
            raise AuthkitError(400, "invalid_id_token", "id token claims do not match")
        return {"user": claims, "tokens": tokens}

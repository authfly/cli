#!/usr/bin/env python3
"""Audit the Stalwart management surface live and write docs/api-capture/probe.json + docs/stalwart-api.md.

Sources: the live schema (GET /api/schema: objects, fields, forms, lists, layouts), the admin's effective permissions
(GET /api/account: one permission per object method), and live probes: every singleton is read with x:<Obj>/get
["singleton"], every object type with x:<Obj>/query + x:<Obj>/get, every HTTP endpoint from the docs is requested.
Secrets in captured responses are redacted. Usage: STALWART_URL=http://localhost:8080 STALWART_ADMIN=user:pass tools/stalwart-audit.py
"""
import base64, json, os, re, sys, urllib.request, urllib.error, gzip, time

URL = os.environ.get("STALWART_URL", "http://localhost:8080").rstrip("/")
ADMIN = os.environ.get("STALWART_ADMIN", "admin:authfly-dev-admin")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "api-capture")
AUTH = "Basic " + base64.b64encode(ADMIN.encode()).decode()
SECRET = re.compile(r"secret|password|privatekey|private_key|token|credential|apikey|api_key|^key$|clientsecret", re.I)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
opener = urllib.request.build_opener(NoRedirect)

def http(method, path, body=None, auth=True, headers=None):
    h = {"Accept": "application/json", **(headers or {})}
    if auth: h["Authorization"] = AUTH
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(URL + path, data=data, method=method, headers=h)
    try:
        with opener.open(req, timeout=15) as r:
            raw, status, hd = r.read(), r.status, {k.title(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        raw, status, hd = e.read(), e.code, {k.title(): v for k, v in e.headers.items()}
    except Exception as e:  # timeouts on streams
        return {"status": 0, "error": str(e)[:200]}
    if hd.get("Content-Encoding") == "gzip":
        raw = gzip.decompress(raw)
    ct = hd.get("Content-Type", "")
    try:
        out = json.loads(raw) if raw and "json" in ct else raw.decode("utf8", "replace")[:300]
    except Exception:
        out = raw[:300].decode("utf8", "replace")
    return {"status": status, "contentType": ct, "location": hd.get("Location"), "body": out}

def redact(v, key=""):
    if isinstance(v, dict): return {k: ("[redacted]" if SECRET.search(k) and not isinstance(x, bool) else redact(x, k)) for k, x in v.items()}
    if isinstance(v, list): return [redact(x, key) for x in v[:3]] + (["…"] if len(v) > 3 else [])
    if isinstance(v, str) and len(v) > 400: return v[:400] + "…"
    return v

def jmap(calls):
    r = http("POST", "/jmap", {"using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"], "methodCalls": calls})
    return r["body"]["methodResponses"] if isinstance(r.get("body"), dict) and "methodResponses" in r["body"] else [["error", r, "x"]]

def main():
    os.makedirs(OUT, exist_ok=True)
    schema = http("GET", "/api/schema/" + http("GET", "/api/schema")["location"].rsplit("/", 1)[-1])["body"]
    json.dump(schema, open(os.path.join(OUT, "schema.json"), "w"))
    perms = set(http("GET", "/api/account")["body"]["permissions"])
    # navigation groups from the web admin layout
    group = {}
    def walk(items, path):
        for it in items:
            node = it.get("container") or it.get("link") or it
            name = node.get("name", "")
            if node.get("viewName"): group.setdefault(node["viewName"].split("/")[0], " / ".join(path + [name]))
            walk(node.get("items", []), path + [name])
    for sec in schema["layouts"]: walk(sec.get("items", []), [sec["name"]])
    objects = {}
    for name, o in sorted(schema["objects"].items()):
        if o["type"] == "view":
            continue
        pre = o.get("permissionPrefix", "")
        ops = [op for op in ["Get", "Query", "Create", "Update", "Destroy"] if pre + op in perms]
        entry = {"name": name, "kind": o["type"], "description": o.get("description", ""), "permissionPrefix": pre, "operations": ops,
                 "group": group.get(name, "Other" if name.startswith("x:") else "JMAP (user data)"),
                 "fields": {k: {"description": f.get("description", ""), "type": f.get("type", {}), "update": f.get("update")}
                            for k, f in schema["fields"].get(name, {}).get("properties", {}).items()} if name in schema["fields"] else {},
                 "variants": schema["schemas"].get(name, {}).get("variants")}
        if not name.startswith("x:"):
            entry["probe"] = {"note": "standard JMAP object of user data (RFC 8620/8621 and drafts), reached as an account, not probed as admin"}
            objects[name] = entry; continue
        if o["type"] == "singleton":
            res = jmap([[f"{name}/get", {"ids": ["singleton"]}, "g"]])[0]
            entry["probe"] = {"get": {"request": {"ids": ["singleton"]}, "response": redact(res[1]), "ok": res[0] == f"{name}/get"}}
        else:
            res = jmap([[f"{name}/query", {"limit": 3}, "q"], [f"{name}/get", {"#ids": {"resultOf": "q", "name": f"{name}/query", "path": "/ids"}}, "g"]])
            entry["probe"] = {"query": {"request": {"limit": 3}, "response": redact(res[0][1]), "ok": res[0][0] == f"{name}/query"},
                              "get": {"request": {"#ids": "result of query"}, "response": redact(res[1][1]) if len(res) > 1 else None, "ok": len(res) > 1 and res[1][0] == f"{name}/get"}}
        objects[name] = entry
    # HTTP endpoints (docs: development/api, auth/oauth endpoints, openid)
    eps = [
        ("GET", "/.well-known/openid-configuration", False, None, "OIDC discovery", "docs: auth/openid"),
        ("GET", "/.well-known/oauth-authorization-server", False, None, "OAuth metadata (RFC 8414)", "docs: auth/oauth/endpoints"),
        ("GET", "/auth/jwks.json", False, None, "JSON Web Key Set", "docs: auth/openid"),
        ("POST", "/auth/token", False, b"grant_type=authorization_code&code=invalid", "Token endpoint (code, refresh, device)", "docs: auth/oauth/endpoints"),
        ("GET", "/auth/userinfo", False, None, "UserInfo (bearer)", "docs: auth/openid"),
        ("POST", "/auth/introspect", True, b"token=invalid", "Token introspection (RFC 7662)", "docs: auth/oauth/endpoints"),
        ("POST", "/auth/device", False, b"client_id=probe", "Device authorization (RFC 8628)", "docs: auth/oauth/endpoints"),
        ("POST", "/auth/register", False, {"redirect_uris": ["https://probe.invalid/cb"], "client_name": "probe"}, "Dynamic client registration (RFC 7591)", "docs: auth/oauth/client-registration"),
        ("POST", "/api/auth", False, {"type": "authCode", "accountName": "nobody@invalid", "accountSecret": "x", "clientId": "probe"}, "Credential check, issues an authorization code", "docs: development/api"),
        ("GET", "/api/discover/admin@authfly.test", False, None, "OIDC discovery per address", "docs: development/api"),
        ("GET", "/api/account", True, None, "Effective permissions, edition, locale", "docs: development/api"),
        ("GET", "/api/schema", True, None, "Configuration schema (redirect to hash)", "docs: development/api"),
        ("GET", "/api/token/delivery", True, None, "Short-lived SSE token (delivery)", "docs: development/api"),
        ("GET", "/api/token/tracing", True, None, "SSE token tracing (Enterprise)", "docs: development/api"),
        ("GET", "/api/token/metrics", True, None, "SSE token metrics (Enterprise)", "docs: development/api"),
        ("GET", "/api/live/delivery/authfly.test?timeout=1", True, None, "Live delivery test (SSE)", "docs: development/api"),
        ("GET", "/api/live/tracing", True, None, "Live tracing (Enterprise, SSE)", "docs: development/api"),
        ("GET", "/api/live/metrics", True, None, "Live metrics (Enterprise, SSE)", "docs: development/api"),
        ("GET", "/jmap/session", True, None, "JMAP session (RFC 8620)", "docs: development (JMAP)"),
        ("POST", "/jmap", True, {"using": ["urn:ietf:params:jmap:core"], "methodCalls": [["Core/echo", {"probe": True}, "e"]]}, "JMAP API (mail data and x: management objects)", "docs: development (JMAP)"),
        ("GET", "/admin", False, None, "Web admin (x:Application urlPrefix /admin)", "live: x:Application"),
        ("GET", "/account", False, None, "Self-service web UI (x:Application urlPrefix /account)", "live: x:Application"),
        ("GET", "/", False, None, "Root (x:Http redirectRoot)", "docs: ref/object/http"),
        ("GET", "/api/management", True, None, "Pre-0.16 REST management (removed?)", "older docs"),
        ("GET", "/api/principal", True, None, "Pre-0.16 REST principals (removed?)", "older docs"),
        ("GET", "/healthz/live", False, None, "Health check", "docs: install (Docker healthcheck)"),
        ("GET", "/healthz/ready", False, None, "Readiness check", "docs: install"),
        ("GET", "/metrics/prometheus", False, None, "Prometheus scrape (x:Metrics/CollectorPrometheus)", "schema: x:Metrics"),
        ("GET", "/robots.txt", False, None, "robots", "probe"),
    ]
    endpoints = []
    for m, p, auth, body, desc, src in eps:
        hd = {"Content-Type": "application/x-www-form-urlencoded"} if isinstance(body, bytes) else None
        r = http(m, p, body, auth, hd)
        endpoints.append({"method": m, "path": p.split("?")[0], "auth": "admin basic/bearer" if auth else "anonymous", "description": desc, "source": src,
                          "request": body.decode() if isinstance(body, bytes) else body, "status": r.get("status"), "response": redact(r.get("body")), "location": r.get("location")})
        time.sleep(0.1)
    probe = {"server": URL, "capturedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "edition": http("GET", "/api/account")["body"].get("edition"),
             "permissions": sorted(perms), "objects": objects, "endpoints": endpoints}
    json.dump(probe, open(os.path.join(OUT, "probe.json"), "w"), indent=1)
    print(f"objects {len(objects)}, endpoints {len(endpoints)}, permissions {len(perms)}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Render docs/stalwart-api.md from docs/api-capture/probe.json (tools/stalwart-audit.py) plus the hand-written parts
(docs/api-capture/notes.md: findings and the GDPR map)."""
import json, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
p = json.load(open(os.path.join(ROOT, "docs/api-capture/probe.json")))
notes = open(os.path.join(ROOT, "docs/api-capture/notes.md")).read()

def status(o):
    pr = o.get("probe", {})
    if "note" in pr: return "docs-only"
    calls = [v for v in pr.values() if isinstance(v, dict) and "ok" in v]
    if all(c["ok"] for c in calls): return "live"
    d = json.dumps(calls[0]["response"])
    if "Enterprise" in d: return "live: Enterprise only"
    if "Account not found" in d: return "live: per account"
    if "cannot be queried" in d: return "live: set only"
    if "serverUnavailable" in d: return "live: store not configured"
    return "live: error"

def js(v, n=900):
    s = json.dumps(v, indent=1)
    return s if len(s) <= n else s[:n] + "\n…"

objs = p["objects"]
st = {k: status(v) for k, v in objs.items()}
live = [k for k, s in st.items() if s.startswith("live")]
ok = [k for k, s in st.items() if s == "live"]
eps = p["endpoints"]
L = []
L.append("# Stalwart API audit (v0.16)\n")
L.append(f"Captured live from `stalwartlabs/stalwart:v0.16` ({p['edition']} edition) at {p['capturedAt']} by `tools/stalwart-audit.py`, after `authkit init-stalwart` hardened it (so `/auth/register` is refused and `/admin/` is 404 here; the defaults before hardening are described below); regenerate with `python3 tools/stalwart-audit.py && python3 tools/stalwart-api-doc.py`. Raw captures: `docs/api-capture/probe.json` (requests and responses, secrets redacted) and `docs/api-capture/schema.json` (the server's own configuration schema).\n")
L.append("## Coverage\n")
L.append(f"- HTTP endpoints: **{len(eps)}** requested live ({sum(1 for e in eps if e['status'] and e['status'] < 400)} answered 2xx/3xx, the rest with the documented error or 404).")
L.append(f"- Management object types (`x:*` over JMAP): **{sum(1 for k in objs if k.startswith('x:'))}**, all probed live: **{len(ok)}** answered get/query, **{len(live) - len(ok)}** answered with a documented restriction (Enterprise only, per-account, set only, store not configured).")
L.append(f"- JMAP user-data object types (Email, Mailbox, …): **{sum(1 for k in objs if not k.startswith('x:'))}**, docs-only here (standard JMAP; Authkit uses Email/query and Email/get live in the e2e test).")
L.append(f"- JMAP data objects reachable (from the method permissions): see the JMAP section.")
L.append(f"- Permissions: **{len(p['permissions'])}** (one per object method), from `GET /api/account`.\n")
L.append(notes)
L.append("\n## HTTP endpoints\n")
L.append("| Method | Path | Auth | Live status | Purpose | Source |\n|---|---|---|---|---|---|")
for e in eps:
    L.append(f"| {e['method']} | `{e['path']}` | {e['auth']} | {e['status']} | {e['description']} | {e['source']} |")
L.append("\n### Captured examples\n")
for e in eps:
    if e["status"] in (200, 201) and isinstance(e["response"], (dict, list)):
        L.append(f"`{e['method']} {e['path']}`" + (f" with `{json.dumps(e['request'])[:200]}`" if e["request"] else "") + "\n\n```json\n" + js(e["response"], 600) + "\n```\n")
import re as _re
jm = {}
for perm in p["permissions"]:
    m = _re.match(r"jmap([A-Z][a-zA-Z]+?)(Get|Query|QueryChanges|Changes|Create|Update|Destroy|Copy|Import|Parse|Validate|Upload|Lookup|Echo|GetAvailability)$", perm)
    if m: jm.setdefault(m.group(1), []).append(m.group(2))
L.append("\n## JMAP data methods (user data)\n")
L.append("Standard JMAP (RFC 8620 core, RFC 8621 mail, RFC 9610 contacts, calendars, file node, sieve, quota drafts) at `POST /jmap`, authenticated as the account or with `impersonate` and the target `accountId`. Methods as permissions of the admin; docs-only except Email/query, Email/get, Mailbox/get, Identity/get (used live by Authkit's e2e test and GDPR export).\n")
L.append("| Object | Methods |\n|---|---|")
for k in sorted(jm): L.append(f"| `{k}` | {', '.join(sorted(set(jm[k])))} |")
L.append("\n## Management objects (JMAP `x:*`)\n")
L.append("All calls: `POST /jmap`, admin auth (basic or bearer), `using: [\"urn:ietf:params:jmap:core\", \"urn:stalwart:jmap\"]`. Objects take `x:<Name>/get`, `/query`, `/set` (create, update, destroy) and `/changes`; singletons take `/get` and `/set` with the id `singleton`. Methods listed are the admin's permitted operations.\n")
groups = {}
for k, o in objs.items():
    groups.setdefault(o["group"], []).append(k)
for g in sorted(groups):
    L.append(f"\n### {g}\n")
    L.append("| Object | Kind | Operations | Status | Description |\n|---|---|---|---|---|")
    for k in sorted(groups[g]):
        o = objs[k]
        L.append(f"| `{k}` | {o['kind']} | {', '.join(o['operations']) or '-'} | {st[k]} | {o['description'].replace('|', '/')} |")
L.append("\n## Object details\n")
for k in sorted(objs):
    o = objs[k]
    if not k.startswith("x:"): continue
    L.append(f"\n### `{k}`\n\n{o['description']} Kind: {o['kind']}. Status: {st[k]}. Permissions: `{o['permissionPrefix']}*`.\n")
    if o["fields"]:
        L.append("Fields: " + ", ".join(f"`{f}`" + (" (server set)" if d.get("update") == "serverSet" else "") for f, d in sorted(o["fields"].items())) + ".\n")
    if o.get("variants"):
        L.append("Variants: " + ", ".join(f"`{v['name']}`" + (f" ({v['schemaName']})" if v.get('schemaName') else '') for v in o["variants"]) + ".\n")
    pr = o["probe"]
    first = pr.get("get") if pr.get("get", {}).get("ok") else pr.get("query")
    if first:
        L.append(f"```json\n{js(first['response'], 700)}\n```\n")
open(os.path.join(ROOT, "docs/stalwart-api.md"), "w").write("\n".join(L) + "\n")
print("docs/stalwart-api.md:", len(L), "lines;", len(ok), "ok,", len(live) - len(ok), "restricted")

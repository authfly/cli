# e2e helper: drives the Python adapter. argv[1]: authorize | callback; JSON config on stdin; JSON result on stdout.
import json, sys
sys.path.insert(0, "../packages/adapters/python")
from authkit import Authkit, AuthkitApi

cfg = json.load(sys.stdin)
oidc = Authkit(cfg["authkit"], cfg["stalwart"], cfg["client"], cfg["redirect"])
if sys.argv[1] == "authorize":
    url, pending = oidc.authorize_url()
    print(json.dumps({"url": url, "pending": pending}))
else:
    res = oidc.callback(cfg["params"], cfg["pending"])
    api = AuthkitApi(cfg["authkit"])
    tok = api.sign_in(cfg["identifier"], cfg["password"])["token"]
    print(json.dumps({"user": res["user"], "me": api.me(tok)["user"]}))

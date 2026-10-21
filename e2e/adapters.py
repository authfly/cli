# e2e helper: drives the Python adapter. argv[1]: authorize | callback; JSON config on stdin; JSON result on stdout.
import json, sys
sys.path.insert(0, "../packages/adapters/python")
from authfly import Authfly, AuthflyApi

cfg = json.load(sys.stdin)
oidc = Authfly(cfg["authfly"], cfg["stalwart"], cfg["client"], cfg["redirect"])
if sys.argv[1] == "authorize":
    url, pending = oidc.authorize_url()
    print(json.dumps({"url": url, "pending": pending}))
else:
    res = oidc.callback(cfg["params"], cfg["pending"])
    api = AuthflyApi(cfg["authfly"])
    tok = api.sign_in(cfg["identifier"], cfg["password"])["token"]
    print(json.dumps({"user": res["user"], "me": api.me(tok)["user"]}))

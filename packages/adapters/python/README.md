# authkit (Python)

Standard library only. Copy `authkit.py` into your app, or `pip install ./packages/adapters/python`.

```python
from authkit import Authkit, AuthkitApi

api = AuthkitApi("http://localhost:4000")
session = api.sign_in("alice@example.com", "a long password")  # {"token", "user"}
api.me(session["token"])

oidc = Authkit("http://localhost:4000", "http://localhost:8080", "my-app", "http://localhost:8000/callback")
url, pending = oidc.authorize_url()          # redirect; keep `pending` in the signed session
result = oidc.callback(request.args, pending)  # {"user": claims, "tokens": ...}
```

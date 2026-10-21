# authfly (Python)

Standard library only. Copy `authfly.py` into your app, or `pip install ./packages/adapters/python`.

```python
from authfly import Authfly, AuthflyApi

api = AuthflyApi("http://localhost:4000")
session = api.sign_in("alice@example.com", "a long password")  # {"token", "user"}
api.me(session["token"])

oidc = Authfly("http://localhost:4000", "http://localhost:8080", "my-app", "http://localhost:8000/callback")
url, pending = oidc.authorize_url()          # redirect; keep `pending` in the signed session
result = oidc.callback(request.args, pending)  # {"user": claims, "tokens": ...}
```

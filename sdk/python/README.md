# Chain Guard FastAPI connector — prototype

This is step 5 of the connected-application prototype. It observes completed
requests in a **fictional** FastAPI app and sends a small event to the existing
Chain Guard ingestion API. It does not block requests or enforce Chain Guard
decisions in the connected app. It is not published on PyPI.

Install from this repository with Python 3.9+:

```bash
python -m pip install ./sdk/python
```

Register a fictional application in `/#integrations` first. Registration is
available only when the Chain Guard owner has configured `CHAIN_GUARD_ADMIN_KEY`.
Keep its returned connection key and a separate random identity secret of at
least 32 characters in the **connected application's private environment**.
Never put them in frontend code or commit them to Git.

```python
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from chainguard_sdk import ChainGuardMiddleware

app = FastAPI()
app.add_middleware(
    ChainGuardMiddleware,
    server_url=os.environ["CHAIN_GUARD_URL"],
    app_id=os.environ["CHAIN_GUARD_APP_ID"],
    app_key=os.environ["CHAIN_GUARD_APP_KEY"],
    identity_secret=os.environ["CHAIN_GUARD_IDENTITY_SECRET"],
    login_paths=("/login",),
    user_list_paths=("/students",),
    record_pattern=r"/students/(?P<record_id>\d+)",  # fictional numeric IDs only
)

@app.post("/login")
async def login(request: Request):
    request.state.chain_guard_account_id = "fictional-student-42"
    return JSONResponse({"message": "Demo login denied"}, status_code=401)
```

The host login handler must set `chain_guard_account_id` to a **fictional,
non-sensitive stable ID** if you want credential-stuffing correlation. The
connector HMACs it before transmission. Without it, failed logins are still
observed but the multi-account stuffing rule cannot trigger. Never use real
emails or account numbers in this prototype. `record_pattern` is opt-in for
fictional numeric IDs; otherwise those paths are reported only as generic API
requests. The connector never transmits bodies, full URLs, raw IP addresses,
raw authorization tokens, or user-agent strings. It hashes the direct client
address and bearer token with the local identity secret, and sends only a broad
device class. Do not trust proxy-forwarded IP headers for identity.

Delivery is best-effort with a short timeout. If Chain Guard is unavailable,
the connected app still returns its normal response; the event may be lost.
This connector is not production telemetry, authentication, or enforcement.

Run connector tests from this directory:

```bash
python -m unittest discover -s tests -v
```

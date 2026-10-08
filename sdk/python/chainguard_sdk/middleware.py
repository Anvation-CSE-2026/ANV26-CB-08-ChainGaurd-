"""Best-effort ASGI observation; never forwards request bodies or raw identities."""

import asyncio
import hashlib
import hmac
import json
import re
import urllib.request
from urllib.parse import urlsplit


def fingerprint_identifier(value, secret):
    """Return an application-scoped HMAC, not a reversible or plain SHA hash."""
    if not isinstance(value, str) or not value:
        raise ValueError("A non-empty identifier is required")
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


class ChainGuardMiddleware:
    """Send completed HTTP request metadata to the Chain Guard demo API.

    Set ``scope['state']['chain_guard_account_id']`` in a login handler to
    supply a *fictional* account identifier. The middleware HMACs it before
    sending. Never put a password, email, or raw token in this state key.
    """

    def __init__(
        self, app, *, server_url, app_id, app_key, identity_secret,
        login_paths=("/login",), user_list_paths=(), product_list_paths=(),
        record_pattern=None, timeout=0.75,
    ):
        if len(identity_secret) < 32:
            raise ValueError("identity_secret must be at least 32 characters")
        if not app_id or not app_key:
            raise ValueError("A registered app ID and connection key are required")
        parsed = urlsplit(server_url)
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")
        ):
            raise ValueError("Chain Guard requires HTTPS except for localhost")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("Use a plain Chain Guard server URL")
        self.app = app
        self.endpoint = server_url.rstrip("/") + "/api/v1/events"
        self.app_id = app_id
        self.app_key = app_key
        self.secret = identity_secret
        self.login_paths = frozenset(login_paths)
        self.user_list_paths = frozenset(user_list_paths)
        self.product_list_paths = frozenset(product_list_paths)
        self.record_pattern = re.compile(record_pattern) if record_pattern else None
        self.timeout = float(timeout)
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        status = None

        async def observed_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        # Do not interfere with the application's response or exception path.
        await self.app(scope, receive, observed_send)
        if status is None:
            return
        try:
            event = self._event(scope, status)
            if event:
                await asyncio.to_thread(self._post_event, event)
        except Exception:
            # Observation is explicitly best effort, never an app outage.
            pass

    def _event(self, scope, status):
        method = scope.get("method", "GET").upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            return None
        path = scope.get("path", "")
        if path == "/owner" or path.startswith("/api/owner/"):
            return None
        headers = dict(scope.get("headers", ()))
        user_agent = headers.get(b"user-agent", b"").decode("utf-8", "ignore").lower()
        if any(marker in user_agent for marker in ("bot", "curl", "python-requests", "httpx")):
            device = "automated-client"
        elif "mobile" in user_agent:
            device = "mobile"
        elif user_agent:
            device = "desktop-browser"
        else:
            device = "unknown"
        client = scope.get("client")
        # Only the HMAC leaves this application; proxy headers are not trusted.
        client_ip = client[0] if client and client[0] else "unknown-client"
        event = {
            "activity": "api-request", "method": method, "statusCode": status,
            "clientId": fingerprint_identifier("client:" + client_ip, self.secret)[:32],
            "device": device,
        }
        if path in self.login_paths and method == "POST" and (200 <= status < 300 or status in (401, 403)):
            event["activity"] = "login"
            event["outcome"] = "login-approved" if status < 300 else "login-failed"
            account_id = scope.get("state", {}).get("chain_guard_account_id")
            if isinstance(account_id, str) and account_id:
                event["accountFingerprint"] = fingerprint_identifier("account:" + account_id, self.secret)
        elif path in self.user_list_paths:
            event["activity"] = "user-list"
        elif path in self.product_list_paths:
            event["activity"] = "product-list"
        elif self.record_pattern:
            match = self.record_pattern.fullmatch(path)
            if match:
                record_id = match.groupdict().get("record_id")
                # Explicit opt-in; only fictional numeric record IDs are safe here.
                if record_id and re.fullmatch(r"\d{1,12}", record_id):
                    event["activity"] = "user-record"
                    event["recordId"] = record_id
        authorization = headers.get(b"authorization", b"")
        if authorization.lower().startswith(b"bearer ") and len(authorization) > 7:
            token = authorization[7:].decode("utf-8", "ignore")
            event["sessionFingerprint"] = fingerprint_identifier("token:" + token, self.secret)
        return event

    def _post_event(self, event):
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(event, separators=(",", ":")).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Chain-Guard-App-Id": self.app_id,
                "X-Chain-Guard-App-Key": self.app_key,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            response.read(512)

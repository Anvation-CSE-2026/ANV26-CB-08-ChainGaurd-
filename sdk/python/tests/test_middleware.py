import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from chainguard_sdk import ChainGuardMiddleware


SECRET = "fictional-identity-secret-for-tests-only"


async def call(middleware, path, status=200, method="GET", headers=(), account_id=None):
    sent = []

    async def app(scope, _receive, send):
        if account_id:
            scope.setdefault("state", {})["chain_guard_account_id"] = account_id
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware.app = app
    scope = {
        "type": "http", "method": method, "path": path,
        "client": ("203.0.113.12", 4567), "headers": list(headers),
    }

    async def send(message):
        sent.append(message)

    await middleware(scope, None, send)
    return sent


class ConnectorTests(unittest.TestCase):
    def connector(self):
        connector = ChainGuardMiddleware(
            None, server_url="http://localhost:3000", app_id="student-portal",
            app_key="cg_demo_test", identity_secret=SECRET,
            login_paths=("/login",), user_list_paths=("/students",),
            product_list_paths=("/courses",),
            record_pattern=r"/students/(?P<record_id>\d+)",
        )
        connector.events = []
        connector._post_event = connector.events.append
        return connector

    def test_failed_login_pseudonymizes_identity_and_preserves_response(self):
        connector = self.connector()
        sent = asyncio.run(call(
            connector, "/login", 401, "POST",
            [(b"user-agent", b"curl/8"), (b"authorization", b"Bearer fictional-token")],
            account_id="fake-student-42",
        ))
        self.assertEqual(sent[0]["status"], 401)
        event = connector.events[0]
        self.assertEqual((event["activity"], event["outcome"]), ("login", "login-failed"))
        self.assertEqual(event["device"], "automated-client")
        self.assertEqual(len(event["clientId"]), 32)
        self.assertEqual(len(event["accountFingerprint"]), 64)
        self.assertEqual(len(event["sessionFingerprint"]), 64)
        encoded = json.dumps(event)
        for forbidden in ("203.0.113.12", "fake-student-42", "fictional-token", "curl/8"):
            self.assertNotIn(forbidden, encoded)

    def test_explicit_fictional_route_mapping(self):
        connector = self.connector()
        asyncio.run(call(connector, "/students/1234"))
        self.assertEqual(connector.events[0]["activity"], "user-record")
        self.assertEqual(connector.events[0]["recordId"], "1234")
        asyncio.run(call(connector, "/students/private-id"))
        self.assertEqual(connector.events[1]["activity"], "api-request")
        self.assertNotIn("recordId", connector.events[1])

    def test_delivery_failure_does_not_change_host_response(self):
        connector = self.connector()

        def fail(_event):
            raise OSError("Chain Guard unavailable")

        connector._post_event = fail
        sent = asyncio.run(call(connector, "/courses", 200))
        self.assertEqual(sent[0]["status"], 200)
        self.assertEqual(sent[1]["body"], b"ok")

    def test_remote_http_is_rejected(self):
        with self.assertRaises(ValueError):
            ChainGuardMiddleware(
                None, server_url="http://public.example", app_id="demo", app_key="key",
                identity_secret=SECRET,
            )

    def test_http_delivery_uses_authenticated_event_endpoint(self):
        captured = []

        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                captured.append((self.path, dict(self.headers), json.loads(body)))
                self.send_response(202)
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            connector = ChainGuardMiddleware(
                None, server_url=f"http://127.0.0.1:{server.server_port}",
                app_id="student-portal", app_key="cg_demo_test",
                identity_secret=SECRET, user_list_paths=("/students",),
            )
            asyncio.run(call(connector, "/students"))
            self.assertEqual(len(captured), 1)
            path, headers, event = captured[0]
            self.assertEqual(path, "/api/v1/events")
            self.assertEqual(headers["X-Chain-Guard-App-Id"], "student-portal")
            self.assertEqual(headers["X-Chain-Guard-App-Key"], "cg_demo_test")
            self.assertEqual(event["activity"], "user-list")
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == "__main__":
    unittest.main()

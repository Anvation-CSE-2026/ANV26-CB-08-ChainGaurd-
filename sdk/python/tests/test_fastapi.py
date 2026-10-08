import unittest

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient
except ImportError:
    FastAPI = None

from chainguard_sdk import ChainGuardMiddleware


@unittest.skipIf(FastAPI is None, "FastAPI and httpx are optional test dependencies")
class FastApiCompatibilityTests(unittest.TestCase):
    def test_login_handler_and_middleware_work_together(self):
        events = []
        original_post = ChainGuardMiddleware._post_event
        ChainGuardMiddleware._post_event = lambda _self, event: events.append(event)
        try:
            app = FastAPI()
            app.add_middleware(
                ChainGuardMiddleware,
                server_url="http://localhost:3000", app_id="student-portal",
                app_key="cg_demo_test",
                identity_secret="fictional-identity-secret-for-tests-only",
                login_paths=("/login",),
            )

            @app.post("/login")
            async def login(request: Request):
                request.state.chain_guard_account_id = "fictional-student-42"
                return JSONResponse({"message": "Denied"}, status_code=401)

            with TestClient(app) as client:
                response = client.post("/login", json={"password": "never-send-this"})
            self.assertEqual(response.status_code, 401)
            self.assertEqual(events[0]["activity"], "login")
            self.assertEqual(events[0]["outcome"], "login-failed")
            self.assertNotIn("never-send-this", str(events[0]))
        finally:
            ChainGuardMiddleware._post_event = original_post

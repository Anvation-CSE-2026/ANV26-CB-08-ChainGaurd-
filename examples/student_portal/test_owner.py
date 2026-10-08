import unittest
from fastapi.testclient import TestClient
from examples.student_portal.app import create_app
from chainguard_sdk import ChainGuardMiddleware
from unittest.mock import patch


class OwnerLabTests(unittest.TestCase):
    def test_student_page_and_access(self):
        with TestClient(create_app({"PORTAL_OWNER_KEY": "test-private-owner-secret"})) as client:
            self.assertNotIn('id="test-scenarios"', client.get("/").text)
            self.assertIn('href="/owner"', client.get("/").text)
            self.assertIn('Open backend dashboard', client.get("/").text)
            self.assertIn("Chain Guard security gateway", client.get("/owner").text)
            path = "/api/owner/simulations"
            self.assertEqual(client.post(path, json={"scenario": "token"}).status_code, 403)
            student = client.post("/api/login", json={"username": "student1001", "password": "PortalPass!123"})
            self.assertEqual(student.status_code, 200)
            self.assertEqual(client.post(path, json={"scenario": "token"}, headers={"X-Portal-Owner-Key": student.json()["token"]}).status_code, 403)
            headers = {"X-Portal-Owner-Key": "test-private-owner-secret"}
            response = client.post(path, json={"scenario": "combined"}, headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["requestsSent"], 92)
            self.assertFalse(response.json()["connectorConfigured"])
            self.assertEqual(client.post(path, json={"scenario": "invalid"}, headers=headers).status_code, 400)

    def test_disabled_without_key(self):
        with TestClient(create_app({})) as client:
            self.assertEqual(client.post("/api/owner/simulations", json={"scenario": "bot"}).status_code, 503)

    def test_live_processing_details_are_private(self):
        config = {"PORTAL_OWNER_KEY": "private-owner", "CHAIN_GUARD_URL": "http://localhost:3100",
                  "CHAIN_GUARD_APP_ID": "demo-app", "CHAIN_GUARD_APP_KEY": "private-app-key",
                  "CHAIN_GUARD_IDENTITY_SECRET": "a" * 32}
        scoring = {"accepted": True, "risk": {"score": 20, "level": "low", "factors": [{"type": "credential-stuffing", "points": 20, "reason": "Repeated failures"}]},
                   "detections": [{"type": "credential-stuffing", "severity": "high"}]}
        with patch.object(ChainGuardMiddleware, "_post_event", return_value=scoring):
            with TestClient(create_app(config)) as client:
                self.assertEqual(client.get("/api/owner/activity").status_code, 403)
                client.post("/api/login", json={"username": "student1001", "password": "wrong"})
                response = client.get("/api/owner/activity", headers={"X-Portal-Owner-Key": "private-owner"})
                event = response.json()["events"][0]
                self.assertTrue(event["delivered"])
                self.assertEqual(event["risk"]["score"], 20)
                self.assertEqual(len(response.json()["events"]), 1)
                self.assertNotIn("private-app-key", response.text)
                self.assertNotIn("student1001", response.text)

    def test_gateway_stops_handler_and_fails_closed(self):
        config = {"PORTAL_OWNER_KEY": "private-owner", "CHAIN_GUARD_URL": "http://localhost:3100",
                  "CHAIN_GUARD_APP_ID": "demo-app", "CHAIN_GUARD_APP_KEY": "private-app-key",
                  "CHAIN_GUARD_IDENTITY_SECRET": "a" * 32, "CHAIN_GUARD_GATEWAY_ENABLED": "true"}
        decision = {"accepted": True, "allowed": False, "risk": {"score": 85, "level": "critical"},
                    "decision": {"action": "block", "status": 403, "reason": "Critical risk", "retryAfterSeconds": 120}}
        with patch.object(ChainGuardMiddleware, "_post_json", return_value=decision):
            with TestClient(create_app(config)) as client:
                response = client.get("/api/courses")
                self.assertEqual(response.status_code, 403)
                self.assertNotIn("courses", response.json())
                self.assertEqual(response.headers["retry-after"], "120")
                self.assertEqual(client.get("/owner").status_code, 200)
        with patch.object(ChainGuardMiddleware, "_post_json", side_effect=ConnectionError()):
            with TestClient(create_app(config)) as client:
                self.assertEqual(client.get("/api/courses").status_code, 503)
                self.assertEqual(client.get("/api/status").status_code, 200)

    def test_gateway_allows_actual_handler(self):
        config = {"CHAIN_GUARD_URL": "http://localhost:3100", "CHAIN_GUARD_APP_ID": "demo-app",
                  "CHAIN_GUARD_APP_KEY": "private-app-key", "CHAIN_GUARD_IDENTITY_SECRET": "a" * 32,
                  "CHAIN_GUARD_GATEWAY_ENABLED": "true"}
        decision = {"accepted": True, "allowed": True, "risk": {"score": 0, "level": "low"},
                    "decision": {"action": "allow", "status": None, "reason": "Low risk"}}
        with patch.object(ChainGuardMiddleware, "_post_json", return_value=decision):
            with TestClient(create_app(config)) as client:
                self.assertEqual(len(client.get("/api/courses").json()["courses"]), 3)

    def test_verification_forwards_pseudonymous_identity(self):
        config = {"CHAIN_GUARD_URL": "http://localhost:3100", "CHAIN_GUARD_APP_ID": "demo-app",
                  "CHAIN_GUARD_APP_KEY": "private-app-key", "CHAIN_GUARD_IDENTITY_SECRET": "a" * 32,
                  "CHAIN_GUARD_GATEWAY_ENABLED": "true"}
        with patch.object(ChainGuardMiddleware, "_post_json", return_value={"ok": True, "token": "verify-demo"}) as post:
            with TestClient(create_app(config)) as client:
                response = client.post("/api/gateway/verify", json={"challengeId": "demo-id", "answer": "8"}, headers={"Authorization": "Bearer secret-student-session"})
                self.assertEqual(response.status_code, 200)
                payload = post.call_args.args[1]
                self.assertIsInstance(payload["event"], dict)
                self.assertEqual(len(payload["event"]["sessionFingerprint"]), 64)
                self.assertNotIn("secret-student-session", str(payload))


if __name__ == "__main__":
    unittest.main()

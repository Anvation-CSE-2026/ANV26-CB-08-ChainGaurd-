import unittest
from fastapi.testclient import TestClient
from examples.student_portal.app import create_app


class OwnerLabTests(unittest.TestCase):
    def test_student_page_and_access(self):
        with TestClient(create_app({"PORTAL_OWNER_KEY": "test-private-owner-secret"})) as client:
            self.assertNotIn('id="test-scenarios"', client.get("/").text)
            self.assertIn('href="/owner"', client.get("/").text)
            self.assertIn('Open backend dashboard', client.get("/").text)
            self.assertIn("Security test lab", client.get("/owner").text)
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


if __name__ == "__main__":
    unittest.main()

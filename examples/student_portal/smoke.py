"""Exercise all five abuse patterns against a configured Chain Guard server."""

import json

from fastapi.testclient import TestClient

from examples.student_portal.app import create_app


app = create_app()
with TestClient(app) as client:
    for number in range(1001, 1006):
        response = client.post(
            "/api/login",
            json={"username": f"student{number}", "password": "wrong-demo-password"},
        )
        assert response.status_code == 401
    login = client.post(
        "/api/login", json={"username": "student1001", "password": "PortalPass!123"}
    )
    assert login.status_code == 200
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    for number in range(1001, 1005):
        record = client.get(f"/api/students/{number}", headers=headers)
        assert record.status_code == 200
        assert record.json()["id"] == str(number)
    for _ in range(20):
        assert client.get("/api/courses").status_code == 200
    for _ in range(12):
        assert client.get("/api/courses", headers={"User-Agent": "curl/8"}).status_code == 200
    # The same fictional bearer token now appears on a different device class.
    mobile = client.get(
        "/api/students",
        headers={**headers, "User-Agent": "Mozilla/5.0 Mobile"},
    )
    assert mobile.status_code == 200
    assert len(mobile.json()["students"]) == 6

print(json.dumps({"portalRequests": 43, "loginFailures": 5, "abuseScenarios": 5}))

"""Exercise the independent portal against a configured Chain Guard test server."""

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
    roster = client.get("/api/students", headers=headers)
    record = client.get("/api/students/1002", headers=headers)
    courses = client.get("/api/courses")
    assert roster.status_code == record.status_code == courses.status_code == 200
    assert len(roster.json()["students"]) == 6
    assert record.json()["id"] == "1002"

print(json.dumps({"portalRequests": 9, "loginFailures": 5, "recordId": "1002"}))

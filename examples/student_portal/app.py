"""Independent fictional FastAPI app used to prove Chain Guard integration."""

import os
import secrets
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from chainguard_sdk import ChainGuardMiddleware


DEMO_PASSWORD = "PortalPass!123"
STUDENTS = {
    str(number): {
        "id": str(number),
        "name": name,
        "program": program,
        "standing": "Good",
    }
    for number, name, program in (
        (1001, "Avery Reed", "Computer Science"),
        (1002, "Jordan Vale", "Mathematics"),
        (1003, "Morgan Lee", "Physics"),
        (1004, "Riley Quinn", "Design"),
        (1005, "Casey Noor", "Biology"),
        (1006, "Taylor Chen", "Engineering"),
    )
}
COURSES = [
    {"code": "DEMO-CS101", "title": "Introduction to Computing"},
    {"code": "DEMO-MA201", "title": "Applied Mathematics"},
    {"code": "DEMO-DS110", "title": "Design Systems"},
]


class LoginRequest(BaseModel):
    username: str
    password: str


def create_app(config=None):
    """Create an isolated portal; config may override environment for tests."""
    config = config if config is not None else os.environ
    app = FastAPI(title="Fictional Student Portal", docs_url=None, redoc_url=None)
    sessions = {}
    keys = (
        "CHAIN_GUARD_URL", "CHAIN_GUARD_APP_ID", "CHAIN_GUARD_APP_KEY",
        "CHAIN_GUARD_IDENTITY_SECRET",
    )
    configured = [bool(config.get(key)) for key in keys]
    if any(configured) and not all(configured):
        raise ValueError("Set all four Chain Guard connector settings together")
    connected = all(configured)

    if connected:
        app.add_middleware(
            ChainGuardMiddleware,
            server_url=config["CHAIN_GUARD_URL"],
            app_id=config["CHAIN_GUARD_APP_ID"],
            app_key=config["CHAIN_GUARD_APP_KEY"],
            identity_secret=config["CHAIN_GUARD_IDENTITY_SECRET"],
            login_paths=("/api/login",),
            user_list_paths=("/api/students",),
            product_list_paths=("/api/courses",),
            record_pattern=r"/api/students/(?P<record_id>\d+)",
        )

    def current_student(authorization):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Sign in with a demo account")
        student_id = sessions.get(authorization[7:])
        if not student_id:
            raise HTTPException(status_code=401, detail="Demo session expired")
        return student_id

    @app.get("/", include_in_schema=False)
    def home():
        return FileResponse(Path(__file__).with_name("index.html"))

    @app.get("/favicon.svg", include_in_schema=False)
    def favicon():
        return FileResponse(Path(__file__).with_name("favicon.svg"), media_type="image/svg+xml")

    @app.get("/api/status")
    def status():
        return {
            "portal": "fictional-student-portal",
            "chainGuardConfigured": connected,
            "dashboardUrl": config["CHAIN_GUARD_URL"].rstrip("/") + "/#integrations" if connected else None,
        }

    @app.post("/api/login")
    def login(credentials: LoginRequest, request: Request):
        # Only fictional IDs are eligible for correlation. Raw usernames and
        # passwords never leave this application in Chain Guard events.
        username = credentials.username.strip().lower()
        student_id = username.removeprefix("student")
        if username == "student" + student_id and student_id in STUDENTS:
            request.state.chain_guard_account_id = student_id
        if student_id not in STUDENTS or username != "student" + student_id or credentials.password != DEMO_PASSWORD:
            raise HTTPException(status_code=401, detail="Invalid demo credentials")
        token = secrets.token_urlsafe(24)
        sessions[token] = student_id
        return {"token": token, "student": STUDENTS[student_id]}

    @app.get("/api/students")
    def students(authorization: str = Header(default="")):
        current_student(authorization)
        return {"students": list(STUDENTS.values())}

    @app.get("/api/students/{record_id}")
    def student_record(record_id: str, authorization: str = Header(default="")):
        current_student(authorization)
        if record_id not in STUDENTS:
            raise HTTPException(status_code=404, detail="Fictional record not found")
        return STUDENTS[record_id]

    @app.get("/api/courses")
    def courses():
        return {"courses": COURSES}

    return app


app = create_app()

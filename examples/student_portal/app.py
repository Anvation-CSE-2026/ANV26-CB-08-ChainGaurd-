"""Independent fictional FastAPI app used to prove Chain Guard integration."""

import os
import secrets
import asyncio
import httpx
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


class SimulationRequest(BaseModel):
    scenario: str


def create_app(config=None):
    """Create an isolated portal; config may override environment for tests."""
    config = config if config is not None else os.environ
    app = FastAPI(title="Fictional Student Portal", docs_url=None, redoc_url=None)
    sessions = {}
    owner_key = config.get("PORTAL_OWNER_KEY", "")
    simulation_lock = asyncio.Lock()
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

    @app.get("/owner", include_in_schema=False)
    def owner_page():
        return FileResponse(Path(__file__).with_name("owner.html"))

    @app.post("/api/owner/simulations")
    async def simulate(payload: SimulationRequest, x_portal_owner_key: str = Header(default="")):
        if not owner_key:
            raise HTTPException(503, "Owner tests are disabled. Configure PORTAL_OWNER_KEY on the portal server.")
        if not secrets.compare_digest(x_portal_owner_key.encode(), owner_key.encode()):
            raise HTTPException(403, "A valid portal owner key is required.")
        kinds = ("stuffing", "enumeration", "scraping", "token", "bot")
        if payload.scenario not in (*kinds, "combined"):
            raise HTTPException(400, "Unknown fictional scenario.")
        if simulation_lock.locked():
            raise HTTPException(409, "A test is already running. Try again when it finishes.")
        async with simulation_lock:
            # In-process HTTP uses the actual app routes and connector. No user-supplied target.
            transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 46000))
            async with httpx.AsyncClient(transport=transport, base_url="http://portal.test", headers={"User-Agent": "Northstar-Owner-Test"}) as client:
                count = 0
                demo_token = None

                async def send(method, path, expected=200, **kwargs):
                    nonlocal count
                    response = await client.request(method, path, **kwargs)
                    count += 1
                    if response.status_code != expected:
                        raise HTTPException(500, "The fictional test could not finish.")
                    return response

                for kind in kinds if payload.scenario == "combined" else (payload.scenario,):
                    if kind == "stuffing":
                        for number in range(1001, 1006):
                            await send("POST", "/api/login", 401, json={"username": f"student{number}", "password": "wrong-demo-password"})
                    elif kind in ("enumeration", "token"):
                        if demo_token is None:
                            response = await send("POST", "/api/login", json={"username": "student1001", "password": DEMO_PASSWORD})
                            demo_token = response.json()["token"]
                        paths = [f"/api/students/{number}" for number in range(1001, 1005)] if kind == "enumeration" else ["/api/students"] * 50
                        for path in paths:
                            await send("GET", path, headers={"Authorization": f"Bearer {demo_token}"})
                    else:
                        for _ in range(20 if kind == "scraping" else 12):
                            await send("GET", "/api/courses")
                return {"scenario": payload.scenario, "requestsSent": count, "connectorConfigured": connected,
                        "message": "Test requests completed. Check Chain Guard Integrations for delivered events." if connected else "Test requests completed, but no Chain Guard connector is configured."}

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

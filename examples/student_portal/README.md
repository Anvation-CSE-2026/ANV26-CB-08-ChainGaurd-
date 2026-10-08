# Independent fictional Student Portal — connected-app step 6

This is a separate FastAPI application, not a screen inside Chain Guard. Its
accounts, records, courses, and session tokens are fictional and in memory.
It demonstrates an external application sending events through the step-5
connector into Chain Guard's existing ingestion and detection path.

## Run locally

1. Start Chain Guard on port 3000 with a private `CHAIN_GUARD_ADMIN_KEY` of at
   least 32 characters. In its `/#integrations` screen, register **Student
   Portal** and copy the returned app ID and connection key.
2. Create a Python 3.9+ virtual environment and install this example's
   dependencies from the **`examples/student_portal` directory**:

   ```bash
   python -m pip install -r requirements.txt
   ```

3. Set these four **private server-side** environment variables in the terminal
   that will run the portal:

   ```text
   CHAIN_GUARD_URL=http://127.0.0.1:3000
   CHAIN_GUARD_APP_ID=<registered app ID>
   CHAIN_GUARD_APP_KEY=<connection key shown once>
   CHAIN_GUARD_IDENTITY_SECRET=<different random secret of 32+ characters>
   ```

   Use `https://chain-guard-demo.onrender.com` as the URL only if you have
   explicitly configured private owner registration on that service. Current
   public setup may have registration disabled. Do not put real credentials or
   personal data in this demo.

4. From the repository root, run:

   ```bash
   python -m uvicorn examples.student_portal.app:app --host 127.0.0.1 --port 8000
   ```

   Open `http://127.0.0.1:8000/`. Sign in as `student1001` with
   `PortalPass!123`. You can view the fictional roster and record details.
   The student page has no test lab. Open `/owner` for the owner test lab.
   Set a private `PORTAL_OWNER_KEY` on the portal server to enable tests;
   without it tests are disabled. Student login tokens cannot authorize tests.
   The owner enters that key and selects a scenario. The Python backend sends
   actual requests through the app routes and connector (92 for combined).
   Refresh this app in Chain Guard Integrations to review delivered events.
   This is a demo key gate, not Keycloak authentication. Use HTTPS when hosted.

### One-command local demo

From the repository root, run `npm run demo:connected`. The launcher starts
Chain Guard on `http://127.0.0.1:3100/` and this portal on
`http://127.0.0.1:8000/`, registers the portal automatically with temporary
local-only keys, and prints the owner key for the Chain Guard Integrations
screen. Keep that terminal open. Press Ctrl+C to stop both processes.
The same generated local-only key opens tests at `http://127.0.0.1:8000/owner`.
The top-right server icon opens the owner gateway dashboard. Unlock it to view
the last 100 attempts, pre-request decisions, confirmed delivery, actual scoring
responses, new detections, and signal points. These details require the portal
owner key. History resets on portal restart; it is not database storage.

### Gateway protection

The connected-demo launcher enables `CHAIN_GUARD_GATEWAY_ENABLED=true`.
For a manually started portal, set that variable alongside all four connector
settings to enable enforcement. With it unset, the SDK retains observation mode.

The middleware sends pseudonymous request metadata to the authenticated
`/api/v1/gateway/check` endpoint before login, course, roster, and record handlers
run. Chain Guard evaluates current metadata against observed history. Allowed
requests continue to the handler; rate limited (429), verification-needed (428),
and blocked (403) requests do not. If Chain Guard cannot be contacted, the portal
fails closed with 503. Static pages, status, owner controls, and challenge
verification remain reachable. Denied attempts are recorded by Chain Guard;
allowed request outcomes are reported after the portal responds, so real login
failures are learned without sending password bodies to Chain Guard.

This is an application middleware gateway, not a separate reverse proxy or a
production WAF. High-risk verification uses the existing demo math challenge,
not CAPTCHA or MFA. Owner access remains a private demo key, not Keycloak.
The student page offers the challenge and lets the student retry after solving
it. The active shared demo policy controls bands; critical blocks expire after
two minutes. Owner test runs use isolated benchmark-range client identities.
No real student credentials, third-party targets, or cloud infrastructure are used.

The launcher looks for the Python environment used in this workspace at
`work/fastapi-verify`, then `.venv`. If you installed the dependencies
elsewhere, set `CHAIN_GUARD_PYTHON` to that Python executable's absolute path.
Install `requirements.txt` first. The temporary registration and events are
lost when the local Chain Guard process stops. This launcher does not change
your public Render deployment or its private owner key.

The portal also runs without the four connector settings, but its page clearly
shows **Not connected** and no events are sent. Partial configuration fails at
startup. Sessions and Chain Guard registrations reset when their servers
restart. This example is not a real student system or security control.

## Verify the complete path automatically

Install FastAPI, httpx, and the connector in a Python environment. Set
`CHAIN_GUARD_TEST_PYTHON` to that interpreter's absolute path, then run
`npm test` from the repository root. The optional end-to-end test starts a
temporary Chain Guard server, registers the portal, sends 43 real portal
requests through the connector, and checks all five detectors, a cumulative
100/100 score, the protected per-app view, and public-data isolation. It uses
generated test keys and does not touch your hosted registration.

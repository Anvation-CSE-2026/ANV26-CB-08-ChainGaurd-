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
   The **Security test lab** has separate buttons for failed logins, sequential
   records, fast listings, token overuse, rapid automation, and a combined
   scenario. Refresh this app in Chain Guard Integrations to see its alerts
   and cumulative risk score. The combined browser scenario sends about 90
   requests; run it against the local demo, not a real application.

### One-command local demo

From the repository root, run `npm run demo:connected`. The launcher starts
Chain Guard on `http://127.0.0.1:3100/` and this portal on
`http://127.0.0.1:8000/`, registers the portal automatically with temporary
local-only keys, and prints the owner key for the Chain Guard Integrations
screen. Keep that terminal open. Press Ctrl+C to stop both processes.

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

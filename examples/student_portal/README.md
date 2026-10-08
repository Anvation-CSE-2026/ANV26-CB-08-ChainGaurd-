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
   The **Send five failed demo logins** button creates five failed attempts
   across fictional student IDs. Refresh the Chain Guard Integrations status:
   its Student Portal event count should increase. Protected per-app alerts
   and scores in the dashboard are planned for step 7.

The portal also runs without the four connector settings, but its page clearly
shows **Not connected** and no events are sent. Partial configuration fails at
startup. Sessions and Chain Guard registrations reset when their servers
restart. This example is not a real student system or security control.

## Verify the complete path automatically

Install FastAPI, httpx, and the connector in a Python environment. Set
`CHAIN_GUARD_TEST_PYTHON` to that interpreter's absolute path, then run
`npm test` from the repository root. The optional end-to-end test starts a
temporary Chain Guard server, registers the portal, sends nine real portal
requests through the connector, and checks that the existing engine creates
a credential-stuffing alert and a risk score. It uses generated test keys and
does not touch your hosted registration.

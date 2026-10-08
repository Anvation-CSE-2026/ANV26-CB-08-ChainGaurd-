# Chain Guard demo prototype

An API security console for the Chain Guard project. It contains fictional accounts, protected demo routes, five abuse detectors, cumulative risk scoring, security responses, an interactive test lab, and browser-only demo file storage.

## Connected-application foundation (steps 1–2)

The existing demo request observer and a future connected application now share the same analysis path in `security-pipeline.js`. Events carry an `applicationId`; detection windows, token comparisons, and risk scores are scoped to that application so traffic from separate apps cannot combine into one attack. Existing demo traffic is identified as `chain-guard-demo`.

`event-contract.js` defines the first safe integration event format. It accepts an activity (`login`, `user-list`, `user-record`, `product-list`, or `api-request`), method, response status, pseudonymous client ID, broad device class, and optional SHA-256 account/session fingerprints or numeric record ID. It rejects unknown fields such as passwords, raw tokens, email addresses, and untrusted application IDs. The server will assign the application ID only after authenticating a registered connector. Actual URL paths are not accepted; the server uses generic route labels, avoiding accidental capture of private path data.

The contract and engine reuse are covered by automated tests, including cross-application isolation and external-app enumeration. **This is not yet an event-ingestion API or an installable SDK.** Protected registration is described below; authenticated event ingestion comes next. Do not send real customer data to this demo.

## Protected app registration (step 3)

The sidebar now has an **Integrations** screen. App registration is disabled unless the server owner configures `CHAIN_GUARD_ADMIN_KEY` with a private value of at least 32 characters in the server environment. Set it locally before `npm start`, or in the hosting service's private environment settings for the public deployment. Never put that value in this repository or share it with demo visitors. The public demo login is intentionally not an administrator login.

After configuration, open `/#integrations`, enter the owner key, and register a fictional application such as `Student Portal`. The server generates its ID and a separate random connection key. The connection key is returned only on creation; later app listings contain no keys. The owner key is kept in page memory only, not browser storage. `GET /api/integrations/status` reveals only whether setup is enabled; `GET` and `POST /api/integrations/apps` require the owner key in `X-Chain-Guard-Admin-Key`.

Registrations are **in memory** and reset on server restart or deployment. This is a prototype, not durable credential management. The app key can now send synthetic events through the endpoint below; an automatic connector is the next stage. Do not connect a real application or send production data.

## Authenticated event ingestion (step 4)

`POST /api/v1/events` accepts one synthetic JSON event with headers `X-Chain-Guard-App-Id` and `X-Chain-Guard-App-Key` from a registered app. It rejects invalid keys, unknown fields, malformed or oversized JSON, and more than 120 events per minute per app. A successful request returns HTTP 202 with its event ID, 0–100 risk score, and any new detection types. The Integrations screen's **Refresh status** button shows each app's received-event count and last event time.

Example fictional event body:

```json
{
  "activity": "login",
  "method": "POST",
  "statusCode": 401,
  "outcome": "login-failed",
  "clientId": "synthetic-client-01",
  "device": "desktop-browser",
  "accountFingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

The app ID comes from the authenticated header, never from the JSON body. The event format intentionally excludes passwords, email addresses, raw tokens, raw IPs, and full URL paths. For this demo, only fictional IDs and records should be used. Connected-app events are scoped by app inside the engine and **not exposed in the public threat monitor**; a protected multi-app dashboard is a later stage. This event API observes completed requests; it does not block a connected application's request.

## Start

```powershell
npm start
```

Open `http://localhost:3000` in a browser on the same computer. The server listens on `127.0.0.1` only.

The sidebar opens the overview, demo login, detection lab, threat monitor, risk score, and response history. On a narrow screen, use the menu button to open it. The light/dark switch keeps its choice after refresh.

## Demo file storage

After signing in with a displayed demo account, the page opens **File storage**. You can add, search, download, and remove files. This feature uses the browser's IndexedDB, not the server: files stay in the same browser across refreshes and demo sign-ins, but do not sync to another device or another browser. Each fictional demo account has a separate list within that browser. The login is a shared demo credential, not private authentication; never upload real personal or sensitive files. Clearing browser data removes the stored files. Limits: 10 MB per file and 50 MB per demo account in this browser.

## Public deployment

This project includes a `render.yaml` configuration for a Node web service. Connect a Git repository containing these files to a Render Blueprint to publish the page and its live API together. Render uses `PORT`, and the Blueprint sets `HOST=0.0.0.0` so its proxy can reach the server. The local default remains `127.0.0.1`.

After deployment, push code changes to the linked branch to update the public URL automatically. Editing only the local files does **not** update the hosted copy; the new version must be pushed and deployed. Monitoring data and demo sessions are stored in memory, so they reset when the service restarts and should not be treated as durable records. This prototype contains only fictional data and must not be used for real credentials or sensitive information.

Public visitors appear in the monitor under anonymous `visitor-…` IDs rather than raw IP addresses. The lab's reserved documentation IPs remain visible for its fictional scenarios.

## Interactive lab

Open `http://localhost:3000/#lab` or use **Detection lab** in the sidebar. Six buttons run safe synthetic traffic through the real demo API routes: credential stuffing, enumeration, scraping, token misuse, bot activity, and a combined critical-risk example. The result panel shows requests sent, detections, highest risk, and response actions, with a link to matching alerts.

The lab uses reserved documentation IPs and fictional data. Only one run can execute at a time. The route is `POST /api/lab/run/:scenario`, where `:scenario` is one of `credential-stuffing`, `enumeration`, `scraping`, `token-api-key-misuse`, `bot-automation-abuse`, or `combined-risk`.

## Test credentials

Use `avery@demo.chain-guard.test` (or the other listed demo emails) with `DemoPass!123`.

## Demo endpoints

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/login` | Returns a temporary demo bearer token |
| `GET` | `/api/products` | Returns public fictional products |
| `GET` | `/api/users` | Returns fictional sensitive-style customer records; token required |
| `GET` | `/api/users/:id` | Returns one fictional record; token required |
| `GET` | `/api/health` | Service check |

## Step 2: request observation

Every request now produces an in-memory event with its timestamp, endpoint, method, anonymous visitor ID (or fictional lab IP), broad device class, status, duration, login outcome, and a short one-way fingerprint of any bearer token. Passwords, raw tokens, raw emails, and real visitor IP addresses are never written to the observation log.

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/monitor/summary` | Shows basic counts from the in-memory request log |
| `GET` | `/api/monitor/requests?limit=50` | Shows the most recent observed request events |

## Step 3: abuse detection

The detection engine evaluates the observed request stream and creates an alert for these five patterns:

| Abuse type | Demo rule |
| --- | --- |
| Credential stuffing | 5 failed logins for 3 or more accounts from one IP in 10 minutes |
| Enumeration | 4 sequential user-record IDs successfully accessed from one IP in 2 minutes |
| Scraping | 20 listing requests from one IP in 1 minute |
| Token/API-key misuse | A token fingerprint appears from multiple IPs/devices, or 50 times in 1 minute |
| Bot/automation abuse | 12 requests in 15 seconds with automation-like timing or user agent |

Use `GET /api/monitor/detections?limit=50` to view current detection alerts.

The login page at `http://localhost:3000` now includes a **Live threat monitor** screen. It presents alert counts, severity, plain-language explanations, relevant signals, and refreshes automatically every five seconds.

The monitor has a separate openable view for each abuse type. Open `http://localhost:3000/#abuse-credential-stuffing`, `#abuse-enumeration`, `#abuse-scraping`, `#abuse-token-api-key-misuse`, or `#abuse-bot-automation-abuse` directly, or click the tabs in the monitor. Each view shows its detection rule, alert count, and matching live alerts. The **All alerts** tab remains available.

## Step 4: cumulative risk score

Every demo API request receives a 0–100 risk score based on recent activity from its IP address and, for token misuse, its bearer token fingerprint. Each behavior contributes points at most once per request:

| Signal | Points |
| --- | ---: |
| Credential stuffing: 5 failed logins across 3 accounts in 10 minutes | 20 |
| Enumeration: 4 sequential user IDs in 2 minutes | 25 |
| Scraping: 20 listing requests in 1 minute | 30 |
| Token misuse: same token from multiple IPs/devices | 40 |
| Token misuse: 50 requests in 1 minute, if no source change | 30 |
| Bot behavior: 12 rapid requests in 15 seconds | 15 |

The sum is capped at 100. Scores 0–30 are low, 31–60 medium, 61–80 high, and 81–100 critical. The live monitor shows the latest and highest score, plus the exact point breakdown on each alert card. Use `GET /api/monitor/risks?limit=20` for recent scored requests. Country changes and known-bad-IP reputation are not scored because this prototype does not collect or verify those signals.

## Step 5: security response

The demo API now applies the score before serving each login, product, or user-record request:

| Score | Response |
| --- | --- |
| 0–30 | Allow the request to continue |
| 31–60 | Limit the IP to one allowed request every 2 seconds; extra requests receive HTTP 429 |
| 61–80 | Require a small demo verification challenge; unresolved requests receive HTTP 428 |
| 81–100 | Block the IP for 2 minutes with HTTP 403, revoke any presented demo token, and flag the event for admin review |

The login page includes an **Open protected demo record** button after sign-in. If a high-risk request needs verification, the page shows the challenge and retries after a correct answer. The threat monitor shows response counts and recent interventions. `GET /api/monitor/responses?limit=20` exposes the same response log as JSON. The verification API is `POST /api/verify` with `challengeId` and `answer`; a successful response returns a temporary token to send in `X-Demo-Verification` for 5 minutes. Demo challenges and response state are in memory and reset when the server restarts.

This is intentionally not production authentication or logging. All data, credentials, account numbers, and tokens are fake.

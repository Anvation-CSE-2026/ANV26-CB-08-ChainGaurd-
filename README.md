# Chain Guard demo prototype

An API security console for the Chain Guard project. It contains fictional accounts, protected demo routes, five abuse detectors, cumulative risk scoring, security responses, an interactive test lab, and browser-only demo file storage.

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

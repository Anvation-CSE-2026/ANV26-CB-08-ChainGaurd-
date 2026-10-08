const http = require('node:http');
const { readFile } = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const {
  fingerprint,
  getBearerToken,
  startRequestObservation,
  completeRequestObservation,
  recordEvent,
  getRecentEvents,
  getSummary
} = require('./request-monitor');
const { getDetections, getDetectionSummary } = require('./detection-engine');
const { scoreRisk, getRiskSummary } = require('./risk-engine');
const { analyzeObservedEvent } = require('./security-pipeline');
const { decideResponse, verifyChallenge, getResponseSummary, getResponseEvents } = require('./response-engine');
const { SCENARIOS, runLabScenario, getScenarioResults } = require('./lab-runner');
const { createIntegrationRegistry } = require('./integration-registry');
const { DEMO_APPLICATION_ID, normalizeIntegrationEvent } = require('./event-contract');
const { getActivePolicy, listPolicies, setActivePolicy } = require('./security-policy');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

// Every record below is fictional and exists only for this security demo.
const demoUsers = [
  { id: '1001', name: 'Avery Patel', email: 'avery@demo.chain-guard.test', accountNumber: 'CG-DEMO-1001', balance: 4820.5, role: 'customer' },
  { id: '1002', name: 'Jordan Lee', email: 'jordan@demo.chain-guard.test', accountNumber: 'CG-DEMO-1002', balance: 12950.0, role: 'customer' },
  { id: '1003', name: 'Morgan Silva', email: 'morgan@demo.chain-guard.test', accountNumber: 'CG-DEMO-1003', balance: 760.25, role: 'customer' },
  { id: '1004', name: 'Riley Chen', email: 'riley@demo.chain-guard.test', accountNumber: 'CG-DEMO-1004', balance: 3140.75, role: 'customer' }
];

const credentials = new Map([
  ['avery@demo.chain-guard.test', { password: 'DemoPass!123', userId: '1001' }],
  ['jordan@demo.chain-guard.test', { password: 'DemoPass!123', userId: '1002' }],
  ['morgan@demo.chain-guard.test', { password: 'DemoPass!123', userId: '1003' }],
  ['riley@demo.chain-guard.test', { password: 'DemoPass!123', userId: '1004' }]
]);

const products = [
  { id: 'p-101', name: 'Chain Guard Starter', price: 0, category: 'demo' },
  { id: 'p-102', name: 'Chain Guard Monitor', price: 49, category: 'demo' },
  { id: 'p-103', name: 'Chain Guard Response', price: 99, category: 'demo' }
];

const sessions = new Map();
const integrationRegistry = createIntegrationRegistry(process.env.CHAIN_GUARD_ADMIN_KEY);
let labRunning = false;

function sendJson(response, status, body, extraHeaders = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  response.end(JSON.stringify(body, null, 2));
}

function summarizeIntegrationRisk(events) {
  const summary = getRiskSummary(events);
  return {
    scoredRequests: summary.scoredRequests,
    latest: summary.latest ? { score: summary.latest.score, level: summary.latest.level } : null,
    highestScore: summary.highestScore
  };
}

function readJson(request, maxBytes = 1_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    request.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes <= maxBytes) chunks.push(chunk);
    });
    request.on('end', () => {
      if (bytes > maxBytes) {
        const error = new Error('JSON body is too large.');
        error.status = 413;
        reject(error);
        return;
      }
      try {
        const body = Buffer.concat(chunks).toString('utf8');
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    request.on('error', reject);
  });
}

function getAuthenticatedUser(request) {
  const token = getBearerToken(request);
  const userId = token ? sessions.get(token) : null;
  return userId ? demoUsers.find((user) => user.id === userId) : null;
}

async function servePage(response) {
  const page = await readFile(path.join(__dirname, 'public', 'index.html'));
  response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end(page);
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  const observation = startRequestObservation(request, url);
  response.on('finish', () => {
    const event = completeRequestObservation(observation, response);
    analyzeObservedEvent(event, getRecentEvents(500, DEMO_APPLICATION_ID));
  });

  try {
    if (request.method === 'GET' && url.pathname === '/') return servePage(response);

    if (request.method === 'GET' && url.pathname === '/api/health') {
      return sendJson(response, 200, { status: 'ok', service: 'chain-guard-demo-api' });
    }

    if (request.method === 'GET' && url.pathname === '/api/security-policy') {
      return sendJson(response, 200, { activePolicy: getActivePolicy(), policies: listPolicies(), mode: 'shared-demo' });
    }

    if (request.method === 'PUT' && url.pathname === '/api/security-policy') {
      const { policyId } = await readJson(request);
      try {
        return sendJson(response, 200, { activePolicy: setActivePolicy(policyId), policies: listPolicies(), mode: 'shared-demo' });
      } catch (error) {
        return sendJson(response, 400, { error: error.message });
      }
    }

    if (request.method === 'GET' && url.pathname === '/api/integrations/status') {
      return sendJson(response, 200, { registrationConfigured: integrationRegistry.configured, mode: 'demo' });
    }

    if (url.pathname === '/api/integrations/apps' && ['GET', 'POST'].includes(request.method)) {
      if (!integrationRegistry.configured) return sendJson(response, 503, { error: 'Owner setup is required before app registration.' });
      if (!integrationRegistry.isAuthorized(request.headers['x-chain-guard-admin-key'])) {
        return sendJson(response, 401, { error: 'A valid owner key is required.' });
      }
      if (request.method === 'GET') return sendJson(response, 200, { applications: integrationRegistry.listApplications() });
      const { name } = await readJson(request);
      try {
        return sendJson(response, 201, integrationRegistry.createApplication(name));
      } catch (error) {
        return sendJson(response, error.message.startsWith('Demo limit') ? 409 : 400, { error: error.message });
      }
    }

    if (request.method === 'GET' && url.pathname === '/api/integrations/overview') {
      if (!integrationRegistry.configured) return sendJson(response, 503, { error: 'Owner setup is required.' });
      if (!integrationRegistry.isAuthorized(request.headers['x-chain-guard-admin-key'])) {
        return sendJson(response, 401, { error: 'A valid owner key is required.' });
      }
      const applications = integrationRegistry.listApplications().map((application) => {
        const events = getRecentEvents(500, application.id);
        return {
          ...application,
          risk: summarizeIntegrationRisk(events),
          alerts: getDetectionSummary(application.id)
        };
      });
      return sendJson(response, 200, { applications });
    }

    const integrationActivityMatch = url.pathname.match(/^\/api\/integrations\/apps\/([a-z0-9-]+)\/activity$/);
    if (request.method === 'GET' && integrationActivityMatch) {
      if (!integrationRegistry.configured) return sendJson(response, 503, { error: 'Owner setup is required.' });
      if (!integrationRegistry.isAuthorized(request.headers['x-chain-guard-admin-key'])) {
        return sendJson(response, 401, { error: 'A valid owner key is required.' });
      }
      const application = integrationRegistry.getApplication(integrationActivityMatch[1]);
      if (!application) return sendJson(response, 404, { error: 'Registered application not found.' });
      const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 25, 1), 50);
      const recent = getRecentEvents(500, application.id);
      return sendJson(response, 200, {
        application,
        risk: summarizeIntegrationRisk(recent),
        alerts: getDetectionSummary(application.id),
        events: recent.slice(0, limit).map((event) => ({
          id: event.id,
          timestamp: event.timestamp,
          activity: event.activity,
          statusCode: event.statusCode,
          device: event.device,
          risk: event.risk
        })),
        detections: getDetections(limit, application.id).map((detection) => ({
          id: detection.id,
          timestamp: detection.timestamp,
          type: detection.type,
          severity: detection.severity,
          description: detection.description,
          signals: detection.signals
        }))
      });
    }

    if (request.method === 'POST' && ['/api/v1/gateway/check', '/api/v1/gateway/verify'].includes(url.pathname)) {
      const applicationId = request.headers['x-chain-guard-app-id'];
      if (!integrationRegistry.authenticatesApplication(applicationId, request.headers['x-chain-guard-app-key'])) {
        return sendJson(response, 401, { error: 'A valid application connection is required.' });
      }
      if (String(request.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/json') {
        return sendJson(response, 415, { error: 'Send JSON.' });
      }
      if (!integrationRegistry.allowEvent(applicationId)) return sendJson(response, 429, { error: 'Gateway capacity reached.' });
      const body = await readJson(request, 8192);
      let event;
      try { event = normalizeIntegrationEvent(body.event, applicationId); }
      catch (error) { return sendJson(response, 422, { error: error.message }); }
      // Login outcomes are only known after the portal handles them. Preflight must not invent failures.
      if (event.activity === 'login') event.outcome = 'login-approved';
      if (url.pathname.endsWith('/verify')) {
        const result = verifyChallenge(event, body.challengeId, body.answer);
        return sendJson(response, result.ok ? 200 : 400, result);
      }
      const risk = scoreRisk(event, [event, ...getRecentEvents(500, applicationId)]);
      const decision = decideResponse({ headers: { 'x-demo-verification': body.verificationToken } }, event, risk);
      let detections = [];
      if (decision.action !== 'allow') {
        event.statusCode = decision.status;
        event.security = { ...decision, decisionScore: risk.score, decisionLevel: risk.level, factors: risk.factors, policy: getActivePolicy() };
        recordEvent(event);
        detections = analyzeObservedEvent(event, getRecentEvents(500, applicationId)).detections;
        integrationRegistry.recordEvent(applicationId, event.timestamp);
      }
      return sendJson(response, 200, { accepted: true, allowed: decision.action === 'allow', decision, risk,
        detections: detections.map(({ type, severity }) => ({ type, severity })) });
    }

    if (request.method === 'POST' && url.pathname === '/api/v1/events') {
      const applicationId = request.headers['x-chain-guard-app-id'];
      if (!integrationRegistry.authenticatesApplication(applicationId, request.headers['x-chain-guard-app-key'])) {
        return sendJson(response, 401, { error: 'A valid application connection is required.' });
      }
      if (String(request.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/json') {
        return sendJson(response, 415, { error: 'Send a JSON event.' });
      }
      if (!integrationRegistry.allowEvent(applicationId)) {
        return sendJson(response, 429, { error: 'Demo event limit reached. Try again in a minute.' }, { 'Retry-After': '60' });
      }
      let event;
      try {
        event = normalizeIntegrationEvent(await readJson(request, 8_192), applicationId);
      } catch (error) {
        if (error.status) throw error;
        return sendJson(response, error.message === 'Invalid JSON body' ? 400 : 422, { error: error.message });
      }
      recordEvent(event);
      const { detections } = analyzeObservedEvent(event, getRecentEvents(500, applicationId));
      integrationRegistry.recordEvent(applicationId, event.timestamp);
      return sendJson(response, 202, {
        accepted: true,
        eventId: event.id,
        applicationId,
        risk: event.risk,
        detections: detections.map(({ type, severity }) => ({ type, severity }))
      });
    }

    if (request.method === 'POST' && url.pathname === '/api/verify') {
      const { challengeId, answer } = await readJson(request);
      const verification = verifyChallenge(observation, challengeId, answer);
      observation.outcome = verification.ok ? 'verification-passed' : 'verification-failed';
      return verification.ok
        ? sendJson(response, 200, { message: 'Demo verification passed.', verificationToken: verification.token, expiresInSeconds: verification.expiresInSeconds })
        : sendJson(response, 400, { error: verification.error });
    }

    if (request.method === 'GET' && url.pathname === '/api/lab/results') {
      return sendJson(response, 200, { results: getScenarioResults() });
    }

    const labMatch = url.pathname.match(/^\/api\/lab\/run\/([a-z-]+)$/);
    if (request.method === 'POST' && labMatch) {
      if (!SCENARIOS.has(labMatch[1])) return sendJson(response, 404, { error: 'Unknown lab scenario.' });
      if (labRunning) return sendJson(response, 409, { error: 'A lab scenario is already running.' });
      labRunning = true;
      try {
        return sendJson(response, 200, await runLabScenario(labMatch[1], PORT));
      } finally {
        labRunning = false;
      }
    }

    if (/^\/api\/(login|products|users)(\/|$)/.test(url.pathname)) {
      const provisional = { ...observation, statusCode: 0 };
      const decisionRisk = scoreRisk(provisional, [provisional, ...getRecentEvents(500, DEMO_APPLICATION_ID)]);
      const decision = decideResponse(request, observation, decisionRisk);
      observation.security = {
        action: decision.action,
        reason: decision.reason,
        decisionScore: decisionRisk.score,
        decisionLevel: decisionRisk.level,
        policy: getActivePolicy(),
        factors: decisionRisk.factors,
        blockedUntil: decision.blockedUntil || null,
        evidence: [provisional, ...getRecentEvents(500, DEMO_APPLICATION_ID)]
          .filter((event) => event.ip === observation.ip && /^\/api\/(login|products|users)(\/|$)/.test(event.endpoint))
          .slice(0, 10)
          .reverse()
          .map((event) => ({ timestamp: event.timestamp, method: event.method, endpoint: event.endpoint })),
        alertAdmin: Boolean(decision.alertAdmin)
      };
      if (decision.action !== 'allow') {
        if (decision.action === 'block') {
          const token = getBearerToken(request);
          observation.security.revokedToken = Boolean(token && sessions.delete(token));
        }
        const headers = decision.retryAfterSeconds ? { 'Retry-After': String(decision.retryAfterSeconds) } : {};
        return sendJson(response, decision.status, {
          error: decision.reason,
          action: decision.action,
          riskScore: decisionRisk.score,
          ...(decision.challenge ? { challenge: decision.challenge, verificationUrl: '/api/verify' } : {}),
          ...(decision.retryAfterSeconds ? { retryAfterSeconds: decision.retryAfterSeconds } : {})
        }, headers);
      }
    }

    if (request.method === 'POST' && url.pathname === '/api/login') {
      const { email = '', password = '' } = await readJson(request);
      const account = credentials.get(String(email).toLowerCase());
      observation.accountFingerprint = fingerprint(String(email).toLowerCase());

      if (!account || account.password !== password) {
        observation.outcome = 'login-failed';
        return sendJson(response, 401, { error: 'Invalid demo email or password.' });
      }

      const token = `demo_${randomUUID()}`;
      sessions.set(token, account.userId);
      const user = demoUsers.find((item) => item.id === account.userId);
      observation.outcome = 'login-approved';
      observation.userId = user.id;
      observation.tokenFingerprint = fingerprint(token);
      return sendJson(response, 200, { token, user, message: 'Demo login successful.' });
    }

    if (request.method === 'GET' && url.pathname === '/api/products') {
      return sendJson(response, 200, { products });
    }

    if (request.method === 'GET' && url.pathname === '/api/users') {
      const user = getAuthenticatedUser(request);
      if (!user) return sendJson(response, 401, { error: 'A demo bearer token is required.' });
      observation.userId = user.id;
      observation.outcome = 'authenticated-request';
      return sendJson(response, 200, { users: demoUsers });
    }

    const userMatch = url.pathname.match(/^\/api\/users\/([a-zA-Z0-9-]+)$/);
    if (request.method === 'GET' && userMatch) {
      const user = getAuthenticatedUser(request);
      if (!user) return sendJson(response, 401, { error: 'A demo bearer token is required.' });
      observation.userId = user.id;
      observation.outcome = 'authenticated-request';
      const record = demoUsers.find((item) => item.id === userMatch[1]);
      return record
        ? sendJson(response, 200, { user: record })
        : sendJson(response, 404, { error: 'Demo user not found.' });
    }

    if (request.method === 'GET' && url.pathname === '/api/monitor/summary') {
      return sendJson(response, 200, { summary: getSummary() });
    }

    if (request.method === 'GET' && url.pathname === '/api/monitor/requests') {
      return sendJson(response, 200, { events: getRecentEvents(url.searchParams.get('limit'), DEMO_APPLICATION_ID) });
    }

    if (request.method === 'GET' && url.pathname === '/api/monitor/detections') {
      return sendJson(response, 200, {
        summary: getDetectionSummary(DEMO_APPLICATION_ID),
        riskSummary: getRiskSummary(getRecentEvents(500, DEMO_APPLICATION_ID)),
        detections: getDetections(url.searchParams.get('limit'), DEMO_APPLICATION_ID)
      });
    }

    if (request.method === 'GET' && url.pathname === '/api/monitor/risks') {
      const scored = getRecentEvents(500, DEMO_APPLICATION_ID)
        .filter((event) => /^\/api\/(login|products|users)(\/|$)/.test(event.endpoint))
        .slice(0, Math.min(Math.max(Number(url.searchParams.get('limit')) || 20, 1), 100))
        .map((event) => ({
          timestamp: event.timestamp,
          ip: event.ip,
          method: event.method,
          endpoint: event.endpoint,
          statusCode: event.statusCode,
          outcome: event.outcome,
          action: event.security?.action || 'allow',
          risk: event.risk
        }));
      return sendJson(response, 200, { summary: getRiskSummary(getRecentEvents(500, DEMO_APPLICATION_ID)), requests: scored });
    }

    if (request.method === 'GET' && url.pathname === '/api/monitor/responses') {
      const action = url.searchParams.get('action') || 'interventions';
      if (!['interventions', 'all', 'allow', 'rate-limit', 'step-up', 'block'].includes(action)) {
        return sendJson(response, 400, { error: 'Choose a valid response filter.' });
      }
      const events = getRecentEvents(500, DEMO_APPLICATION_ID);
      return sendJson(response, 200, {
        summary: getResponseSummary(events),
        responses: getResponseEvents(events, url.searchParams.get('limit'), action)
      });
    }

    return sendJson(response, 404, { error: 'Route not found.' });
  } catch (error) {
    const status = error.status || (error.message === 'Invalid JSON body' ? 400 : 500);
    return sendJson(response, status, { error: status < 500 ? error.message : 'Unexpected server error.' });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`Chain Guard demo is running on ${HOST}:${PORT}`);
  });
}

module.exports = { server };

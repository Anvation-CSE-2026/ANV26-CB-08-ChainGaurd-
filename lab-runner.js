const http = require('node:http');
const { setTimeout: pause } = require('node:timers/promises');
const { getRecentEvents, labRequestSecret } = require('./request-monitor');
const { getDetections } = require('./detection-engine');
const { DEMO_APPLICATION_ID } = require('./event-contract');

const SCENARIOS = new Set([
  'legitimate-high-volume',
  'credential-stuffing',
  'enumeration',
  'slow-enumeration',
  'scraping',
  'token-api-key-misuse',
  'bot-automation-abuse',
  'combined-risk'
]);

let runNumber = 0;

function callApi(port, method, route, { ip, token, body, bot = false } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const request = http.request({
      hostname: '127.0.0.1',
      port,
      path: route,
      method,
      headers: {
        'X-Chain-Guard-Lab-Secret': labRequestSecret,
        'X-Demo-Client-IP': ip,
        'User-Agent': bot ? 'ChainGuardLabBot/1.0' : 'ChainGuardLabBrowser/1.0',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {})
      }
    }, (response) => {
      let text = '';
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => {
        try {
          resolve({ status: response.statusCode, data: JSON.parse(text) });
        } catch {
          reject(new Error('The demo API returned an unreadable response.'));
        }
      });
    });
    request.on('error', reject);
    request.setTimeout(10_000, () => request.destroy(new Error('The demo API request timed out.')));
    if (payload) request.write(payload);
    request.end();
  });
}

async function runLabScenario(type, port) {
  if (!SCENARIOS.has(type)) throw new Error('Unknown lab scenario.');
  runNumber += 1;
  const suffix = (runNumber % 250) + 1;
  const ip = `198.51.100.${suffix}`;
  const secondIp = `203.0.113.${suffix}`;
  const beforeEvents = new Set(getRecentEvents(500, DEMO_APPLICATION_ID).map((event) => event.id));
  const beforeAlerts = new Set(getDetections(200, DEMO_APPLICATION_ID).map((alert) => alert.id));
  const requests = [];
  const requestTrace = [];
  const sourceIps = new Set();
  const startedAt = Date.now();
  const send = async (method, route, options = {}) => {
    const sentAt = Date.now();
    sourceIps.add(options.ip || ip);
    const response = await callApi(port, method, route, { ip, ...options });
    requests.push(response.status);
    requestTrace.push({ method, endpoint: route, elapsedMs: sentAt - startedAt, statusCode: response.status });
    return response;
  };
  const login = async () => {
    const response = await send('POST', '/api/login', {
      body: { email: 'avery@demo.chain-guard.test', password: 'DemoPass!123' }
    });
    if (!response.data.token) throw new Error('Demo login failed during the lab run.');
    return response.data.token;
  };

  if (type === 'legitimate-high-volume') {
    // Many independent visitors create high total volume without any one
    // visitor behaving abusively.
    for (let index = 0; index < 50; index += 1) {
      const visitor = ((runNumber * 53 + index) % 250) + 1;
      await send('GET', '/api/products', { ip: `192.0.2.${visitor}` });
    }
  } else if (type === 'credential-stuffing') {
    for (let index = 1; index <= 5; index += 1) {
      await send('POST', '/api/login', {
        body: { email: `lab-target-${index}@demo.chain-guard.test`, password: 'wrong-demo-password' }
      });
    }
  } else if (type === 'enumeration') {
    const token = await login();
    for (let id = 1001; id <= 1004; id += 1) await send('GET', `/api/users/${id}`, { token });
  } else if (type === 'slow-enumeration') {
    const token = await login();
    for (let id = 1001; id <= 1004; id += 1) {
      await pause(1500);
      await send('GET', `/api/users/${id}`, { token });
    }
  } else if (type === 'scraping') {
    for (let index = 0; index < 20; index += 1) await send('GET', '/api/products');
  } else if (type === 'token-api-key-misuse') {
    const token = await login();
    await send('GET', '/api/users/1001', { token });
    await send('GET', '/api/users/1002', { token, ip: secondIp });
  } else if (type === 'bot-automation-abuse') {
    for (let index = 0; index < 12; index += 1) await send('GET', '/api/products', { bot: true });
  } else if (type === 'combined-risk') {
    const token = await login();
    await send('GET', '/api/users/1001', { token, ip: secondIp });
    for (let index = 0; index < 20; index += 1) await send('GET', '/api/products', { token, bot: true });
  }

  const newEvents = getRecentEvents(500, DEMO_APPLICATION_ID).filter((event) => !beforeEvents.has(event.id) && sourceIps.has(event.ip));
  const newAlerts = getDetections(200, DEMO_APPLICATION_ID).filter((alert) => !beforeAlerts.has(alert.id) && sourceIps.has(alert.ip));
  const actions = [...new Set(newEvents.map((event) => event.security?.action).filter((action) => action && action !== 'allow'))];
  return {
    scenario: type,
    demoIp: ip,
    requestsSent: requests.length,
    statusCodes: [...new Set(requests)],
    detectedTypes: [...new Set(newAlerts.map((alert) => alert.type))],
    highestRiskScore: newEvents.reduce((highest, event) => Math.max(highest, event.risk?.score || 0), 0),
    actions,
    alertsCreated: newAlerts.length,
    ...(type === 'slow-enumeration' ? {
      requestTrace,
      rateLimitComparison: {
        label: 'Example static rule: up to 3 requests per second',
        windowMs: 1000,
        limit: 3,
        peakRequests: Math.max(...requestTrace.map((request) => requestTrace.filter((candidate) =>
          candidate.elapsedMs <= request.elapsedMs && candidate.elapsedMs > request.elapsedMs - 1000
        ).length)),
        // A comparison rule for this run, not a configured gateway limit.
        exceeded: requestTrace.some((request) => requestTrace.filter((candidate) =>
          candidate.elapsedMs <= request.elapsedMs && candidate.elapsedMs > request.elapsedMs - 1000
        ).length > 3)
      }
    } : {})
  };
}

module.exports = { SCENARIOS, runLabScenario };

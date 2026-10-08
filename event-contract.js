const { randomUUID, createHash } = require('node:crypto');

const DEMO_APPLICATION_ID = 'chain-guard-demo';
const ACTIVITIES = new Set(['login', 'user-list', 'user-record', 'product-list', 'api-request']);
const DEVICES = new Set(['desktop-browser', 'mobile', 'automated-client', 'unknown']);
const ALLOWED_FIELDS = new Set([
  'activity', 'method', 'statusCode', 'outcome', 'clientId', 'device',
  'accountFingerprint', 'sessionFingerprint', 'recordId'
]);
const salt = randomUUID();

function classifyEndpoint(endpoint) {
  if (endpoint === '/api/login') return { activity: 'login', recordId: null };
  if (endpoint === '/api/users') return { activity: 'user-list', recordId: null };
  if (endpoint === '/api/products') return { activity: 'product-list', recordId: null };
  const recordId = endpoint.match(/^\/api\/users\/(\d+)$/)?.[1];
  return recordId ? { activity: 'user-record', recordId } : { activity: 'api-request', recordId: null };
}

function activityOf(event) {
  return ACTIVITIES.has(event.activity) ? event.activity : classifyEndpoint(event.endpoint || '').activity;
}

function recordIdOf(event) {
  return event.recordId || classifyEndpoint(event.endpoint || '').recordId;
}

function sameApplication(event, candidate) {
  return (event.applicationId || DEMO_APPLICATION_ID) === (candidate.applicationId || DEMO_APPLICATION_ID);
}

function isMonitoredActivity(event) {
  return activityOf(event) !== 'api-request' ||
    (event.applicationId && event.applicationId !== DEMO_APPLICATION_ID);
}

function validateIntegrationEvent(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Event must be a JSON object.');
  if (Object.keys(input).some((field) => !ALLOWED_FIELDS.has(field))) throw new Error('Event contains an unsupported field.');
  if (!ACTIVITIES.has(input.activity)) throw new Error('Invalid activity.');
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(input.method)) throw new Error('Invalid method.');
  if (!Number.isInteger(input.statusCode) || input.statusCode < 100 || input.statusCode > 599) throw new Error('Invalid status code.');
  if (typeof input.clientId !== 'string' || !/^[a-zA-Z0-9_-]{8,64}$/.test(input.clientId)) throw new Error('Invalid pseudonymous client ID.');
  if (!DEVICES.has(input.device)) throw new Error('Invalid device class.');
  if (input.activity === 'login' && !['login-failed', 'login-approved'].includes(input.outcome)) throw new Error('Invalid login outcome.');
  if (input.activity !== 'login' && input.outcome !== undefined && input.outcome !== 'observed') throw new Error('Invalid outcome.');
  for (const field of ['accountFingerprint', 'sessionFingerprint']) {
    if (input[field] !== undefined && (typeof input[field] !== 'string' || !/^[a-f0-9]{64}$/.test(input[field]))) {
      throw new Error(`Invalid ${field}.`);
    }
  }
  if (input.activity === 'user-record') {
    if (typeof input.recordId !== 'string' || !/^\d{1,12}$/.test(input.recordId)) throw new Error('Invalid numeric record ID.');
  } else if (input.recordId !== undefined) {
    throw new Error('Record ID is only valid for user-record activity.');
  }
  if (input.activity === 'login' && input.method !== 'POST') throw new Error('Login activity must use POST.');
  return input;
}

function normalizeIntegrationEvent(input, applicationId) {
  if (typeof applicationId !== 'string' || !/^[a-z0-9-]{3,50}$/.test(applicationId)) throw new Error('Invalid registered application ID.');
  validateIntegrationEvent(input);
  const scopedFingerprint = (value) => value
    ? createHash('sha256').update(`${salt}:${applicationId}:${value}`).digest('hex').slice(0, 12)
    : null;
  const endpoint = {
    login: '/api/login',
    'user-list': '/api/users',
    'user-record': '/api/users/:id',
    'product-list': '/api/products',
    'api-request': '/connected/request'
  }[input.activity];
  return {
    id: randomUUID(),
    applicationId,
    timestamp: new Date().toISOString(),
    activity: input.activity,
    recordId: input.recordId || null,
    endpoint,
    method: input.method,
    statusCode: input.statusCode,
    outcome: input.outcome || 'observed',
    ip: `client-${scopedFingerprint(input.clientId)}`,
    device: input.device,
    accountFingerprint: scopedFingerprint(input.accountFingerprint),
    tokenFingerprint: scopedFingerprint(input.sessionFingerprint),
    userId: null,
    durationMs: 0
  };
}

module.exports = {
  DEMO_APPLICATION_ID,
  classifyEndpoint,
  activityOf,
  recordIdOf,
  sameApplication,
  isMonitoredActivity,
  validateIntegrationEvent,
  normalizeIntegrationEvent
};

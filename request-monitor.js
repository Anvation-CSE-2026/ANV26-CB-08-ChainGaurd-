const { createHash, randomUUID } = require('node:crypto');

const MAX_EVENTS = 500;
const events = [];
const visitorSalt = randomUUID();
const labRequestSecret = randomUUID();

function fingerprint(value) {
  return value ? createHash('sha256').update(value).digest('hex').slice(0, 12) : null;
}

function getClientIp(request) {
  if (request.headers['x-chain-guard-lab-secret'] === labRequestSecret) {
    return String(request.headers['x-demo-client-ip'] || 'demo-lab');
  }
  const forwarded = request.headers['x-forwarded-for'];
  const forwardedIp = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : null;
  const source = forwardedIp || request.socket.remoteAddress || 'unknown';
  return `visitor-${fingerprint(`${visitorSalt}:${source}`)}`;
}

function getDevice(userAgent) {
  if (!userAgent) return 'unknown';
  if (/mobile|android|iphone|ipad/i.test(userAgent)) return 'mobile';
  if (/bot|crawler|spider|curl|postman/i.test(userAgent)) return 'automated-client';
  return 'desktop-browser';
}

function getBearerToken(request) {
  const authorization = request.headers.authorization || '';
  return authorization.startsWith('Bearer ') ? authorization.slice(7) : null;
}

function startRequestObservation(request, url) {
  const token = getBearerToken(request);
  return {
    id: randomUUID(),
    startedAt: Date.now(),
    timestamp: new Date().toISOString(),
    method: request.method,
    endpoint: url.pathname,
    ip: getClientIp(request),
    device: getDevice(request.headers['user-agent']),
    tokenFingerprint: fingerprint(token),
    outcome: 'observed',
    userId: null,
    accountFingerprint: null
  };
}

function completeRequestObservation(observation, response) {
  const event = {
    ...observation,
    durationMs: Date.now() - observation.startedAt,
    statusCode: response.statusCode
  };
  delete event.startedAt;
  events.unshift(event);
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
  return event;
}

function getRecentEvents(limit = 50) {
  const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), MAX_EVENTS);
  return events.slice(0, safeLimit);
}

function getSummary() {
  const latest = events.slice(0, 100);
  const failedLogins = latest.filter((event) => event.endpoint === '/api/login' && event.outcome === 'login-failed').length;
  const byEndpoint = latest.reduce((counts, event) => {
    counts[event.endpoint] = (counts[event.endpoint] || 0) + 1;
    return counts;
  }, {});

  return {
    recordedRequests: events.length,
    failedLogins,
    uniqueIps: new Set(latest.map((event) => event.ip)).size,
    requestsByEndpoint: byEndpoint
  };
}

module.exports = {
  fingerprint,
  getBearerToken,
  startRequestObservation,
  completeRequestObservation,
  getRecentEvents,
  getSummary,
  labRequestSecret
};

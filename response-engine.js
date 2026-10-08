const { randomInt, randomUUID } = require('node:crypto');

const RATE_LIMIT_MS = 2_000;
const BLOCK_MS = 2 * 60_000;
const VERIFY_MS = 5 * 60_000;
const lastAllowedByIp = new Map();
const blockedIps = new Map();
const challenges = new Map();
const verifications = new Map();

function identity(observation) {
  return `${observation.ip}:${observation.tokenFingerprint || 'anonymous'}`;
}

function createChallenge(observation) {
  const left = randomInt(2, 10);
  const right = randomInt(2, 10);
  const id = randomUUID();
  challenges.set(id, {
    answer: left + right,
    identity: identity(observation),
    expiresAt: Date.now() + VERIFY_MS,
    attempts: 0
  });
  return { id, question: `What is ${left} + ${right}?`, expiresInSeconds: VERIFY_MS / 1000 };
}

function verifyChallenge(observation, challengeId, answer) {
  const challenge = challenges.get(challengeId);
  if (!challenge || challenge.expiresAt <= Date.now() || challenge.identity !== identity(observation)) {
    return { ok: false, error: 'The demo challenge is invalid or expired.' };
  }
  challenge.attempts += 1;
  if (Number(answer) !== challenge.answer || String(answer).trim() === '') {
    if (challenge.attempts >= 3) challenges.delete(challengeId);
    return { ok: false, error: 'Incorrect answer. Try the current challenge again.' };
  }
  challenges.delete(challengeId);
  const token = `verify_${randomUUID()}`;
  verifications.set(token, { identity: identity(observation), expiresAt: Date.now() + VERIFY_MS });
  return { ok: true, token, expiresInSeconds: VERIFY_MS / 1000 };
}

function hasValidVerification(request, observation) {
  const token = request.headers['x-demo-verification'];
  const record = token && verifications.get(token);
  return Boolean(record && record.expiresAt > Date.now() && record.identity === identity(observation));
}

function decideResponse(request, observation, risk) {
  const now = Date.now();
  const blockedUntil = blockedIps.get(observation.ip) || 0;
  if (blockedUntil > now) {
    return { action: 'block', status: 403, reason: 'IP temporarily blocked after critical-risk activity.', retryAfterSeconds: Math.ceil((blockedUntil - now) / 1000) };
  }
  if (blockedUntil) blockedIps.delete(observation.ip);

  if (risk.level === 'critical') {
    blockedIps.set(observation.ip, now + BLOCK_MS);
    return { action: 'block', status: 403, reason: 'Critical cumulative risk score.', retryAfterSeconds: BLOCK_MS / 1000, alertAdmin: true };
  }

  if (risk.level === 'high' && !hasValidVerification(request, observation)) {
    return { action: 'step-up', status: 428, reason: 'High cumulative risk score; demo verification required.', challenge: createChallenge(observation) };
  }

  if (risk.level === 'medium') {
    const lastAllowed = lastAllowedByIp.get(observation.ip) || 0;
    const remaining = RATE_LIMIT_MS - (now - lastAllowed);
    if (remaining > 0) {
      return { action: 'rate-limit', status: 429, reason: 'Medium cumulative risk score; requests are limited to one every 2 seconds.', retryAfterSeconds: Math.ceil(remaining / 1000) };
    }
  }

  lastAllowedByIp.set(observation.ip, now);
  return { action: 'allow', status: null, reason: risk.level === 'high' ? 'Demo verification passed.' : 'Request allowed.' };
}

function getResponseSummary(events) {
  const actions = { allow: 0, 'rate-limit': 0, 'step-up': 0, block: 0 };
  for (const event of events) {
    if (event.security?.action in actions) actions[event.security.action] += 1;
  }
  return { total: Object.values(actions).reduce((total, count) => total + count, 0), byAction: actions };
}

function getResponseEvents(events, limit = 20) {
  const safeLimit = Math.min(Math.max(Number(limit) || 20, 1), 100);
  return events
    .filter((event) => event.security && event.security.action !== 'allow')
    .slice(0, safeLimit)
    .map((event) => ({
      timestamp: event.timestamp,
      endpoint: event.endpoint,
      ip: event.ip,
      statusCode: event.statusCode,
      action: event.security.action,
      reason: event.security.reason,
      decisionScore: event.security.decisionScore,
      revokedToken: Boolean(event.security.revokedToken),
      alertAdmin: Boolean(event.security.alertAdmin)
    }));
}

module.exports = { decideResponse, verifyChallenge, getResponseSummary, getResponseEvents };

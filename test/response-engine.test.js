const test = require('node:test');
const assert = require('node:assert/strict');
const { decideResponse, verifyChallenge } = require('../response-engine');

function actor(ip, tokenFingerprint = null) {
  return { ip, tokenFingerprint };
}

test('medium risk allows a paced request and rate limits a burst', () => {
  const subject = actor('203.0.113.121');
  const request = { headers: {} };
  assert.equal(decideResponse(request, subject, { level: 'medium' }).action, 'allow');
  const second = decideResponse(request, subject, { level: 'medium' });
  assert.equal(second.action, 'rate-limit');
  assert.equal(second.status, 429);
  assert.ok(second.retryAfterSeconds >= 1);
});

test('high risk challenge can be solved and used by the same actor', () => {
  const subject = actor('203.0.113.122', 'demo-token-fingerprint');
  const challengeDecision = decideResponse({ headers: {} }, subject, { level: 'high' });
  assert.equal(challengeDecision.status, 428);
  const numbers = challengeDecision.challenge.question.match(/\d+/g).map(Number);
  const verification = verifyChallenge(subject, challengeDecision.challenge.id, numbers[0] + numbers[1]);
  assert.equal(verification.ok, true);
  const retry = decideResponse({ headers: { 'x-demo-verification': verification.token } }, subject, { level: 'high' });
  assert.equal(retry.action, 'allow');
  const differentIp = decideResponse({ headers: { 'x-demo-verification': verification.token } }, actor('203.0.113.123', 'demo-token-fingerprint'), { level: 'high' });
  assert.equal(differentIp.action, 'step-up');
});

test('critical risk blocks and keeps the IP blocked temporarily', () => {
  const subject = actor('203.0.113.124');
  const first = decideResponse({ headers: {} }, subject, { level: 'critical' });
  assert.equal(first.status, 403);
  assert.equal(first.alertAdmin, true);
  const later = decideResponse({ headers: {} }, subject, { level: 'low' });
  assert.equal(later.action, 'block');
  assert.ok(later.retryAfterSeconds > 0);
});

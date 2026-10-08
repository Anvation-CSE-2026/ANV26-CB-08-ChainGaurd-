const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeIntegrationEvent } = require('../event-contract');
const { analyzeObservedEvent } = require('../security-pipeline');

const fingerprint = (character) => character.repeat(64);
const loginFailure = (clientId, accountFingerprint) => ({
  activity: 'login',
  method: 'POST',
  statusCode: 401,
  outcome: 'login-failed',
  clientId,
  device: 'desktop-browser',
  accountFingerprint
});

test('integration contract keeps application identity server-controlled and rejects sensitive fields', () => {
  const input = loginFailure('synthetic-client-1', fingerprint('a'));
  const event = normalizeIntegrationEvent(input, 'student-portal');
  assert.equal(event.applicationId, 'student-portal');
  assert.equal(event.activity, 'login');
  assert.equal(event.endpoint, '/api/login');
  assert.match(event.ip, /^client-[a-f0-9]{12}$/);
  assert.ok(!JSON.stringify(event).includes(input.clientId));
  assert.ok(!JSON.stringify(event).includes(input.accountFingerprint));
  assert.throws(() => normalizeIntegrationEvent({ ...input, password: 'not-allowed' }, 'student-portal'), /unsupported field/);
  assert.throws(() => normalizeIntegrationEvent({ ...input, applicationId: 'another-app' }, 'student-portal'), /unsupported field/);
  assert.throws(() => normalizeIntegrationEvent({ ...input, accountFingerprint: 'someone@example.com' }, 'student-portal'), /accountFingerprint/);
});

test('connected-app activity uses the existing detector and risk engine without crossing apps', () => {
  const history = [];
  for (let index = 0; index < 4; index += 1) {
    const event = normalizeIntegrationEvent(loginFailure('synthetic-client-2', fingerprint(String(index))), 'student-portal');
    history.unshift(event);
    analyzeObservedEvent(event, history);
  }
  const unrelated = normalizeIntegrationEvent(loginFailure('synthetic-client-2', fingerprint('9')), 'separate-portal');
  // Even identical pseudonymous clients must not combine activity across applications.
  unrelated.ip = history[0].ip;
  history.unshift(unrelated);
  assert.equal(analyzeObservedEvent(unrelated, history).event.risk.score, 0);
  assert.equal(unrelated.detections, undefined);

  const fifth = normalizeIntegrationEvent(loginFailure('synthetic-client-2', fingerprint('8')), 'student-portal');
  history.unshift(fifth);
  const result = analyzeObservedEvent(fifth, history);
  assert.equal(result.event.risk.score, 20);
  assert.deepEqual(result.event.detections, ['credential-stuffing']);
  assert.equal(result.detections[0].applicationId, 'student-portal');
});

test('record enumeration works with an external route classification and no real URL', () => {
  const history = [];
  let latest;
  for (const recordId of ['1001', '1002', '1003', '1004']) {
    latest = normalizeIntegrationEvent({
      activity: 'user-record', method: 'GET', statusCode: 200,
      clientId: 'synthetic-client-3', device: 'desktop-browser', recordId
    }, 'student-portal');
    history.unshift(latest);
    analyzeObservedEvent(latest, history);
  }
  assert.equal(latest.endpoint, '/api/users/:id');
  assert.equal(latest.risk.score, 25);
  assert.deepEqual(latest.detections, ['enumeration']);
});

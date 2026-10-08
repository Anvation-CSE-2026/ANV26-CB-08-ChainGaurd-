const test = require('node:test');
const assert = require('node:assert/strict');
const { scoreRisk, riskLevel } = require('../risk-engine');

const baseTime = Date.parse('2026-10-08T10:00:00.000Z');

function request(seconds, overrides = {}) {
  return {
    timestamp: new Date(baseTime + seconds * 1000).toISOString(),
    ip: '203.0.113.10',
    endpoint: '/api/products',
    method: 'GET',
    statusCode: 200,
    outcome: 'observed',
    device: 'desktop-browser',
    tokenFingerprint: null,
    accountFingerprint: null,
    ...overrides
  };
}

test('normal demo API traffic scores zero and monitoring traffic is excluded', () => {
  const normal = request(0);
  assert.equal(scoreRisk(normal, [normal]).score, 0);
  const monitor = request(1, { endpoint: '/api/monitor/detections' });
  assert.equal(scoreRisk(monitor, [normal, monitor]).score, 0);
});

test('signals add cumulatively and the total is capped at 100', () => {
  const failures = Array.from({ length: 5 }, (_, index) => request(index, {
    endpoint: '/api/login', method: 'POST', statusCode: 401, outcome: 'login-failed',
    accountFingerprint: `account-${index % 3}`
  }));
  const lookups = Array.from({ length: 4 }, (_, index) => request(5 + index, {
    endpoint: `/api/users/${1001 + index}`, tokenFingerprint: 'token-one'
  }));
  const listing = Array.from({ length: 20 }, (_, index) => request(9 + index * 0.1, {
    tokenFingerprint: 'token-one', device: 'automated-client'
  }));
  const secondIp = request(12, {
    ip: '203.0.113.11', endpoint: '/api/users/1001', tokenFingerprint: 'token-one'
  });
  const lastRequest = request(13, { tokenFingerprint: 'token-one', device: 'automated-client' });
  const events = [...failures, ...lookups, ...listing, secondIp, lastRequest];
  const result = scoreRisk(lastRequest, events);

  assert.equal(result.score, 100);
  assert.equal(result.level, 'critical');
  assert.deepEqual(result.factors.map((factor) => factor.points), [20, 25, 30, 40, 15]);
});

test('risk levels follow the agreed score bands', () => {
  assert.equal(riskLevel(30), 'low');
  assert.equal(riskLevel(31), 'medium');
  assert.equal(riskLevel(60), 'medium');
  assert.equal(riskLevel(61), 'high');
  assert.equal(riskLevel(80), 'high');
  assert.equal(riskLevel(81), 'critical');
});

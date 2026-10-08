const test = require('node:test');
const assert = require('node:assert/strict');
const { getActivePolicy, listPolicies, setActivePolicy, riskLevelForPolicy } = require('../security-policy');

test('standard policy keeps the original response bands', () => {
  setActivePolicy('standard');
  assert.equal(getActivePolicy().label, 'Standard');
  assert.equal(riskLevelForPolicy(30), 'low');
  assert.equal(riskLevelForPolicy(31), 'medium');
  assert.equal(riskLevelForPolicy(61), 'high');
  assert.equal(riskLevelForPolicy(81), 'critical');
});

test('strict and baseline-aware policies change response bands', () => {
  setActivePolicy('strict');
  assert.equal(riskLevelForPolicy(25), 'medium');
  setActivePolicy('baseline');
  assert.equal(riskLevelForPolicy(25), 'low');
  assert.equal(riskLevelForPolicy(75), 'high');
  assert.deepEqual(listPolicies().map((policy) => policy.id), ['strict', 'standard', 'baseline']);
  setActivePolicy('standard');
});

test('unknown policy is rejected', () => {
  assert.throws(() => setActivePolicy('unknown'), /valid security policy/);
});

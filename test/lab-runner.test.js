const test = require('node:test');
const assert = require('node:assert/strict');
const { server } = require('../server');
const { SCENARIOS, runLabScenario } = require('../lab-runner');

test('legitimate high-volume traffic stays allowed and creates no abuse alerts', async (t) => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  assert.equal(SCENARIOS.has('legitimate-high-volume'), true);
  const result = await runLabScenario('legitimate-high-volume', server.address().port);

  assert.equal(result.requestsSent, 50);
  assert.deepEqual(result.statusCodes, [200]);
  assert.deepEqual(result.detectedTypes, []);
  assert.equal(result.highestRiskScore, 0);
  assert.deepEqual(result.actions, []);
  assert.equal(result.alertsCreated, 0);
});

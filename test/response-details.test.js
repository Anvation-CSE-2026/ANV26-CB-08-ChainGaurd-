const test = require('node:test');
const assert = require('node:assert/strict');
const { server } = require('../server');
const { runLabScenario } = require('../lab-runner');

test('response details preserve the decision policy, filter allowed requests and expose real block expiry', async (t) => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  const setPolicy = (policyId) => fetch(`${base}/api/security-policy`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ policyId })
  });
  await setPolicy('strict');
  await fetch(`${base}/api/products`);
  await setPolicy('standard');
  const allowed = await (await fetch(`${base}/api/monitor/responses?action=allow`)).json();
  assert.equal(allowed.responses.length, 1);
  assert.equal(allowed.responses[0].action, 'allow');
  assert.equal(allowed.responses[0].policy.id, 'strict');
  assert.equal(allowed.responses[0].policy.thresholds.medium, 20);
  assert.equal(allowed.responses[0].evidence[0].endpoint, '/api/products');

  await runLabScenario('combined-risk', port);
  const blocked = await (await fetch(`${base}/api/monitor/responses?action=block`)).json();
  assert.ok(blocked.responses.length > 0);
  assert.ok(blocked.responses.every((response) => response.action === 'block'));
  assert.ok(blocked.responses[0].blockedUntil > Date.now());
  assert.equal(blocked.responses[0].policy.id, 'standard');
  assert.ok(blocked.responses[0].factors.length > 0);
  assert.ok(blocked.responses[0].evidence.length > 0);
  assert.equal((await fetch(`${base}/api/monitor/responses?action=invalid`)).status, 400);
});

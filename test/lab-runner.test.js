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

test('slow enumeration stays below the comparison rate limit but triggers sequence detection', async (t) => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const result = await runLabScenario('slow-enumeration', server.address().port);
  assert.equal(result.requestsSent, 5);
  assert.deepEqual(result.statusCodes, [200]);
  assert.deepEqual(result.detectedTypes, ['enumeration']);
  assert.equal(result.highestRiskScore, 25);
  assert.equal(result.rateLimitComparison.exceeded, false);
  assert.equal(result.rateLimitComparison.peakRequests, 1);
  assert.deepEqual(result.requestTrace.slice(1).map((request) => request.endpoint), [
    '/api/users/1001', '/api/users/1002', '/api/users/1003', '/api/users/1004'
  ]);
  for (let index = 1; index < result.requestTrace.length; index += 1) {
    assert.ok(result.requestTrace[index].elapsedMs - result.requestTrace[index - 1].elapsedMs >= 1400);
  }
});

test('scenario scores retain separate latest-run peaks without altering cumulative monitoring', async (t) => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  const scraping = await runLabScenario('scraping', port);
  await runLabScenario('legitimate-high-volume', port);
  const before = await (await fetch(`http://127.0.0.1:${port}/api/monitor/risks`)).json();
  const stored = await (await fetch(`http://127.0.0.1:${port}/api/lab/results`)).json();
  const after = await (await fetch(`http://127.0.0.1:${port}/api/monitor/risks`)).json();
  assert.equal(stored.results.find((result) => result.scenario === 'scraping').highestRiskScore, scraping.highestRiskScore);
  assert.equal(stored.results.find((result) => result.scenario === 'legitimate-high-volume').highestRiskScore, 0);
  assert.equal(stored.results.filter((result) => result.scenario === 'legitimate-high-volume').length, 1);
  assert.deepEqual(before.summary, after.summary);
  assert.equal(after.summary.latest.score, 0);
});

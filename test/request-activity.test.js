const test = require('node:test');
const assert = require('node:assert/strict');
const { server } = require('../server');

test('request activity exposes safe decision details for scored demo requests', async (t) => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;

  assert.equal((await fetch(`${base}/api/products`)).status, 200);
  const response = await fetch(`${base}/api/monitor/risks?limit=1`);
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.requests.length, 1);
  assert.deepEqual(
    {
      method: data.requests[0].method,
      endpoint: data.requests[0].endpoint,
      statusCode: data.requests[0].statusCode,
      action: data.requests[0].action,
      score: data.requests[0].risk.score
    },
    { method: 'GET', endpoint: '/api/products', statusCode: 200, action: 'allow', score: 0 }
  );
  assert.match(data.requests[0].ip, /^visitor-/);
});

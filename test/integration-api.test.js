const test = require('node:test');
const assert = require('node:assert/strict');

const ownerKey = 'test-owner-key-' + 'a'.repeat(32);
process.env.CHAIN_GUARD_ADMIN_KEY = ownerKey;
const { server } = require('../server');

test('registration API requires owner access and never lists app keys', async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const status = await (await fetch(`${base}/api/integrations/status`)).json();
    assert.equal(status.registrationConfigured, true);

    const denied = await fetch(`${base}/api/integrations/apps`);
    assert.equal(denied.status, 401);
    const wrongKey = await fetch(`${base}/api/integrations/apps`, { headers: { 'X-Chain-Guard-Admin-Key': 'wrong' } });
    assert.equal(wrongKey.status, 401);

    const create = await fetch(`${base}/api/integrations/apps`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Chain-Guard-Admin-Key': ownerKey },
      body: JSON.stringify({ name: 'Student Portal' })
    });
    assert.equal(create.status, 201);
    const created = await create.json();
    assert.equal(created.application.name, 'Student Portal');
    assert.match(created.connectionKey, /^cg_demo_/);

    const list = await (await fetch(`${base}/api/integrations/apps`, {
      headers: { 'X-Chain-Guard-Admin-Key': ownerKey }
    })).json();
    assert.equal(list.applications.length, 1);
    assert.equal(list.applications[0].id, created.application.id);
    assert.ok(!JSON.stringify(list).includes(created.connectionKey));

    const invalid = await fetch(`${base}/api/integrations/apps`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Chain-Guard-Admin-Key': ownerKey },
      body: JSON.stringify({ name: '<script>' })
    });
    assert.equal(invalid.status, 400);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

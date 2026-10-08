const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');

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
    const sharedDemoCode = await fetch(`${base}/api/integrations/overview`, { headers: { 'X-Chain-Guard-Admin-Key': 'stuportal123' } });
    assert.equal(sharedDemoCode.status, 401);

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

    const eventUrl = `${base}/api/v1/events`;
    const eventHeaders = {
      'Content-Type': 'application/json',
      'X-Chain-Guard-App-Id': created.application.id,
      'X-Chain-Guard-App-Key': created.connectionKey
    };
    const eventBody = (index) => ({
      activity: 'login', method: 'POST', statusCode: 401,
      outcome: 'login-failed', clientId: 'student-test-client', device: 'desktop-browser',
      accountFingerprint: createHash('sha256').update(`fictional-student-${index}`).digest('hex')
    });
    assert.equal((await fetch(eventUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(eventBody(0)) })).status, 401);
    assert.equal((await fetch(eventUrl, { method: 'POST', headers: { ...eventHeaders, 'X-Chain-Guard-App-Key': 'wrong' }, body: JSON.stringify(eventBody(0)) })).status, 401);
    assert.equal((await fetch(eventUrl, { method: 'POST', headers: { ...eventHeaders, 'Content-Type': 'text/plain' }, body: JSON.stringify(eventBody(0)) })).status, 415);
    assert.equal((await fetch(eventUrl, { method: 'POST', headers: eventHeaders, body: JSON.stringify({ ...eventBody(0), password: 'forbidden' }) })).status, 422);
    assert.equal((await fetch(eventUrl, { method: 'POST', headers: eventHeaders, body: JSON.stringify({ padding: 'x'.repeat(9_000) }) })).status, 413);

    let result;
    for (let index = 0; index < 5; index += 1) {
      const accepted = await fetch(eventUrl, { method: 'POST', headers: eventHeaders, body: JSON.stringify(eventBody(index)) });
      assert.equal(accepted.status, 202);
      result = await accepted.json();
    }
    assert.equal(result.accepted, true);
    assert.equal(result.applicationId, created.application.id);
    assert.equal(result.risk.score, 20);
    assert.deepEqual(result.detections, [{ type: 'credential-stuffing', severity: 'high' }]);

    const updatedList = await (await fetch(`${base}/api/integrations/apps`, {
      headers: { 'X-Chain-Guard-Admin-Key': ownerKey }
    })).json();
    assert.equal(updatedList.applications[0].eventCount, 5);
    assert.equal(updatedList.applications[0].status, 'receiving-events');
    assert.ok(updatedList.applications[0].lastEventAt);

    const publicRequests = await (await fetch(`${base}/api/monitor/requests?limit=500`)).json();
    const publicDetections = await (await fetch(`${base}/api/monitor/detections?limit=50`)).json();
    assert.ok(!JSON.stringify(publicRequests).includes(created.application.id));
    assert.ok(!JSON.stringify(publicDetections).includes(created.application.id));
    assert.equal(publicDetections.summary.total, 0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

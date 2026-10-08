const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');

const ownerKey = 'test-dashboard-owner-' + 'x'.repeat(32);
process.env.CHAIN_GUARD_ADMIN_KEY = ownerKey;
const { server } = require('../server');

test('protected multi-app dashboard isolates alerts, events, and scores', async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const ownerHeaders = { 'X-Chain-Guard-Admin-Key': ownerKey };
  try {
    const denied = await fetch(`${base}/api/integrations/overview`);
    assert.equal(denied.status, 401);

    async function register(name) {
      const response = await fetch(`${base}/api/integrations/apps`, {
        method: 'POST', headers: { ...ownerHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      });
      assert.equal(response.status, 201);
      return response.json();
    }

    const portal = await register('Student Portal');
    const shop = await register('Fictional Shop');
    async function ingest(registered, event) {
      const response = await fetch(`${base}/api/v1/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Chain-Guard-App-Id': registered.application.id,
          'X-Chain-Guard-App-Key': registered.connectionKey
        },
        body: JSON.stringify(event)
      });
      assert.equal(response.status, 202);
      return response.json();
    }

    for (let number = 1; number <= 5; number += 1) {
      await ingest(portal, {
        activity: 'login', method: 'POST', statusCode: 401, outcome: 'login-failed',
        clientId: 'fictional-client-one', device: 'desktop-browser',
        accountFingerprint: createHash('sha256').update(`fake-student-${number}`).digest('hex')
      });
    }
    await ingest(shop, {
      activity: 'product-list', method: 'GET', statusCode: 200,
      clientId: 'fictional-client-two', device: 'mobile'
    });

    const overviewResponse = await fetch(`${base}/api/integrations/overview`, { headers: ownerHeaders });
    assert.equal(overviewResponse.status, 200);
    const overview = await overviewResponse.json();
    assert.equal(overview.applications.length, 2);
    const portalSummary = overview.applications.find((app) => app.id === portal.application.id);
    const shopSummary = overview.applications.find((app) => app.id === shop.application.id);
    assert.equal(portalSummary.eventCount, 5);
    assert.equal(portalSummary.alerts.byType['credential-stuffing'], 1);
    assert.equal(portalSummary.risk.highestScore, 20);
    assert.equal(shopSummary.eventCount, 1);
    assert.equal(shopSummary.alerts.total, 0);
    assert.equal(shopSummary.risk.highestScore, 0);
    assert.ok(!JSON.stringify(overview).includes(portal.connectionKey));
    assert.ok(!JSON.stringify(overview).includes(shop.connectionKey));

    const activityUrl = (id) => `${base}/api/integrations/apps/${id}/activity?limit=20`;
    assert.equal((await fetch(activityUrl(portal.application.id))).status, 401);
    assert.equal((await fetch(activityUrl('missing-app'))).status, 401);
    assert.equal((await fetch(activityUrl('missing-app'), { headers: ownerHeaders })).status, 404);
    const portalActivity = await (await fetch(activityUrl(portal.application.id), { headers: ownerHeaders })).json();
    const shopActivity = await (await fetch(activityUrl(shop.application.id), { headers: ownerHeaders })).json();
    assert.equal(portalActivity.events.length, 5);
    assert.equal(portalActivity.detections.length, 1);
    assert.equal(portalActivity.events.at(0).risk.score, 20);
    assert.equal(shopActivity.events.length, 1);
    assert.equal(shopActivity.events[0].activity, 'product-list');
    assert.equal(shopActivity.detections.length, 0);
    assert.ok(!JSON.stringify(portalActivity).includes('accountFingerprint'));
    assert.ok(!JSON.stringify(portalActivity).includes('clientId'));

    const publicDetections = await (await fetch(`${base}/api/monitor/detections`)).json();
    assert.equal(publicDetections.summary.total, 0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

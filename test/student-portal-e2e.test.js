const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const { getRecentEvents } = require('../request-monitor');
const { getDetections } = require('../detection-engine');

const python = process.env.CHAIN_GUARD_TEST_PYTHON;

test('separate FastAPI Student Portal sends events through the real Chain Guard pipeline', {
  skip: !python && 'Set CHAIN_GUARD_TEST_PYTHON to a Python with FastAPI, httpx, and the connector installed.'
}, async () => {
  const ownerKey = 'test-student-portal-owner-' + 'a'.repeat(32);
  process.env.CHAIN_GUARD_ADMIN_KEY = ownerKey;
  const { server } = require('../server');
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const registration = await fetch(`${base}/api/integrations/apps`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Chain-Guard-Admin-Key': ownerKey },
      body: JSON.stringify({ name: 'Student Portal E2E' })
    });
    assert.equal(registration.status, 201);
    const { application, connectionKey } = await registration.json();
    const result = await new Promise((resolve, reject) => {
      const child = spawn(python, ['-m', 'examples.student_portal.smoke'], {
        cwd: path.join(__dirname, '..'),
        env: {
          ...process.env,
          CHAIN_GUARD_URL: base,
          CHAIN_GUARD_APP_ID: application.id,
          CHAIN_GUARD_APP_KEY: connectionKey,
          CHAIN_GUARD_IDENTITY_SECRET: 'fictional-identity-secret-for-tests-only'
        }
      });
      let output = '';
      let errors = '';
      child.stdout.on('data', (chunk) => { output += chunk; });
      child.stderr.on('data', (chunk) => { errors += chunk; });
      child.on('error', reject);
      child.on('close', (code) => code === 0 ? resolve(output) : reject(new Error(errors || `Python exited ${code}`)));
    });
    assert.equal(JSON.parse(result).portalRequests, 43);
    const events = getRecentEvents(100, application.id);
    assert.equal(events.length, 43);
    assert.equal(events.filter((event) => event.activity === 'login' && event.outcome === 'login-failed').length, 5);
    const detected = new Set(getDetections(100, application.id).map((alert) => alert.type));
    for (const type of ['credential-stuffing', 'enumeration', 'scraping', 'token-api-key-misuse', 'bot-automation-abuse']) {
      assert.ok(detected.has(type), `Missing ${type} detection`);
    }
    assert.equal(events[0].risk.score, 100);
    assert.equal(events[0].risk.level, 'critical');
    assert.ok(events[0].risk.factors.length >= 4);
    assert.ok(!JSON.stringify(events).includes('wrong-demo-password'));
    assert.ok(!JSON.stringify(events).includes(connectionKey));
    assert.ok(!JSON.stringify(events).includes('PortalPass!123'));
    const dashboard = await (await fetch(`${base}/api/integrations/apps/${application.id}/activity?limit=50`, {
      headers: { 'X-Chain-Guard-Admin-Key': ownerKey }
    })).json();
    assert.equal(dashboard.application.eventCount, 43);
    assert.equal(dashboard.risk.highestScore, 100);
    assert.equal(dashboard.risk.latest.score, 100);
    assert.ok(dashboard.detections.length >= 5);
    const publicMonitor = await (await fetch(`${base}/api/monitor/detections?limit=50`)).json();
    assert.equal(publicMonitor.summary.total, 0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

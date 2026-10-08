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
    assert.equal(JSON.parse(result).portalRequests, 9);
    const events = getRecentEvents(20, application.id);
    assert.equal(events.length, 9);
    assert.equal(events.filter((event) => event.activity === 'login' && event.outcome === 'login-failed').length, 5);
    assert.ok(getDetections(20, application.id).some((alert) => alert.type === 'credential-stuffing'));
    assert.ok(events.some((event) => event.risk.score >= 20));
    assert.ok(!JSON.stringify(events).includes('wrong-demo-password'));
    assert.ok(!JSON.stringify(events).includes(connectionKey));
    assert.ok(!JSON.stringify(events).includes('PortalPass!123'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

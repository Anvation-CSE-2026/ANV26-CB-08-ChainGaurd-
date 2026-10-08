const test = require('node:test');
const assert = require('node:assert/strict');
const { createIntegrationRegistry } = require('../integration-registry');

test('registration stays disabled without an owner key', () => {
  const registry = createIntegrationRegistry();
  assert.equal(registry.configured, false);
  assert.equal(registry.isAuthorized('anything'), false);
});

test('owner-only registration returns each app key once and keeps it out of listings', () => {
  const adminKey = 'a'.repeat(40);
  const registry = createIntegrationRegistry(adminKey);
  assert.equal(registry.isAuthorized(adminKey), true);
  assert.equal(registry.isAuthorized('b'.repeat(40)), false);
  const { application, connectionKey } = registry.createApplication('Student Portal');
  assert.match(application.id, /^student-portal-[a-f0-9]{8}$/);
  assert.match(connectionKey, /^cg_demo_[A-Za-z0-9_-]{43}$/);
  assert.equal(registry.authenticatesApplication(application.id, connectionKey), true);
  assert.equal(registry.authenticatesApplication(application.id, 'wrong'), false);
  assert.equal(registry.authenticatesApplication('missing', connectionKey), false);
  assert.equal(registry.listApplications().length, 1);
  assert.ok(!JSON.stringify(registry.listApplications()).includes(connectionKey));
  assert.ok(!JSON.stringify(registry.listApplications()).includes('keyDigest'));
  assert.throws(() => registry.createApplication('<script>'), /App name/);
});

test('each registered app has a bounded synthetic event rate', () => {
  const registry = createIntegrationRegistry('c'.repeat(40));
  const { application } = registry.createApplication('Test Portal');
  for (let index = 0; index < 120; index += 1) assert.equal(registry.allowEvent(application.id, 1_000), true);
  assert.equal(registry.allowEvent(application.id, 1_000), false);
  assert.equal(registry.allowEvent(application.id, 61_001), true);
  registry.recordEvent(application.id, '2026-10-08T12:00:00.000Z');
  assert.equal(registry.listApplications()[0].eventCount, 1);
  assert.equal(registry.listApplications()[0].status, 'receiving-events');
});

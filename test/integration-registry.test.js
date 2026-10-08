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

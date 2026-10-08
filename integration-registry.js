const { createHash, randomBytes, timingSafeEqual } = require('node:crypto');

function digest(value) {
  return createHash('sha256').update(value).digest();
}

function createIntegrationRegistry(adminKey) {
  const configured = typeof adminKey === 'string' && adminKey.length >= 32;
  const adminDigest = configured ? digest(adminKey) : null;
  const applications = new Map();
  const recentEventTimes = new Map();

  function isAuthorized(candidate) {
    return configured && typeof candidate === 'string' &&
      timingSafeEqual(adminDigest, digest(candidate));
  }

  function listApplications() {
    return [...applications.values()].map(({ keyDigest, ...publicFields }) => publicFields);
  }

  function getApplication(id) {
    const application = applications.get(id);
    if (!application) return null;
    const { keyDigest, ...publicFields } = application;
    return publicFields;
  }

  function createApplication(name) {
    if (typeof name !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9 _-]{1,59}$/.test(name)) {
      throw new Error('App name must be 2–60 letters, numbers, spaces, hyphens, or underscores.');
    }
    if (applications.size >= 20) throw new Error('Demo limit reached: 20 registered applications.');
    const cleanedName = name.trim();
    if (cleanedName.length < 2) throw new Error('App name must contain at least 2 characters.');
    const id = `${cleanedName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 38)}-${randomBytes(4).toString('hex')}`;
    const connectionKey = `cg_demo_${randomBytes(32).toString('base64url')}`;
    const application = {
      id,
      name: cleanedName,
      createdAt: new Date().toISOString(),
      lastEventAt: null,
      eventCount: 0,
      status: 'awaiting-events',
      keyDigest: digest(connectionKey)
    };
    applications.set(id, application);
    const { keyDigest, ...publicFields } = application;
    return { application: publicFields, connectionKey };
  }

  function authenticatesApplication(id, candidate) {
    const application = applications.get(id);
    return Boolean(application && typeof candidate === 'string' &&
      timingSafeEqual(application.keyDigest, digest(candidate)));
  }

  function allowEvent(id, now = Date.now()) {
    if (!applications.has(id)) return false;
    const recent = (recentEventTimes.get(id) || []).filter((time) => now - time < 60_000);
    if (recent.length >= 120) {
      recentEventTimes.set(id, recent);
      return false;
    }
    recent.push(now);
    recentEventTimes.set(id, recent);
    return true;
  }

  function recordEvent(id, timestamp) {
    const application = applications.get(id);
    if (!application) return;
    application.eventCount += 1;
    application.lastEventAt = timestamp;
    application.status = 'receiving-events';
  }

  return { configured, isAuthorized, listApplications, getApplication, createApplication, authenticatesApplication, allowEvent, recordEvent };
}

module.exports = { createIntegrationRegistry };

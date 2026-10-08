const { randomUUID } = require('node:crypto');
const { DEMO_APPLICATION_ID, activityOf, recordIdOf, sameApplication } = require('./event-contract');

const alerts = [];
const recentAlertKeys = new Map();

function within(events, milliseconds, predicate) {
  const now = Date.now();
  return events.filter((event) => now - new Date(event.timestamp).getTime() <= milliseconds && predicate(event));
}

function sameClient(event, candidate) {
  return candidate.ip === event.ip;
}

function sequentialIds(events) {
  const ids = [...new Set(events
    .map(recordIdOf)
    .filter(Boolean)
    .map(Number))].sort((a, b) => a - b);

  let run = 1;
  for (let index = 1; index < ids.length; index += 1) {
    run = ids[index] === ids[index - 1] + 1 ? run + 1 : 1;
    if (run >= 4) return true;
  }
  return false;
}

function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function buildDetection(type, severity, event, description, signals) {
  return { type, severity, event, description, signals, key: `${event.applicationId || DEMO_APPLICATION_ID}:${type}:${event.ip}:${event.tokenFingerprint || 'anonymous'}` };
}

function inspectCredentialStuffing(event, events) {
  if (activityOf(event) !== 'login' || event.outcome !== 'login-failed') return null;
  const attempts = within(events, 10 * 60_000, (candidate) =>
    sameClient(event, candidate) && activityOf(candidate) === 'login' && candidate.outcome === 'login-failed'
  );
  const targetedAccounts = new Set(attempts.map((candidate) => candidate.accountFingerprint).filter(Boolean));
  if (attempts.length >= 5 && targetedAccounts.size >= 3) {
    return buildDetection('credential-stuffing', 'high', event,
      'Repeated failed login attempts targeted several accounts from one IP address.',
      { failedLogins: attempts.length, uniqueAccounts: targetedAccounts.size, windowSeconds: 600 });
  }
  return null;
}

function inspectEnumeration(event, events) {
  if (activityOf(event) !== 'user-record' || event.statusCode !== 200) return null;
  const requests = within(events, 2 * 60_000, (candidate) =>
    sameClient(event, candidate) && activityOf(candidate) === 'user-record' && candidate.statusCode === 200
  );
  if (sequentialIds(requests)) {
    return buildDetection('enumeration', 'high', event,
      'Sequential user IDs were requested from the same IP address.',
      { distinctUserRecordRequests: new Set(requests.map((candidate) => candidate.endpoint)).size, windowSeconds: 120 });
  }
  return null;
}

function inspectScraping(event, events) {
  const listings = new Set(['product-list', 'user-list']);
  if (!listings.has(activityOf(event)) || event.method !== 'GET') return null;
  const requests = within(events, 60_000, (candidate) =>
    sameClient(event, candidate) && listings.has(activityOf(candidate)) && candidate.method === 'GET'
  );
  if (requests.length >= 20) {
    return buildDetection('scraping', 'medium', event,
      'Listing endpoints were requested at an unusually high volume.',
      { listingRequests: requests.length, windowSeconds: 60 });
  }
  return null;
}

function inspectTokenMisuse(event, events) {
  if (!event.tokenFingerprint) return null;
  const requests = within(events, 10 * 60_000, (candidate) => candidate.tokenFingerprint === event.tokenFingerprint);
  const distinctIps = new Set(requests.map((candidate) => candidate.ip));
  const distinctDevices = new Set(requests.map((candidate) => candidate.device));
  const oneMinuteRequests = within(requests, 60_000, () => true);
  if (distinctIps.size >= 2 || distinctDevices.size >= 2 || oneMinuteRequests.length >= 50) {
    return buildDetection('token-api-key-misuse', 'critical', event,
      'The same token fingerprint appeared from unusual sources or at an excessive rate.',
      { uniqueIps: distinctIps.size, deviceTypes: distinctDevices.size, requestsInOneMinute: oneMinuteRequests.length });
  }
  return null;
}

function inspectBotAutomation(event, events) {
  const requests = within(events, 15_000, (candidate) => sameClient(event, candidate));
  if (requests.length < 12) return null;
  const times = requests.map((candidate) => new Date(candidate.timestamp).getTime()).sort((a, b) => a - b);
  const intervals = times.slice(1).map((time, index) => time - times[index]);
  const automatedUserAgent = event.device === 'automated-client';
  if (automatedUserAgent || median(intervals) < 350) {
    return buildDetection('bot-automation-abuse', 'medium', event,
      'Requests show automated timing or an automation-oriented client signature.',
      { requestsInFifteenSeconds: requests.length, medianIntervalMs: median(intervals), automatedUserAgent });
  }
  return null;
}

function detectAbuse(event, allEvents) {
  if ((event.applicationId || DEMO_APPLICATION_ID) === DEMO_APPLICATION_ID && activityOf(event) === 'api-request') return [];
  const applicationEvents = allEvents.filter((candidate) => sameApplication(event, candidate));
  const candidates = [
    inspectCredentialStuffing(event, applicationEvents),
    inspectEnumeration(event, applicationEvents),
    inspectScraping(event, applicationEvents),
    inspectTokenMisuse(event, applicationEvents),
    inspectBotAutomation(event, applicationEvents)
  ].filter(Boolean);

  const created = [];
  for (const candidate of candidates) {
    const lastSeen = recentAlertKeys.get(candidate.key) || 0;
    if (Date.now() - lastSeen < 30_000) continue;
    recentAlertKeys.set(candidate.key, Date.now());
    const alert = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      type: candidate.type,
      severity: candidate.severity,
      sourceEventId: candidate.event.id,
      applicationId: candidate.event.applicationId || DEMO_APPLICATION_ID,
      ip: candidate.event.ip,
      endpoint: candidate.event.endpoint,
      description: candidate.description,
      signals: candidate.signals,
      risk: candidate.event.risk
    };
    alerts.unshift(alert);
    const olderAlerts = alerts.filter((item) => item.applicationId === alert.applicationId);
    if (olderAlerts.length > 200) alerts.splice(alerts.indexOf(olderAlerts[200]), 1);
    created.push(alert);
  }
  if (recentAlertKeys.size > 2_000) {
    for (const [key, time] of recentAlertKeys) {
      if (Date.now() - time > 30_000) recentAlertKeys.delete(key);
    }
  }
  return created;
}

function getDetections(limit = 50, applicationId = null) {
  const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const visible = applicationId ? alerts.filter((alert) => alert.applicationId === applicationId) : alerts;
  return visible.slice(0, safeLimit);
}

function getDetectionSummary(applicationId = null) {
  const visible = applicationId ? alerts.filter((alert) => alert.applicationId === applicationId) : alerts;
  return visible.reduce((summary, alert) => {
    summary.total += 1;
    summary.byType[alert.type] = (summary.byType[alert.type] || 0) + 1;
    return summary;
  }, { total: 0, byType: {} });
}

module.exports = { detectAbuse, getDetections, getDetectionSummary };

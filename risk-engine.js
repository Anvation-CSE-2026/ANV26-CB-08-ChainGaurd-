const API_PREFIX = /^\/api\/(login|products|users)(\/|$)/;

function recent(events, time, windowMs, predicate) {
  return events.filter((event) => {
    const age = time - new Date(event.timestamp).getTime();
    return age >= 0 && age <= windowMs && predicate(event);
  });
}

function hasSequentialUserIds(events) {
  const ids = [...new Set(events
    .map((event) => event.endpoint.match(/^\/api\/users\/(\d+)$/)?.[1])
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
  const sorted = [...values].sort((a, b) => a - b);
  if (!sorted.length) return Infinity;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function riskLevel(score) {
  if (score <= 30) return 'low';
  if (score <= 60) return 'medium';
  if (score <= 80) return 'high';
  return 'critical';
}

function scoreRisk(event, events) {
  const factors = [];
  const add = (type, points, reason) => factors.push({ type, points, reason });
  const time = new Date(event.timestamp).getTime();

  // Monitoring page visits and monitor polling are not customer API behavior.
  if (!API_PREFIX.test(event.endpoint)) {
    return { score: 0, level: 'low', factors, calculatedAt: event.timestamp };
  }

  const sameIp = (candidate) => candidate.ip === event.ip && API_PREFIX.test(candidate.endpoint);
  const loginFailures = recent(events, time, 10 * 60_000, (candidate) =>
    sameIp(candidate) && candidate.endpoint === '/api/login' && candidate.outcome === 'login-failed'
  );
  const accounts = new Set(loginFailures.map((candidate) => candidate.accountFingerprint).filter(Boolean));
  if (loginFailures.length >= 5 && accounts.size >= 3) {
    add('credential-stuffing', 20, `${loginFailures.length} failed logins across ${accounts.size} accounts in 10 minutes`);
  }

  const userLookups = recent(events, time, 2 * 60_000, (candidate) =>
    sameIp(candidate) && candidate.statusCode === 200 && /^\/api\/users\/\d+$/.test(candidate.endpoint)
  );
  if (hasSequentialUserIds(userLookups)) {
    add('enumeration', 25, 'Four or more sequential user IDs in 2 minutes');
  }

  const listingRequests = recent(events, time, 60_000, (candidate) =>
    sameIp(candidate) && candidate.method === 'GET' &&
    (candidate.endpoint === '/api/products' || candidate.endpoint === '/api/users')
  );
  if (listingRequests.length >= 20) {
    add('scraping', 30, `${listingRequests.length} listing requests in 1 minute`);
  }

  if (event.tokenFingerprint) {
    const tokenEvents = recent(events, time, 10 * 60_000, (candidate) =>
      candidate.tokenFingerprint === event.tokenFingerprint && API_PREFIX.test(candidate.endpoint)
    );
    const ipCount = new Set(tokenEvents.map((candidate) => candidate.ip)).size;
    const deviceCount = new Set(tokenEvents.map((candidate) => candidate.device)).size;
    const tokenRequestsInMinute = recent(tokenEvents, time, 60_000, () => true).length;
    if (ipCount >= 2 || deviceCount >= 2) {
      add('token-api-key-misuse', 40, `Same token seen from ${ipCount} IPs and ${deviceCount} device types`);
    } else if (tokenRequestsInMinute >= 50) {
      add('token-api-key-misuse', 30, `${tokenRequestsInMinute} token requests in 1 minute`);
    }
  }

  const fastRequests = recent(events, time, 15_000, sameIp);
  if (fastRequests.length >= 12) {
    const times = fastRequests.map((candidate) => new Date(candidate.timestamp).getTime()).sort((a, b) => a - b);
    const gaps = times.slice(1).map((value, index) => value - times[index]);
    if (event.device === 'automated-client' || median(gaps) < 350) {
      add('bot-automation-abuse', 15, `${fastRequests.length} rapid requests in 15 seconds`);
    }
  }

  const score = Math.min(100, factors.reduce((total, factor) => total + factor.points, 0));
  return { score, level: riskLevel(score), factors, calculatedAt: event.timestamp };
}

function getRiskSummary(events) {
  const apiEvents = events.filter((event) => API_PREFIX.test(event.endpoint) && event.risk);
  const latest = apiEvents[0] || null;
  const highest = apiEvents.reduce((max, event) => Math.max(max, event.risk.score), 0);
  return {
    scoredRequests: apiEvents.length,
    latest: latest ? { score: latest.risk.score, level: latest.risk.level, ip: latest.ip } : null,
    highestScore: highest
  };
}

module.exports = { scoreRisk, getRiskSummary, riskLevel };

const test = require('node:test');
const assert = require('node:assert/strict');
const { startRequestObservation, labRequestSecret } = require('../request-monitor');

function request(headers = {}) {
  return { method: 'GET', headers, socket: { remoteAddress: '127.0.0.1' } };
}

test('public requests use anonymous stable visitor IDs and omit raw user agents', () => {
  const headers = { 'x-forwarded-for': '203.0.113.42', 'user-agent': 'Private Browser Details' };
  const first = startRequestObservation(request(headers), new URL('http://localhost/api/products'));
  const second = startRequestObservation(request(headers), new URL('http://localhost/api/products'));
  assert.match(first.ip, /^visitor-[a-f0-9]{12}$/);
  assert.equal(first.ip, second.ip);
  assert.ok(!JSON.stringify(first).includes('203.0.113.42'));
  assert.ok(!JSON.stringify(first).includes('Private Browser Details'));
});

test('only signed lab requests can use fictional source IPs', () => {
  const url = new URL('http://localhost/api/products');
  const spoofed = startRequestObservation(request({ 'x-demo-client-ip': '198.51.100.8' }), url);
  const lab = startRequestObservation(request({
    'x-demo-client-ip': '198.51.100.8',
    'x-chain-guard-lab-secret': labRequestSecret
  }), url);
  assert.match(spoofed.ip, /^visitor-/);
  assert.equal(lab.ip, '198.51.100.8');
});

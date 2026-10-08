#!/usr/bin/env node
// Launch two independent local processes with disposable fictional credentials.
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { existsSync } = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const root = path.join(__dirname, '..');
const python = process.env.CHAIN_GUARD_PYTHON || [
  path.join(root, 'work', 'fastapi-verify', 'Scripts', 'python.exe'),
  path.join(root, '.venv', 'Scripts', 'python.exe'),
  path.join(root, '.venv', 'bin', 'python')
].find(existsSync);
const chainPort = Number(process.env.CHAIN_GUARD_LOCAL_PORT || 3100);
const portalPort = Number(process.env.CHAIN_GUARD_PORTAL_PORT || 8000);
const host = '127.0.0.1';
const chainUrl = `http://${host}:${chainPort}`;
const portalUrl = `http://${host}:${portalPort}`;
const ownerKey = process.env.CHAIN_GUARD_LOCAL_OWNER_KEY || `local_demo_${randomBytes(32).toString('base64url')}`;
let chainProcess;
let portalProcess;
let stopping = false;

function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  if (portalProcess && !portalProcess.killed) portalProcess.kill();
  if (chainProcess && !chainProcess.killed) chainProcess.kill();
  process.exitCode = exitCode;
}

process.on('SIGINT', () => stop());
process.on('SIGTERM', () => stop());

function portAvailable(port) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(port, host, () => probe.close(() => resolve(true)));
  });
}

async function waitFor(url, ready) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (stopping) throw new Error('Startup interrupted.');
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (response.ok && ready(await response.json())) return;
    } catch { /* service still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Local service did not become ready: ${url}`);
}

async function main() {
  if (!python) throw new Error('Python environment not found. Set CHAIN_GUARD_PYTHON to a Python with FastAPI, uvicorn, and the local connector installed.');
  if (!Number.isInteger(chainPort) || !Number.isInteger(portalPort) || chainPort < 1024 || portalPort < 1024 || chainPort === portalPort) {
    throw new Error('Choose two different local ports above 1023.');
  }
  if (!(await portAvailable(chainPort)) || !(await portAvailable(portalPort))) {
    throw new Error(`Port ${chainPort} or ${portalPort} is already in use. Set CHAIN_GUARD_LOCAL_PORT or CHAIN_GUARD_PORTAL_PORT.`);
  }

  chainProcess = spawn(process.execPath, ['server.js'], {
    cwd: root,
    env: { ...process.env, HOST: host, PORT: String(chainPort), CHAIN_GUARD_ADMIN_KEY: ownerKey },
    stdio: ['ignore', 'ignore', 'pipe']
  });
  chainProcess.on('error', (error) => { process.stderr.write(`Chain Guard failed: ${error.message}\n`); stop(1); });
  chainProcess.on('exit', () => { if (!stopping) { process.stderr.write('Chain Guard stopped unexpectedly.\n'); stop(1); } });
  chainProcess.stderr.on('data', (chunk) => process.stderr.write(`Chain Guard: ${chunk}`));
  await waitFor(`${chainUrl}/api/health`, (body) => body.status === 'ok');

  const registration = await fetch(`${chainUrl}/api/integrations/apps`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Chain-Guard-Admin-Key': ownerKey },
    body: JSON.stringify({ name: 'Student Portal Local' })
  });
  if (!registration.ok) throw new Error(`Could not register local Student Portal (HTTP ${registration.status}).`);
  const { application, connectionKey } = await registration.json();

  const portalEnvironment = { ...process.env };
  delete portalEnvironment.CHAIN_GUARD_ADMIN_KEY;
  portalProcess = spawn(python, ['-m', 'uvicorn', 'examples.student_portal.app:app', '--host', host, '--port', String(portalPort)], {
    cwd: root,
    env: {
      ...portalEnvironment,
      CHAIN_GUARD_URL: chainUrl,
      CHAIN_GUARD_APP_ID: application.id,
      CHAIN_GUARD_APP_KEY: connectionKey,
      CHAIN_GUARD_IDENTITY_SECRET: randomBytes(32).toString('hex'),
      PORTAL_OWNER_KEY: ownerKey
    },
    stdio: ['ignore', 'ignore', 'pipe']
  });
  portalProcess.on('error', (error) => { process.stderr.write(`Student Portal failed: ${error.message}\n`); stop(1); });
  portalProcess.on('exit', () => { if (!stopping) { process.stderr.write('Student Portal stopped unexpectedly.\n'); stop(1); } });
  portalProcess.stderr.on('data', (chunk) => process.stderr.write(`Student Portal: ${chunk}`));
  await waitFor(`${portalUrl}/api/status`, (body) => body.chainGuardConfigured === true);

  process.stdout.write(`\nStudent Portal: ${portalUrl}/\nChain Guard owner view: ${chainUrl}/#integrations\nLocal-only owner key: ${ownerKey}\nPortal demo login: student1001 / PortalPass!123\n\nBoth apps are connected. Keep this terminal open; press Ctrl+C to stop them.\n`);
}

main().catch((error) => { process.stderr.write(`${error.message}\n`); stop(1); });

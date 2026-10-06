// REST command channel for agents that cannot hold a Socket.IO connection
// (the AiBoO Linux Sentinel polls over HTTPS).
//
// Covers: dashboard dispatch -> queue -> agent picks up -> agent acks ->
// ActionRecord appears in the Isolation & Termination tab.
//
// Runs without MongoDB.   Run:  npm test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import jwt from 'jsonwebtoken';

process.env.ALERT_STORE = 'memory';
process.env.JWT_SECRET = 'test-secret';
process.env.AGENT_API_KEY = 'test-agent-key';

const { default: agentRoutes } = await import('../routes/agent.routes.js');

let server;
let base;
const token = (role) => jwt.sign({ id: role, role, email: `${role}@test`, name: role }, 'test-secret');
const ADMIN = token('admin');
const ENDPOINT = 'auroraa-prod-ubuntu';

const call = (method, path, { body, role, agent } = {}) =>
  new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (role) headers.Authorization = `Bearer ${role === 'admin' ? ADMIN : role}`;
    if (agent) {
      headers['x-api-key'] = 'test-agent-key';
      headers['x-endpoint-id'] = ENDPOINT;
    }
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    const req = http.request(`${base}${path}`, { method, headers }, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => {
        let json = null;
        try { json = raw ? JSON.parse(raw) : null; } catch { /* text */ }
        resolve({ status: res.statusCode, json, raw });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });

before(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api/agent', agentRoutes);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((r) => server.close(r)));

test('dispatch to an endpoint that is not on the socket channel gets queued', async () => {
  const res = await call('POST', '/api/agent/commands', {
    role: 'admin',
    body: { endpoint_id: ENDPOINT, action: 'block_access', target: '45.95.147.3', params: { reason: 'test' } },
  });
  assert.equal(res.status, 202);
  assert.equal(res.json.ok, true);
  assert.equal(res.json.queued, true);
  assert.match(res.json.cmd_id, /^cmd_/);
});

test('the agent picks the command up once and it is marked sent', async () => {
  const first = await call('GET', '/api/agent/commands/pending', { agent: true });
  assert.equal(first.status, 200);
  const cmd = first.json.commands.find((c) => c.action === 'block_access');
  assert.ok(cmd, 'queued command should be handed to the agent');
  assert.equal(cmd.status, 'sent');
  assert.equal(cmd.target, '45.95.147.3');
  assert.equal(cmd.params.reason, 'test');

  const second = await call('GET', '/api/agent/commands/pending', { agent: true });
  assert.equal(second.json.commands.filter((c) => c.cmd_id === cmd.cmd_id).length, 0,
    'the same command must not be delivered twice');
});

test('wrong API key cannot read commands', async () => {
  const res = await new Promise((resolve, reject) => {
    const req = http.request(`${base}/api/agent/commands/pending`,
      { method: 'GET', headers: { 'x-api-key': 'nope', 'x-endpoint-id': ENDPOINT } }, (r) => {
        let raw = ''; r.on('data', (c) => (raw += c));
        r.on('end', () => resolve({ status: r.statusCode, raw }));
      });
    req.on('error', reject); req.end();
  });
  assert.equal(res.status, 401);
});

test('the ack stores the result and shows up as a response action', async () => {
  const pending = await call('GET', '/api/agent/commands/pending', { agent: true });
  const queued = await call('POST', '/api/agent/commands', {
    role: 'admin',
    body: { endpoint_id: ENDPOINT, action: 'terminate_process', target: '4242' },
  });
  const ack = await call('POST', `/api/agent/commands/${queued.json.cmd_id}/ack`, {
    agent: true,
    body: {
      status: 'executed', platform: 'linux',
      result: { message: 'stopped 4242:evil', details: 'SIGKILL', metadata: { dry_run: true } },
    },
  });
  assert.equal(ack.status, 200);
  assert.equal(ack.json.status, 'executed');
  assert.equal(ack.json.action.status, 'success');
  assert.equal(ack.json.action.source, ENDPOINT);
  assert.match(ack.json.action.details, /stopped 4242/);

  const actions = await call('GET', '/api/agent/actions', { role: 'admin' });
  assert.equal(actions.status, 200);
  const list = Array.isArray(actions.json) ? actions.json : actions.json.actions || [];
  assert.ok(list.some((a) => String(a.details || '').includes('stopped 4242')),
    'the action must be visible in the dashboard response list');
  assert.ok(pending.status === 200);
});

test('a failed ack is recorded as failed with the reason', async () => {
  const queued = await call('POST', '/api/agent/commands', {
    role: 'admin',
    body: { endpoint_id: ENDPOINT, action: 'quarantine_file', target: '/etc/shadow' },
  });
  const ack = await call('POST', `/api/agent/commands/${queued.json.cmd_id}/ack`, {
    agent: true,
    body: { status: 'failed', error: 'refused: needs root', result: { message: 'read-only mode' } },
  });
  assert.equal(ack.status, 200);
  assert.equal(ack.json.action.status, 'failed');
  assert.match(String(ack.json.action.details || ack.json.action.summary), /read-only|refused/);
});

test('command history is available to the dashboard', async () => {
  const res = await call('GET', `/api/agent/commands/history?endpoint_id=${ENDPOINT}`, { role: 'admin' });
  assert.equal(res.status, 200);
  assert.ok(res.json.count >= 3);
  const acked = res.json.commands.filter((c) => c.status === 'executed' || c.status === 'failed');
  assert.ok(acked.length >= 2, 'acks must be reflected in the history');
});

test('a viewer cannot dispatch remote actions', async () => {
  const res = await call('POST', '/api/agent/commands', {
    role: token('viewer'),
    body: { endpoint_id: ENDPOINT, action: 'block_access', target: '1.2.3.4' },
  });
  assert.ok(res.status === 403 || res.status === 401, `expected refusal, got ${res.status}`);
});

test('the heartbeat records the platform so the dashboard can show a Linux badge', async () => {
  const res = await call('POST', '/api/agent/heartbeat', {
    agent: true,
    body: { source: ENDPOINT, platform: 'linux' },
  });
  assert.equal(res.status, 200);
  assert.equal(res.json.platform, 'linux');

  const endpoints = await call('GET', '/api/agent/endpoints', { role: 'admin' });
  const ep = endpoints.json.find((e) => e.source === ENDPOINT);
  assert.ok(ep, 'endpoint should be listed');
  assert.equal(ep.platform, 'linux');
});

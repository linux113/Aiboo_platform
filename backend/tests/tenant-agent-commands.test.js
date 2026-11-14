import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import express from 'express';
import jwt from 'jsonwebtoken';

process.env.ALERT_STORE = 'memory';
process.env.JWT_SECRET = 'tenant-command-test-secret';
process.env.AGENT_API_KEY = 'legacy-test-key';

const mongoose = (await import('mongoose')).default;
const User = (await import('../models/User.js')).default;
const Organization = (await import('../models/Organization.js')).default;
const AgentCredential = (await import('../models/AgentCredential.js')).default;
const Subscription = (await import('../models/Subscription.js')).default;
const Plan = (await import('../models/Plan.js')).default;
const { getCommandState } = await import('../services/commandQueue.service.js');
const { default: agentRoutes, getAgentStore } = await import('../routes/agent.routes.js');

const ORG_A = '650000000000000000000021';
const ORG_B = '650000000000000000000022';
const ENDPOINT = 'shared-endpoint-name';
const expires = { [ORG_A]: new Date(Date.now() + 60_000), [ORG_B]: new Date(Date.now() + 60_000) };
const secretByKey = new Map();
let responseActionsEnabled = true;
const tokenFor = (keyId, secret) => `aiboo1_${keyId}.${secret}`;
const secretA = 'A'.repeat(43);
const secretB = 'B'.repeat(43);
const keyA = 'tenantKeyA';
const keyB = 'tenantKeyB';
secretByKey.set(keyA, { organization: ORG_A, secretHash: crypto.createHash('sha256').update(secretA).digest('hex') });
secretByKey.set(keyB, { organization: ORG_B, secretHash: crypto.createHash('sha256').update(secretB).digest('hex') });
const agentTokenA = tokenFor(keyA, secretA);
const agentTokenB = tokenFor(keyB, secretB);

const query = (value) => {
  const q = {
    select() { return q; },
    then(resolve, reject) { return Promise.resolve(value).then(resolve, reject); },
  };
  return q;
};
Object.defineProperty(mongoose.connection, 'readyState', { value: 1, configurable: true, writable: true });
User.findById = (id) => {
  const organization = id === 'company-admin-b' ? ORG_B : ORG_A;
  return query({ _id: id, name: 'Company admin', email: `${id}@test`, role: 'admin', active: true, organization });
};
Organization.findById = (id) => query(['' + ORG_A, '' + ORG_B].includes(String(id)) ? {
  _id: String(id), name: 'Test company', slug: 'test-company', status: 'active', isLegacy: false,
  subscriptionExpiresAt: expires[String(id)],
} : null);
Subscription.findOne = () => query({ plan: 'business-plan' });
Plan.findById = () => query({ enabled: true, features: { responseActions: responseActionsEnabled } });
AgentCredential.findOne = ({ keyId }) => {
  const found = secretByKey.get(keyId);
  if (!found) return query(null);
  return query({
    _id: `credential-${keyId}`, organization: found.organization, endpointId: ENDPOINT,
    platform: 'windows', secretHash: found.secretHash,
  });
};

let server;
let base;
const adminToken = (id = 'company-admin-a') => jwt.sign({ id, role: 'admin' }, process.env.JWT_SECRET);
const call = (method, path, { body, admin, key, endpoint = ENDPOINT } = {}) => new Promise((resolve, reject) => {
  const data = body ? JSON.stringify(body) : null;
  const headers = { 'Content-Type': 'application/json' };
  if (admin) headers.Authorization = `Bearer ${adminToken(admin === true ? 'company-admin-a' : admin)}`;
  if (key) {
    headers['x-api-key'] = key;
    headers['x-endpoint-id'] = endpoint;
  }
  if (data) headers['Content-Length'] = Buffer.byteLength(data);
  const req = http.request(`${base}${path}`, { method, headers }, (res) => {
    let raw = '';
    res.on('data', (chunk) => { raw += chunk; });
    res.on('end', () => {
      let json = null;
      try { json = raw ? JSON.parse(raw) : null; } catch { /* ignored */ }
      resolve({ status: res.statusCode, json, raw });
    });
  });
  req.on('error', reject);
  if (data) req.write(data);
  req.end();
});

before(async () => {
  const state = getCommandState();
  state.commandQueue.length = 0;
  state.commandHistory.length = 0;
  const app = express();
  app.use(express.json());
  app.use('/api/agent', agentRoutes);
  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

test('tenant command polling, acknowledgements and dispatch stay bound to organization plus endpoint', async () => {
  const dispatched = await call('POST', '/api/agent/commands', {
    admin: true,
    body: { endpoint_id: ENDPOINT, action: 'terminate_process', target: '1234', params: { reason: 'approved test' } },
  });
  assert.equal(dispatched.status, 202);
  assert.equal(dispatched.json.queued, true);

  const legacyPoll = await call('GET', '/api/agent/commands/pending', { key: 'legacy-test-key' });
  assert.equal(legacyPoll.status, 200);
  assert.equal(legacyPoll.json.count, 0, 'the shared legacy key cannot read a tenant command');

  const pickedUpByA = await call('GET', '/api/agent/commands/pending', { key: agentTokenA });
  assert.equal(pickedUpByA.status, 200);
  assert.equal(pickedUpByA.json.count, 1);
  assert.equal(pickedUpByA.json.commands[0].organization, ORG_A);

  const crossTenantAck = await call('POST', `/api/agent/commands/${dispatched.json.cmd_id}/ack`, {
    key: agentTokenB,
    body: { status: 'executed', source: ENDPOINT, result: { message: 'should not be accepted' } },
  });
  assert.equal(crossTenantAck.status, 404);
  const legacyAck = await call('POST', `/api/agent/commands/${dispatched.json.cmd_id}/ack`, {
    key: 'legacy-test-key',
    body: { status: 'executed', source: ENDPOINT },
  });
  assert.equal(legacyAck.status, 404, 'the shared legacy key cannot acknowledge a tenant command');

  const ack = await call('POST', `/api/agent/commands/${dispatched.json.cmd_id}/ack`, {
    key: agentTokenA,
    body: { status: 'executed', source: ENDPOINT, platform: 'windows', result: { message: 'completed' } },
  });
  assert.equal(ack.status, 200);
  assert.equal(ack.json.action.organization, ORG_A);

  const actionReport = await call('POST', '/api/agent/actions', {
    key: agentTokenA,
    body: { id: 'agent-action-id', action: 'terminate_process', status: 'success', source: ENDPOINT, metadata: { cmd_id: dispatched.json.cmd_id } },
  });
  assert.equal(actionReport.status, 201);
  const canonicalActionId = `act_${ENDPOINT}_${dispatched.json.cmd_id}`;
  assert.equal(getAgentStore().actions.filter((action) => action.id === canonicalActionId && action.organization === ORG_A).length, 1,
    'the command acknowledgement and Windows ActionRecord update one dashboard row');

  const pickedUpByB = await call('GET', '/api/agent/commands/pending', { key: agentTokenB });
  assert.equal(pickedUpByB.status, 200);
  assert.equal(pickedUpByB.json.count, 0);
});

test('plans without response actions cannot dispatch or poll commands', async () => {
  responseActionsEnabled = false;
  const dispatch = await call('POST', '/api/agent/commands', {
    admin: true,
    body: { endpoint_id: ENDPOINT, action: 'terminate_process', target: '1234' },
  });
  assert.equal(dispatch.status, 403);
  const poll = await call('GET', '/api/agent/commands/pending', { key: agentTokenA });
  assert.equal(poll.status, 403);
  responseActionsEnabled = true;
});

test('expired tenant credentials cannot poll commands', async () => {
  expires[ORG_A] = new Date(Date.now() - 1000);
  const response = await call('GET', '/api/agent/commands/pending', { key: agentTokenA });
  assert.equal(response.status, 401);
  expires[ORG_A] = new Date(Date.now() + 60_000);
});

test('tenant poll rejects a claimed endpoint different from its credential', async () => {
  const response = await call('GET', '/api/agent/commands/pending', { key: agentTokenA, endpoint: 'another-endpoint' });
  assert.equal(response.status, 403);
});

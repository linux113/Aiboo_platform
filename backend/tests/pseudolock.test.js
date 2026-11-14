// PseudoLock approvals + multi-step playbooks, end to end over HTTP with a
// fake agent on the command channel (no MongoDB, no real PC).   Run: npm test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import express from 'express';
import jwt from 'jsonwebtoken';

process.env.ALERT_STORE = 'memory';
process.env.JWT_SECRET = 'test-secret';
process.env.AGENT_API_KEY = 'test-agent-key';
process.env.APPROVAL_EXPIRY_MINUTES = '30';
process.env.PLAYBOOK_ACTION_TIMEOUT_SECONDS = '5';

const mongoose = (await import('mongoose')).default;
const User = (await import('../models/User.js')).default;
const Organization = (await import('../models/Organization.js')).default;
const Subscription = (await import('../models/Subscription.js')).default;
const Plan = (await import('../models/Plan.js')).default;
const AgentCredential = (await import('../models/AgentCredential.js')).default;
const LEGACY_ORG = '650000000000000000000004';
const COMPANY_A = '650000000000000000000014';
const COMPANY_B = '650000000000000000000015';
const TENANT_AGENT_SECRET = 'T'.repeat(43);
const TENANT_AGENT_TOKEN = `aiboo1_keyid123.${TENANT_AGENT_SECRET}`;
const { default: agentRoutes } = await import('../routes/agent.routes.js');
const { default: plRoutes } = await import('../routes/pseudolock.routes.js');
const { useMemoryStore } = await import('../services/alertStore.js');
const svc = await import('../services/pseudolock.service.js');
const responseRules = await import('../services/responseRules.service.js');
Object.defineProperty(mongoose.connection, 'readyState', { value: 1, configurable: true, writable: true });
const queryDoc = (value) => { const q = { select() { return q; }, then(resolve, reject) { return Promise.resolve(value).then(resolve, reject); } }; return q; };
User.findById = (id) => queryDoc({
  _id: id, name: String(id), email: `${id}@test`, role: ['admin', 'analyst', 'viewer'].includes(String(id)) ? String(id) : String(id).includes('analyst') ? 'analyst' : 'admin', active: true,
  organization: String(id).startsWith('tenant-a') ? COMPANY_A : String(id).startsWith('tenant-b') ? COMPANY_B : LEGACY_ORG,
});
Organization.findById = (id) => queryDoc(String(id) === LEGACY_ORG
  ? { _id: LEGACY_ORG, name: 'Internal Legacy Workspace', slug: 'legacy', status: 'legacy', isLegacy: true }
  : [COMPANY_A, COMPANY_B].includes(String(id))
    ? { _id: id, name: 'Company', slug: String(id), status: 'active', isLegacy: false, subscriptionExpiresAt: new Date(Date.now() + 86400000) }
    : null);
Subscription.findOne = () => queryDoc({ plan: 'test-plan' });
let companyFeatures = { responseActions: true, playbooks: true };
Plan.findById = () => queryDoc({ enabled: true, features: companyFeatures });
AgentCredential.findOne = () => queryDoc({
  _id: '650000000000000000000016', keyId: 'keyid123', secretHash: crypto.createHash('sha256').update(TENANT_AGENT_SECRET).digest('hex'),
  organization: COMPANY_A, endpointId: 'tenant-a-pc', platform: 'windows', status: 'active',
});


// ---- fake agent channel: PC "gorilla" is online and answers every command
const sent = [];
const listeners = new Set();
let failNext = null;   // error text -> next command fails
let silentNext = false; // next command never answered (timeout)
let failAtCall = 0;     // command number N fails with "user not found"
const fakeChannel = {
  dispatch(endpointId, action, target, params) {
    if (endpointId !== 'gorilla') return { ok: false, error: 'not connected' };
    const cmd_id = `cmd_${sent.length + 1}`;
    sent.push({ cmd_id, endpointId, action, target, params });
    const err = failNext || (failAtCall === sent.length ? 'user not found' : null); failNext = null;
    const silent = silentNext; silentNext = false;
    if (!silent) {
      setTimeout(() => {
        for (const fn of listeners) fn({ cmd_id, status: 'received' });
        for (const fn of listeners) fn(err ? { cmd_id, status: 'failed', error: err } : { cmd_id, status: 'executed', result: { message: `${action} ok` } });
      }, 20);
    }
    return { ok: true, cmd_id };
  },
  isOnline: (id) => id === 'gorilla',
  getCommand: () => undefined,
  onAck(fn) { listeners.add(fn); return () => listeners.delete(fn); },
};

let server;
let base;
const events = [];
const token = (role, email = `${role}@test`) => jwt.sign({ id: role, role, email, name: role }, 'test-secret');
const AUTH = {
  admin: token('admin'), analyst: token('analyst'), viewer: token('viewer'), analyst2: token('analyst', 'second@test'),
  tenantA: jwt.sign({ id: 'tenant-a-admin', role: 'admin', email: 'admin@tenant-a.test' }, 'test-secret'),
  tenantB: jwt.sign({ id: 'tenant-b-admin', role: 'admin', email: 'admin@tenant-b.test' }, 'test-secret'),
};
const call = async (method, path, { body, role = 'admin', agent, tenantAgent, authToken } = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (tenantAgent) { headers['x-api-key'] = TENANT_AGENT_TOKEN; headers['x-endpoint-id'] = 'tenant-a-pc'; }
  else if (agent) { headers['x-api-key'] = 'test-agent-key'; headers['x-endpoint-id'] = 'gorilla'; }
  else headers.Authorization = `Bearer ${authToken || AUTH[role]}`;
  const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
};
const gate = (id, { verdict = 'BLOCK', auto, ip = '45.95.147.3', user = 'lalit', ts } = {}) => ({
  gate: 3, event_id: id, verdict, severity: 'high', source: 'gorilla', timestamp: ts || new Date().toISOString(),
  ...(auto === undefined ? {} : { auto_response: auto }),
  metadata: { trigate: {
    pattern: 'brute_force', entity: user, subject: user,
    context: { pattern: 'brute_force', pattern_label: 'Password guessing', src_ip: ip, entity: user, subject: user, description: '6 wrong passwords' },
    trust: { score: 40 }, intent: { score: 80 }, impact: { score: 60 }, risk: { score: 66, level: 'high' },
    recommended: [
      { action: 'block_access', target: ip, text: `Block IP ${ip}` },
      { action: 'restrict_identity', target: user, text: `Disable ${user} for 30 min` },
      { action: 'isolate_asset', target: 'this PC', text: 'Isolate' }, // no IP -> must be skipped
      { action: 'notify_security', target: '', text: 'Tell the team' },
    ],
  } },
});

before(async () => {
  useMemoryStore();
  svc.useMemoryResponseStore();
  svc.initPseudoLock({ agentChannel: fakeChannel, emitter: (ev, data) => events.push({ ev, data }), sweepSeconds: 0 });
  const app = express();
  app.use(express.json());
  app.use('/api/agent', agentRoutes);
  app.use('/api/pseudolock', plRoutes);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { svc.stopPseudoLock(); await new Promise((r) => server.close(r)); });

const settle = (ms = 80) => new Promise((r) => setTimeout(r, ms));
const processGate = async (decision) => {
  await responseRules.onTriGateDecision(decision, {});
  await settle();
};

test('company approvals, playbooks and runs are tenant-isolated and actions use the tenant queue', async () => {
  svc.useMemoryResponseStore();
  sent.length = 0;
  const approval = await call('POST', '/api/pseudolock/approvals', {
    authToken: AUTH.tenantA,
    body: { action: 'block_access', target: '203.0.113.21', endpoint: 'tenant-a-pc', reason: 'test' },
  });
  assert.equal(approval.status, 201);
  assert.equal(approval.data.organization, COMPANY_A);
  assert.ok(events.some((event) => event.ev === 'approval:new' && event.data.organization === COMPANY_A));
  assert.equal((await call('GET', '/api/pseudolock/approvals', { authToken: AUTH.tenantB })).data.length, 0);
  assert.equal((await call('GET', '/api/pseudolock/approvals', { authToken: AUTH.tenantA })).data.length, 1);
  assert.equal((await call('GET', '/api/pseudolock/approvals', { role: 'admin' })).data.length, 0);
  assert.equal((await call('POST', `/api/pseudolock/approvals/${approval.data.id}/approve`, {
    authToken: AUTH.tenantB, body: {},
  })).status, 404, 'another tenant cannot approve the record');
  const decision = await call('POST', `/api/pseudolock/approvals/${approval.data.id}/approve`, {
    authToken: AUTH.tenantA, body: {},
  });
  assert.equal(decision.status, 200);
  assert.equal(decision.data.status, 'running');
  const { getCommandState, finishCommand } = await import('../services/commandQueue.service.js');
  const approvalCommand = getCommandState().commandQueue.find((item) => item.organization === COMPANY_A && item.endpoint_id === 'tenant-a-pc' && item.status === 'queued');
  assert.ok(approvalCommand, 'approved action uses the organization-bound queue');
  assert.equal(sent.length, 0, 'approved tenant action never uses the legacy socket channel');
  finishCommand(approvalCommand.cmd_id, 'executed', null, { message: 'test ack' }, COMPANY_A, 'tenant-a-pc');
  await svc.waitForApprovalExecution(approval.data.id);
  assert.equal((await call('GET', `/api/pseudolock/approvals/${approval.data.id}`, { authToken: AUTH.tenantA })).data.status, 'done');
  assert.equal((await call('GET', `/api/pseudolock/approvals/${approval.data.id}`, { authToken: AUTH.tenantB })).status, 404);

  const created = await call('POST', '/api/pseudolock/playbooks', {
    authToken: AUTH.tenantA,
    body: { name: 'Tenant action', steps: [{ type: 'action', action: 'block_access', target: '{ip}' }] },
  });
  assert.equal(created.status, 201);
  assert.equal(created.data.organization, COMPANY_A);
  assert.equal((await call('GET', `/api/pseudolock/playbooks/${created.data.id}`, { authToken: AUTH.tenantB })).status, 404);

  const rule = await call('POST', '/api/pseudolock/rules', {
    authToken: AUTH.tenantA,
    body: { name: 'Tenant notification', mode: 'notify', conditions: { verdicts: ['block'] } },
  });
  assert.equal(rule.status, 201);
  assert.equal(rule.data.organization, COMPANY_A);
  assert.ok(events.some((event) => event.ev === 'rule:updated' && event.data.organization === COMPANY_A));
  assert.equal((await call('GET', '/api/pseudolock/rules', { authToken: AUTH.tenantB })).data.length, 0);
  assert.equal((await call('GET', '/api/pseudolock/rules', { authToken: AUTH.tenantA })).data.length, 1);

  const run = await call('POST', `/api/pseudolock/playbooks/${created.data.id}/run`, {
    authToken: AUTH.tenantA,
    body: { endpoint: 'tenant-a-pc', vars: { ip: '203.0.113.22' } },
  });
  assert.equal(run.status, 202);
  await settle(40);
  const queued = getCommandState().commandQueue.find((item) => item.organization === COMPANY_A && item.endpoint_id === 'tenant-a-pc' && item.status === 'queued');
  assert.ok(queued, 'tenant action was put into its organization-bound REST queue');
  assert.equal(sent.length, 0, 'tenant action never uses the shared socket channel');
  assert.equal(finishCommand(queued.cmd_id, 'executed', null, { message: 'test ack' }, COMPANY_A, 'tenant-a-pc')?.status, 'executed');
  await svc.waitForRun(run.data.id);
  assert.ok(events.some((event) => event.ev === 'run:updated' && event.data.organization === COMPANY_A));
  assert.equal((await call('GET', `/api/pseudolock/runs/${run.data.id}`, { authToken: AUTH.tenantB })).status, 404);
});

test('company response endpoints enforce response-action and playbook entitlements', async () => {
  companyFeatures = { responseActions: false, playbooks: false };
  assert.equal((await call('GET', '/api/pseudolock/approvals', { authToken: AUTH.tenantA })).status, 403);
  companyFeatures = { responseActions: true, playbooks: false };
  assert.equal((await call('GET', '/api/pseudolock/approvals', { authToken: AUTH.tenantA })).status, 200);
  assert.equal((await call('GET', '/api/pseudolock/playbooks', { authToken: AUTH.tenantA })).status, 403);
  assert.equal((await call('GET', '/api/pseudolock/runs', { authToken: AUTH.tenantA })).status, 403);
  const playbookApproval = await svc.withResponseOrganization(COMPANY_A, () => svc.__saveApprovalForTests({
    id: 'tenant_playbook_approval', status: 'pending', kind: 'playbook_start', playbookId: 'builtin_safe_test',
    endpoint: '', vars: {}, expiresAt: new Date(Date.now() + 60000).toISOString(), history: [],
  }));
  assert.equal((await call('POST', `/api/pseudolock/approvals/${playbookApproval.id}/approve`, {
    authToken: AUTH.tenantA, body: {},
  })).status, 403);

  // A global legacy badge webhook must neither be advertised to nor invoked by a company workspace.
  const previousBadgeWebhook = process.env.BADGE_WEBHOOK_URL;
  process.env.BADGE_WEBHOOK_URL = 'http://127.0.0.1:1/legacy-badge-hook';
  try {
    const badgeStatus = await call('GET', '/api/agent/playbooks/status', { authToken: AUTH.tenantA });
    assert.equal(badgeStatus.data.badge.configured, false);
    const badgeAction = await svc.withResponseOrganization(COMPANY_A, () => svc.executeAction({
      action: 'freeze_badge', target: 'EMP-1042', by: 'tenant admin',
    }));
    assert.equal(badgeAction.ok, false);
    assert.match(badgeAction.error, /not configured for this company workspace/i);
  } finally {
    if (previousBadgeWebhook === undefined) delete process.env.BADGE_WEBHOOK_URL;
    else process.env.BADGE_WEBHOOK_URL = previousBadgeWebhook;
  }
  companyFeatures = { responseActions: true, playbooks: true };
});

test('tenant agent decisions trigger only entitled, organization-scoped response automation', async () => {
  svc.useMemoryResponseStore();
  events.length = 0;
  sent.length = 0;
  companyFeatures = { responseActions: true, playbooks: true };
  const playbook = await call('POST', '/api/pseudolock/playbooks', {
    authToken: AUTH.tenantA,
    body: { name: 'Automated tenant response', steps: [{ type: 'action', action: 'block_access', target: '{ip}' }] },
  });
  assert.equal(playbook.status, 201);
  const rule = await call('POST', '/api/pseudolock/rules', {
    authToken: AUTH.tenantA,
    body: { name: 'Auto malware response', mode: 'auto', playbookId: playbook.data.id,
      conditions: { patterns: ['malware'], verdicts: ['block'], minRisk: 0 } },
  });
  assert.equal(rule.status, 201);

  const malwareDecision = (eventId, ip) => {
    const decision = gate(eventId, { auto: false, ip });
    decision.source = 'tenant-a-pc';
    decision.metadata.trigate.pattern = 'malware';
    decision.metadata.trigate.context.pattern = 'malware';
    return decision;
  };

  // responseActions without playbooks may create ordinary action approvals,
  // but must not execute a stored playbook rule.
  companyFeatures = { responseActions: true, playbooks: false };
  let response = await call('POST', '/api/agent/gate-decision', {
    tenantAgent: true, body: malwareDecision('tenant-no-playbooks', '203.0.113.31'),
  });
  assert.equal(response.status, 200);
  await settle(120);
  let approvals = (await call('GET', '/api/pseudolock/approvals', { authToken: AUTH.tenantA })).data;
  assert.ok(approvals.some((approval) => approval.alertId === 'tg_tenant-no-playbooks' && approval.origin === 'trigate'));
  assert.equal((await import('../services/commandQueue.service.js')).getCommandState().commandQueue.some((item) => item.endpoint_id === 'tenant-a-pc' && item.status === 'queued'), false);

  // With both current entitlements, the matching rule starts the playbook and
  // dispatches only to the REST queue bound to this organization and endpoint.
  companyFeatures = { responseActions: true, playbooks: true };
  response = await call('POST', '/api/agent/gate-decision', {
    tenantAgent: true, body: malwareDecision('tenant-automated', '203.0.113.32'),
  });
  assert.equal(response.status, 200);
  await settle(120);
  const { getCommandState, finishCommand } = await import('../services/commandQueue.service.js');
  const queued = getCommandState().commandQueue.find((item) => item.endpoint_id === 'tenant-a-pc' && item.organization === COMPANY_A && item.status === 'queued');
  assert.ok(queued, 'rule action was queued for the tenant endpoint');
  assert.equal(sent.length, 0, 'tenant response did not use the shared socket channel');
  const runs = (await call('GET', '/api/pseudolock/runs', { authToken: AUTH.tenantA })).data;
  const run = runs.find((candidate) => candidate.ruleId === rule.data.id);
  assert.ok(run);
  finishCommand(queued.cmd_id, 'executed', null, { message: 'test ack' }, COMPANY_A, 'tenant-a-pc');
  await svc.waitForRun(run.id);
  assert.ok(events.some((event) => event.ev === 'run:updated' && event.data.organization === COMPANY_A));
  assert.equal((await call('GET', '/api/pseudolock/runs', { authToken: AUTH.tenantB })).data.length, 0);
  const tenantActivity = (await call('GET', `/api/pseudolock/rules/activity?ruleId=${rule.data.id}`, { authToken: AUTH.tenantA })).data;
  const otherActivity = (await call('GET', `/api/pseudolock/rules/activity?ruleId=${rule.data.id}`, { authToken: AUTH.tenantB })).data;
  assert.ok(tenantActivity.length > 0);
  assert.ok(tenantActivity.every((item) => item.organization === COMPANY_A));
  assert.equal(otherActivity.length, 0);

  // Without responseActions, even default recommendation approvals are skipped.
  companyFeatures = { responseActions: false, playbooks: true };
  response = await call('POST', '/api/agent/gate-decision', {
    tenantAgent: true, body: gate('tenant-no-responses', { auto: false, ip: '203.0.113.33', pattern: 'brute_force' }),
  });
  assert.equal(response.status, 200);
  await settle(80);
  companyFeatures = { responseActions: true, playbooks: true };
  approvals = (await call('GET', '/api/pseudolock/approvals', { authToken: AUTH.tenantA })).data;
  assert.equal(approvals.some((approval) => approval.alertId === 'tg_tenant-no-responses'), false);
});

test('TriGate BLOCK with auto_response OFF creates pending approvals (no duplicates)', async () => {
  await processGate(gate('ev1', { auto: false }));
  let r = await call('GET', '/api/pseudolock/approvals?status=pending');
  assert.equal(r.data.length, 2, 'block IP + restrict account (isolate without IP and notify are skipped)');
  const block = r.data.find((a) => a.action === 'block_access');
  assert.equal(block.target, '45.95.147.3');
  assert.equal(block.endpoint, 'gorilla');
  assert.equal(block.origin, 'trigate');
  assert.equal(block.alertId, 'tg_ev1');
  assert.ok(block.expiresInSeconds > 29 * 60 && block.expiresInSeconds <= 30 * 60);
  assert.equal(r.data.find((a) => a.action === 'restrict_identity').params.minutes, 30);

  // same attack again -> counted, not duplicated
  await processGate(gate('ev2', { auto: false }));
  r = await call('GET', '/api/pseudolock/approvals?status=pending');
  assert.equal(r.data.length, 2);
  assert.equal(r.data.find((a) => a.action === 'block_access').occurrences, 2);
  assert.equal((await call('GET', '/api/pseudolock/approvals/count')).data.pending, 2);

  // The shared legacy API key is not organization-bound. Its gate events must
  // not invoke the global response-rules / approval engine.
  await call('POST', '/api/agent/gate-decision', { agent: true, body: gate('unbound', { auto: false }) });
  await settle();
  assert.equal((await call('GET', '/api/pseudolock/approvals/count')).data.pending, 2);
  assert.ok(events.some((e) => e.ev === 'approval:new'));
});

test('no approval when the agent already acted (auto_response ON), for HOLD, or for old replayed decisions', async () => {
  const before = (await call('GET', '/api/pseudolock/approvals?status=pending')).data.length;
  await processGate(gate('ev3', { auto: true, ip: '45.95.147.4' }));
  await processGate(gate('ev4', { verdict: 'HOLD', ip: '45.95.147.5' }));
  await processGate(gate('ev5', { ip: '45.95.147.6', ts: new Date(Date.now() - 2 * 3600e3).toISOString() }));
  assert.equal((await call('GET', '/api/pseudolock/approvals?status=pending')).data.length, before);
});

test('viewer cannot approve; approve runs the action on the PC and records who approved', async () => {
  const pend = (await call('GET', '/api/pseudolock/approvals?status=pending')).data;
  const block = pend.find((a) => a.action === 'block_access');
  let r = await call('POST', `/api/pseudolock/approvals/${block.id}/approve`, { role: 'viewer' });
  assert.equal(r.status, 403);
  r = await call('POST', `/api/pseudolock/approvals/${block.id}/approve`, { role: 'analyst', body: { note: 'confirmed attack' } });
  assert.equal(r.status, 200);
  assert.equal(r.data.status, 'running');
  await svc.waitForApprovalExecution(block.id);
  r = await call('GET', `/api/pseudolock/approvals/${block.id}`);
  assert.equal(r.data.status, 'done');
  assert.equal(r.data.decidedBy, 'analyst@test');
  assert.equal(r.data.note, 'confirmed attack');
  assert.ok(r.data.decidedAt);
  assert.match(r.data.result, /block_access ok/);
  const cmd = sent.at(-1);
  assert.deepEqual([cmd.endpointId, cmd.action, cmd.target], ['gorilla', 'block_access', '45.95.147.3']);
  // deciding twice is refused
  r = await call('POST', `/api/pseudolock/approvals/${block.id}/reject`);
  assert.equal(r.status, 409);
});

test('reject records who rejected and runs nothing; failed action is shown as failed', async () => {
  const restrict = (await call('GET', '/api/pseudolock/approvals?status=pending')).data.find((a) => a.action === 'restrict_identity');
  const n = sent.length;
  let r = await call('POST', `/api/pseudolock/approvals/${restrict.id}/reject`, { body: { note: 'it was me' } });
  assert.equal(r.data.status, 'rejected');
  assert.equal(r.data.decidedBy, 'admin@test');
  assert.equal(sent.length, n);

  r = await call('POST', '/api/pseudolock/approvals', { body: { action: 'revoke_identity', target: 'guest', endpoint: 'gorilla', reason: 'manual test' } });
  assert.equal(r.status, 201);
  failNext = "Refusing to disable 'guest'";
  await call('POST', `/api/pseudolock/approvals/${r.data.id}/approve`);
  await svc.waitForApprovalExecution(r.data.id);
  const a = (await call('GET', `/api/pseudolock/approvals/${r.data.id}`)).data;
  assert.equal(a.status, 'failed');
  assert.match(a.error, /Refusing/);

  r = await call('POST', '/api/pseudolock/approvals', { body: { action: 'block_access', target: 'not-an-ip', endpoint: 'gorilla' } });
  assert.equal(r.status, 400);
});

test('approvals expire; four-eyes rule when switched on', async () => {
  let r = await call('POST', '/api/pseudolock/approvals', { body: { action: 'block_access', target: '198.51.100.7', endpoint: 'gorilla', expiresMinutes: 1 } });
  const id = r.data.id;
  assert.equal(r.data.expiresMinutes, 1);
  await forceExpire(id); // pretend the minute has passed
  assert.equal(await svc.sweepExpired(), 1);
  r = await call('GET', `/api/pseudolock/approvals/${id}`);
  assert.equal(r.data.status, 'expired');
  assert.match(r.data.history.at(-1).what, /expired/);
  r = await call('POST', `/api/pseudolock/approvals/${id}/approve`);
  assert.equal(r.status, 409);

  process.env.APPROVAL_FOUR_EYES = 'true';
  r = await call('POST', '/api/pseudolock/approvals', { role: 'analyst', body: { action: 'block_access', target: '198.51.100.8', endpoint: 'gorilla' } });
  let d = await call('POST', `/api/pseudolock/approvals/${r.data.id}/approve`, { role: 'analyst' });
  assert.equal(d.status, 403);
  d = await call('POST', `/api/pseudolock/approvals/${r.data.id}/approve`, { role: 'analyst2' });
  assert.equal(d.status, 200);
  await svc.waitForApprovalExecution(r.data.id);
  delete process.env.APPROVAL_FOUR_EYES;
});

// helper: rewrite expiresAt in the memory store via a tiny re-save
async function forceExpire(id) {
  const a = await svc.getApproval(id);
  a.expiresAt = new Date(Date.now() - 1000).toISOString();
  await svc.__saveApprovalForTests(a);
}

test('built-in playbooks are listed with the variables they need and cannot be edited', async () => {
  const r = await call('GET', '/api/pseudolock/playbooks');
  const pg = r.data.find((p) => p.id === 'builtin_password_guessing');
  assert.ok(pg.builtIn);
  assert.deepEqual(pg.variables.sort(), ['ip', 'pc', 'user']);
  assert.equal((await call('PUT', '/api/pseudolock/playbooks/builtin_password_guessing', { body: pg })).status, 400);
  assert.equal((await call('DELETE', '/api/pseudolock/playbooks/builtin_password_guessing')).status, 400);
  const cat = (await call('GET', '/api/pseudolock/catalog')).data;
  assert.ok(cat.actions.find((a) => a.id === 'throttle_segment').params.length === 2);
});

test('run built-in "Contain password guessing": steps run in order on the PC', async () => {
  let r = await call('POST', '/api/pseudolock/playbooks/builtin_password_guessing/run', { body: { endpoint: 'gorilla', vars: { ip: '45.95.147.3' } } });
  assert.equal(r.status, 400);
  assert.match(r.data.error, /User name/);
  r = await call('POST', '/api/pseudolock/playbooks/builtin_password_guessing/run', { body: { endpoint: 'offline-pc', vars: { ip: '45.95.147.3', user: 'guest' } } });
  assert.equal(r.status, 409);
  r = await call('POST', '/api/pseudolock/playbooks/builtin_password_guessing/run', { body: { endpoint: 'gorilla', vars: { ip: 'abc', user: 'guest' } } });
  assert.equal(r.status, 400);
  const n = sent.length;
  r = await call('POST', '/api/pseudolock/playbooks/builtin_password_guessing/run', { role: 'analyst', body: { endpoint: 'gorilla', vars: { ip: '45.95.147.3', user: 'guest' }, alertId: 'tg_ev1' } });
  assert.equal(r.status, 202);
  await svc.waitForRun(r.data.id);
  const run = (await call('GET', `/api/pseudolock/runs/${r.data.id}`)).data;
  assert.equal(run.status, 'done');
  assert.deepEqual(run.steps.map((s) => s.status), ['done', 'done', 'done']);
  assert.deepEqual(sent.slice(n).map((c) => [c.action, c.target, c.params.minutes]), [['block_access', '45.95.147.3', undefined], ['restrict_identity', 'guest', 30]]);
  assert.equal(run.startedBy, 'analyst@test');
  const note = events.filter((e) => e.ev === 'pseudolock:notify').at(-1);
  assert.match(note.data.message, /Blocked 45\.95\.147\.3 and disabled account guest for 30 min on gorilla/);
});

test('a failing step stops the run (or continues when onFailure = continue)', async () => {
  failNext = 'firewall error';
  let r = await call('POST', '/api/pseudolock/playbooks/builtin_password_guessing/run', { body: { endpoint: 'gorilla', vars: { ip: '45.95.147.3', user: 'guest' } } });
  await svc.waitForRun(r.data.id);
  let run = (await call('GET', `/api/pseudolock/runs/${r.data.id}`)).data;
  assert.equal(run.status, 'failed');
  assert.deepEqual(run.steps.map((s) => s.status), ['failed', 'skipped', 'skipped']);
  assert.match(run.message, /firewall error/);

  // step 2 (disable account) has onFailure: continue -> run goes on to step 3
  failAtCall = sent.length + 2;
  r = await call('POST', '/api/pseudolock/playbooks/builtin_password_guessing/run', { body: { endpoint: 'gorilla', vars: { ip: '45.95.147.3', user: 'guest' } } });
  await svc.waitForRun(r.data.id);
  run = (await call('GET', `/api/pseudolock/runs/${r.data.id}`)).data;
  assert.equal(run.status, 'done');
  assert.deepEqual(run.steps.map((s) => s.status), ['done', 'failed', 'done']);
  assert.match(run.steps[1].error, /user not found/);
});

test('timeout when the agent never answers', async () => {
  silentNext = true;
  const r = await call('POST', '/api/pseudolock/playbooks/builtin_stop_program/run', { body: { endpoint: 'gorilla', vars: { ip: '45.95.147.3', pid: '4321' } } });
  await svc.waitForRun(r.data.id);
  const run = (await call('GET', `/api/pseudolock/runs/${r.data.id}`)).data;
  assert.equal(run.status, 'failed');
  assert.match(run.steps[0].error, /No answer from 'gorilla'/);
});

test('editor: create, validate, run with approval step (approve, reject), edit, delete', async () => {
  let r = await call('POST', '/api/pseudolock/playbooks', { body: { name: '', steps: [{ type: 'action', action: 'block_access', target: '{ipaddr}' }] } });
  assert.equal(r.status, 400);
  assert.ok(r.data.errors.some((e) => /Name is required/.test(e)));
  assert.ok(r.data.errors.some((e) => /unknown variable \{ipaddr\}/.test(e)));
  r = await call('POST', '/api/pseudolock/playbooks', { role: 'viewer', body: { name: 'x', steps: [{ type: 'wait', seconds: 1 }] } });
  assert.equal(r.status, 403);

  r = await call('POST', '/api/pseudolock/playbooks', { role: 'analyst', body: {
    name: 'Throttle then block', description: 'test',
    steps: [
      { type: 'action', action: 'throttle_segment', target: '{ip}', params: { kbps: 512, minutes: 10 } },
      { type: 'approval', message: 'Block {ip} on {pc}?', expiresMinutes: 5 },
      { type: 'action', action: 'block_access', target: '{ip}' },
      { type: 'notify', level: 'critical', message: 'done {ip}' },
    ],
  } });
  assert.equal(r.status, 201);
  const pb = r.data;
  assert.equal(pb.createdBy, 'analyst@test');
  assert.deepEqual(pb.variables.sort(), ['ip', 'pc']);

  // run 1: approve
  const n = sent.length;
  r = await call('POST', `/api/pseudolock/playbooks/${pb.id}/run`, { body: { endpoint: 'gorilla', vars: { ip: '203.0.113.9' } } });
  await svc.waitForRun(r.data.id);
  let run = (await call('GET', `/api/pseudolock/runs/${r.data.id}`)).data;
  assert.equal(run.status, 'waiting_approval');
  assert.deepEqual(run.steps.map((s) => s.status), ['done', 'waiting', 'pending', 'pending']);
  assert.deepEqual(sent.slice(n).map((c) => [c.action, c.params]), [['throttle_segment', { kbps: 512, minutes: 10 }]]);
  const gateApr = (await call('GET', '/api/pseudolock/approvals?status=pending')).data.find((a) => a.runId === run.id);
  assert.equal(gateApr.title, 'Block 203.0.113.9 on gorilla?');
  assert.equal(gateApr.expiresMinutes, 5);
  await call('POST', `/api/pseudolock/approvals/${gateApr.id}/approve`, { role: 'analyst2' });
  await settle(30);
  await svc.waitForRun(run.id);
  run = (await call('GET', `/api/pseudolock/runs/${run.id}`)).data;
  assert.equal(run.status, 'done');
  assert.equal(run.steps[1].message, 'Approved by second@test');
  assert.equal(sent.at(-1).action, 'block_access');

  // run 2: reject -> stopped, block never sent
  r = await call('POST', `/api/pseudolock/playbooks/${pb.id}/run`, { body: { endpoint: 'gorilla', vars: { ip: '203.0.113.10' } } });
  await svc.waitForRun(r.data.id);
  const apr2 = (await call('GET', '/api/pseudolock/approvals?status=pending')).data.find((a) => a.runId === r.data.id);
  const m = sent.length;
  await call('POST', `/api/pseudolock/approvals/${apr2.id}/reject`, { body: { note: 'false alarm' } });
  await settle(30);
  run = (await call('GET', `/api/pseudolock/runs/${r.data.id}`)).data;
  assert.equal(run.status, 'stopped');
  assert.deepEqual(run.steps.map((s) => s.status), ['done', 'failed', 'skipped', 'skipped']);
  assert.equal(sent.length, m);

  // run 3: cancel while waiting -> its approval is cancelled
  r = await call('POST', `/api/pseudolock/playbooks/${pb.id}/run`, { body: { endpoint: 'gorilla', vars: { ip: '203.0.113.11' } } });
  await svc.waitForRun(r.data.id);
  const c = await call('POST', `/api/pseudolock/runs/${r.data.id}/cancel`);
  assert.equal(c.data.status, 'cancelled');
  const apr3 = (await call('GET', '/api/pseudolock/approvals?status=all')).data.find((a) => a.runId === r.data.id);
  assert.equal(apr3.status, 'cancelled');

  // edit + disable + delete
  r = await call('PUT', `/api/pseudolock/playbooks/${pb.id}`, { body: { ...pb, name: 'Renamed', enabled: false } });
  assert.equal(r.data.name, 'Renamed');
  assert.equal(r.data.version, 2);
  r = await call('POST', `/api/pseudolock/playbooks/${pb.id}/run`, { body: { endpoint: 'gorilla', vars: { ip: '203.0.113.12' } } });
  assert.equal(r.status, 400);
  assert.equal((await call('DELETE', `/api/pseudolock/playbooks/${pb.id}`)).status, 200);
  assert.equal((await call('GET', `/api/pseudolock/playbooks/${pb.id}`)).status, 404);
  assert.ok((await call('GET', '/api/pseudolock/runs')).data.length >= 3);
});

test('playbook approval step that expires stops the run', async () => {
  const r = await call('POST', '/api/pseudolock/playbooks/builtin_safe_test/run', { body: { endpoint: '' } });
  assert.equal(r.status, 202, 'safe test needs no PC');
  await svc.waitForRun(r.data.id);
  let run = (await call('GET', `/api/pseudolock/runs/${r.data.id}`)).data;
  // the 5 s wait step is still running or already waiting for approval
  for (let i = 0; i < 80 && run.status === 'running'; i++) { await settle(100); run = (await call('GET', `/api/pseudolock/runs/${r.data.id}`)).data; }
  assert.equal(run.status, 'waiting_approval');
  const apr = (await call('GET', '/api/pseudolock/approvals?status=pending')).data.find((a) => a.runId === run.id);
  await forceExpire(apr.id);
  await svc.sweepExpired();
  run = (await call('GET', `/api/pseudolock/runs/${run.id}`)).data;
  assert.equal(run.status, 'stopped');
  assert.match(run.message, /expired/);
});

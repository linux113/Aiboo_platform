// PseudoLock response rules ("WHEN this happens -> THEN run this playbook"),
// end to end over HTTP with a fake agent (no MongoDB, no real PC).   Run: npm test
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import jwt from 'jsonwebtoken';

process.env.ALERT_STORE = 'memory';
process.env.JWT_SECRET = 'test-secret';
process.env.AGENT_API_KEY = 'test-agent-key';
process.env.APPROVAL_EXPIRY_MINUTES = '30';
process.env.PLAYBOOK_ACTION_TIMEOUT_SECONDS = '5';
process.env.OFFICE_HOURS = '9-18';

const { default: agentRoutes } = await import('../routes/agent.routes.js');
const { default: plRoutes } = await import('../routes/pseudolock.routes.js');
const { useMemoryStore } = await import('../services/alertStore.js');
const svc = await import('../services/pseudolock.service.js');
const rules = await import('../services/responseRules.service.js');

const sent = [];
const listeners = new Set();
const fakeChannel = {
  dispatch(endpointId, action, target, params) {
    if (endpointId !== 'gorilla') return { ok: false, error: 'not connected' };
    const cmd_id = `cmd_${sent.length + 1}`;
    sent.push({ cmd_id, endpointId, action, target, params });
    setTimeout(() => {
      for (const fn of listeners) fn({ cmd_id, status: 'received' });
      for (const fn of listeners) fn({ cmd_id, status: 'executed', result: { message: `${action} ok` } });
    }, 10);
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
const AUTH = { admin: token('admin'), analyst: token('analyst'), viewer: token('viewer') };
const call = async (method, path, { body, role = 'admin', agent } = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (agent) { headers['x-api-key'] = 'test-agent-key'; headers['x-endpoint-id'] = 'gorilla'; } else headers.Authorization = `Bearer ${AUTH[role]}`;
  const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
};
let evN = 0;
const gate = ({ verdict = 'BLOCK', ip = '45.95.147.3', user = 'lalit', pattern = 'brute_force', risk = 66, hour = 11, importance = 'normal', ts } = {}) => ({
  gate: 3, event_id: `rv${++evN}`, verdict, severity: 'high', source: 'gorilla', timestamp: ts || new Date().toISOString(), auto_response: false,
  metadata: { trigate: {
    pattern, entity: user, subject: user,
    context: { pattern, pattern_label: 'Password guessing', src_ip: ip, ip_kind: rules.ipKindOf(ip), entity: user, subject: user, local_hour: hour, description: '6 wrong passwords' },
    trust: { score: 40 }, intent: { score: 80 }, impact: { score: 60, importance }, risk: { score: risk, level: 'high' },
    recommended: [
      { action: 'block_access', target: ip, text: `Block IP ${ip}` },
      { action: 'restrict_identity', target: user, text: `Disable ${user}` },
    ],
  } },
});
const send = async (opts) => { await call('POST', '/api/agent/gate-decision', { agent: true, body: gate(opts) }); await settle(); };
const settle = (ms = 120) => new Promise((r) => setTimeout(r, ms));
const RULE = {
  name: 'Stop password guessing', mode: 'auto', playbookId: 'builtin_password_guessing',
  conditions: { patterns: ['brute_force'], minRisk: 55, verdicts: ['block'] }, cooldownMinutes: 30, maxPerHour: 10,
};
const pending = async () => (await call('GET', '/api/pseudolock/approvals?status=pending')).data;
const activity = async () => (await call('GET', '/api/pseudolock/rules/activity')).data;
const allRuns = async () => { const runs = (await call('GET', '/api/pseudolock/runs')).data; for (const r of runs) await svc.waitForRun(r.id); return (await call('GET', '/api/pseudolock/runs')).data; };

before(async () => {
  useMemoryStore();
  svc.initPseudoLock({ agentChannel: fakeChannel, emitter: (ev, data) => events.push({ ev, data }), sweepSeconds: 0 });
  const app = express();
  app.use(express.json());
  app.use('/api/agent', agentRoutes);
  app.use('/api/pseudolock', plRoutes);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
beforeEach(() => { svc.useMemoryResponseStore(); rules.__resetRuleCooldowns(); sent.length = 0; events.length = 0; });
after(async () => { svc.stopPseudoLock(); await new Promise((r) => server.close(r)); });

test('rule editor: validation, viewer cannot save, catalog lists attack types', async () => {
  let r = await call('POST', '/api/pseudolock/rules', { body: { name: '', mode: 'auto' } });
  assert.equal(r.status, 400);
  assert.match(r.data.error, /Name is required/);
  r = await call('POST', '/api/pseudolock/rules', { body: { ...RULE, playbookId: '' } });
  assert.equal(r.status, 400);
  assert.match(r.data.error, /playbook/i);
  r = await call('POST', '/api/pseudolock/rules', { body: { ...RULE, conditions: { verdicts: [] } } });
  assert.match(r.data.error, /verdict/i);
  r = await call('POST', '/api/pseudolock/rules', { role: 'viewer', body: RULE });
  assert.equal(r.status, 403);
  r = await call('POST', '/api/pseudolock/rules', { role: 'analyst', body: RULE });
  assert.equal(r.status, 201);
  assert.equal(r.data.enabled, true);
  assert.equal(r.data.playbookName, 'Contain password guessing');
  assert.equal(r.data.createdBy, 'analyst@test');
  const cat = (await call('GET', '/api/pseudolock/catalog', { role: 'viewer' })).data;
  assert.ok(cat.rules.patterns.some((p) => p.id === 'brute_force'));
  assert.deepEqual(cat.rules.officeHours, [9, 18]);
  // playbook used by a rule cannot be deleted
  const pb = (await call('POST', '/api/pseudolock/playbooks', { body: { name: 'Mine', steps: [{ type: 'notify', level: 'info', message: 'hi' }] } })).data;
  await call('PUT', `/api/pseudolock/rules/${r.data.id}`, { body: { ...RULE, playbookId: pb.id } });
  r = await call('DELETE', `/api/pseudolock/playbooks/${pb.id}`);
  assert.equal(r.status, 409);
  assert.match(r.data.error, /Stop password guessing/);
});

test('auto rule runs the playbook with the IP and user from the attack, no default approvals', async () => {
  await call('POST', '/api/pseudolock/rules', { body: RULE });
  await send();
  const runs = await allRuns();
  assert.equal(runs.length, 1);
  assert.equal(runs[0].startedBy, 'Rule "Stop password guessing"');
  assert.equal(runs[0].trigger, 'rule');
  assert.equal(runs[0].status, 'done');
  assert.deepEqual(sent.map((c) => [c.action, c.target]).slice(0, 2), [['block_access', '45.95.147.3'], ['restrict_identity', 'lalit']]);
  assert.equal((await pending()).length, 0, 'rule took over - TriGate approvals not created');
  const act = await activity();
  assert.equal(act[0].outcome, 'ran');
  assert.equal(act[0].runId, runs[0].id);
  const rule = (await call('GET', '/api/pseudolock/rules')).data[0];
  assert.equal(rule.stats.triggered, 1);
});

test('cooldown: same attack again does not run twice; other IP does', async () => {
  await call('POST', '/api/pseudolock/rules', { body: RULE });
  await send();
  await send();
  await send({ ip: '45.95.147.9' });
  const runs = await allRuns();
  assert.equal(runs.length, 2);
  assert.deepEqual((await activity()).map((e) => e.outcome).sort(), ['cooldown', 'ran', 'ran']);
  assert.equal((await pending()).length, 0);
});

test('not matched -> default TriGate approvals as before (other pattern, low risk, HOLD, other PC)', async () => {
  await call('POST', '/api/pseudolock/rules', { body: { ...RULE, conditions: { ...RULE.conditions, pcs: ['gorilla'] } } });
  await send({ pattern: 'admin_group_add' });
  assert.equal((await allRuns()).length, 0);
  assert.equal((await pending()).length, 2);
  await call('POST', '/api/pseudolock/rules', { body: { ...RULE, name: 'other pc', conditions: { ...RULE.conditions, pcs: ['otherpc'] } } });
  const r = (await call('GET', '/api/pseudolock/rules')).data;
  await call('POST', `/api/pseudolock/rules/${r[0].id}/enabled`, { body: { enabled: false } });
  await send({ ip: '45.95.147.10' });
  assert.equal((await allRuns()).length, 0, 'switched-off rule and rule for another PC do nothing');
});

test('test mode only records "would have run"; notify mode only sends a message', async () => {
  await call('POST', '/api/pseudolock/rules', { body: { ...RULE, testMode: true } });
  await send();
  assert.equal((await allRuns()).length, 0);
  assert.equal(sent.length, 0);
  let act = await activity();
  assert.equal(act[0].outcome, 'test');
  assert.match(act[0].message, /would have: run "Contain password guessing"/);
  assert.equal((await pending()).length, 2, 'test mode does not hide the normal approvals');
  // leaving test mode starts fresh: the same attack now really runs (no cooldown from the test)
  const id = (await call('GET', '/api/pseudolock/rules')).data[0].id;
  await call('PUT', `/api/pseudolock/rules/${id}`, { body: { ...RULE, testMode: false } });
  await send();
  assert.equal((await activity())[0].outcome, 'ran');
  assert.equal((await allRuns()).length, 1);

  svc.useMemoryResponseStore(); sent.length = 0;
  await call('POST', '/api/pseudolock/rules', { body: { ...RULE, mode: 'notify', notifyLevel: 'critical' } });
  await send();
  act = await activity();
  assert.equal(act[0].outcome, 'notified');
  assert.ok(events.some((e) => e.ev === 'pseudolock:notify' && e.data.level === 'critical' && /Stop password guessing/.test(e.data.title)));
  assert.equal(sent.length, 0);
});

test('ask mode: approval -> approve starts the playbook; reject starts nothing', async () => {
  await call('POST', '/api/pseudolock/rules', { body: { ...RULE, mode: 'ask' } });
  await send();
  let p = await pending();
  assert.equal(p.length, 1, 'only the rule approval, not the default ones');
  assert.equal(p[0].kind, 'playbook_start');
  assert.equal(p[0].origin, 'rule');
  assert.match(p[0].title, /Stop password guessing.*Contain password guessing.*gorilla/);
  assert.equal(sent.length, 0);
  let r = await call('POST', `/api/pseudolock/approvals/${p[0].id}/approve`, { role: 'analyst' });
  assert.equal(r.status, 200);
  assert.equal(r.data.status, 'done');
  assert.ok(r.data.startedRunId);
  const runs = await allRuns();
  assert.equal(runs[0].id, r.data.startedRunId);
  assert.equal(runs[0].startedBy, 'Rule "Stop password guessing" (approved by analyst@test)');
  assert.equal(runs[0].status, 'done');

  await send({ ip: '45.95.147.20' });
  p = await pending();
  r = await call('POST', `/api/pseudolock/approvals/${p[0].id}/reject`, { body: { note: 'known tester' } });
  assert.equal(r.data.status, 'rejected');
  assert.equal((await allRuns()).length, 1);
});

test('max runs per hour: above the limit the rule asks instead', async () => {
  await call('POST', '/api/pseudolock/rules', { body: { ...RULE, maxPerHour: 2, cooldownMinutes: 0 } });
  await send({ ip: '45.95.147.31' });
  await send({ ip: '45.95.147.32' });
  await send({ ip: '45.95.147.33' });
  assert.equal((await allRuns()).length, 2);
  const p = await pending();
  assert.equal(p.length, 1);
  assert.equal(p[0].kind, 'playbook_start');
  assert.match(p[0].reason, /Limit of 2 automatic runs per hour/);
  assert.equal((await activity())[0].outcome, 'asked');
  assert.ok(events.some((e) => e.ev === 'pseudolock:notify' && /Limit of 2/.test(e.data.message)));
});

test('missing variable -> skipped (local logon has no IP); first matching rule wins; order can change', async () => {
  await call('POST', '/api/pseudolock/rules', { body: RULE });
  await send({ ip: '' });
  assert.equal((await allRuns()).length, 0);
  assert.equal((await activity())[0].outcome, 'skipped');
  assert.match((await activity())[0].message, /no ip/);
  assert.equal((await pending()).length, 1, 'skipped -> normal approvals (restrict user) still created');

  svc.useMemoryResponseStore(); rules.__resetRuleCooldowns();
  const a = (await call('POST', '/api/pseudolock/rules', { body: { ...RULE, name: 'A notify', mode: 'notify' } })).data;
  const b = (await call('POST', '/api/pseudolock/rules', { body: { ...RULE, name: 'B auto' } })).data;
  await send();
  assert.equal((await activity())[0].ruleName, 'A notify');
  const order = (await call('POST', '/api/pseudolock/rules/reorder', { body: { ids: [b.id, a.id] } })).data;
  assert.deepEqual(order.map((r) => r.name), ['B auto', 'A notify']);
  await send({ ip: '45.95.147.40' });
  assert.equal((await activity())[0].ruleName, 'B auto');
  assert.equal((await activity())[0].outcome, 'ran');
});

test('conditions: internet IP only, office hours, PC importance', async () => {
  const base = { ...RULE, mode: 'notify', cooldownMinutes: 0 };
  const id = (await call('POST', '/api/pseudolock/rules', { body: { ...base, conditions: { ...RULE.conditions, ipKind: 'internet', hours: 'off', importance: ['critical'] } } })).data.id;
  await send({ ip: '192.168.1.50', hour: 23, importance: 'critical' }); // office IP -> no
  await send({ ip: '45.95.147.3', hour: 11, importance: 'critical' });  // office hours -> no
  await send({ ip: '45.95.147.3', hour: 23, importance: 'normal' });    // normal PC -> no
  assert.equal((await activity()).length, 0);
  await send({ ip: '45.95.147.3', hour: 23, importance: 'critical' });
  assert.equal((await activity()).length, 1);
  assert.equal(rules.whyNot({ ipKind: 'office' }, { ipKind: 'private', risk: 0, verdict: 'block' }), null);
  assert.equal(rules.whyNot({ ipKind: 'none' }, { ipKind: 'none', risk: 0, verdict: 'block' }), null);
  await call('DELETE', `/api/pseudolock/rules/${id}`);
  assert.equal((await call('GET', '/api/pseudolock/rules')).data.length, 0);
});

test('old replayed decisions never trigger rules', async () => {
  await call('POST', '/api/pseudolock/rules', { body: RULE });
  await send({ ts: new Date(Date.now() - 3 * 3600e3).toISOString() });
  assert.equal((await activity()).length, 0);
  assert.equal((await allRuns()).length, 0);
});

test('"test against old alerts" counts the TriGate alerts the rule would have matched', async () => {
  useMemoryStore(); // empty alert list
  await send({ ip: '45.95.147.50' });                          // brute force, risk 66
  await send({ ip: '45.95.147.51', pattern: 'log_cleared' });  // other type
  await send({ ip: '45.95.147.52', risk: 40, verdict: 'HOLD' });
  let r = await call('POST', '/api/pseudolock/rules/preview', { role: 'viewer', body: { conditions: RULE.conditions, days: 7 } });
  assert.equal(r.status, 200);
  assert.equal(r.data.checked, 3);
  assert.equal(r.data.matched, 1);
  assert.equal(r.data.samples[0].srcIp, '45.95.147.50');
  assert.ok(r.data.notMatchedBecause.length >= 1);
  r = await call('POST', '/api/pseudolock/rules/preview', { body: { conditions: { verdicts: ['block', 'hold'], minRisk: 35 } } });
  assert.equal(r.data.matched, 3);
  r = await call('POST', '/api/pseudolock/rules/preview', { body: { conditions: { verdicts: ['block'], importance: ['critical'] } } });
  assert.equal(r.data.matched, 0, 'alerts store the PC importance (normal)');
});

// Fixes from the 2 Oct 2026 client test:
//  1. a finding re-sent by the agent keeps its id + time -> no duplicate alert
//  2. findings copied from Windows events do not become extra alerts
//     (TriGate already makes the alert for that event)
//  3. clear-alerts --old-noise picks only the known junk
//  4. CSV: endpoints are two plain numbers (Excel showed "1 / 1" as 01-Jan)
// Runs without MongoDB (in-memory alert store).   Run:  npm test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import jwt from 'jsonwebtoken';

process.env.ALERT_STORE = 'memory';
process.env.JWT_SECRET = 'test-secret';
process.env.AGENT_API_KEY = 'test-agent-key';
process.env.REPORT_TZ = 'Asia/Kolkata';

const { default: agentRoutes } = await import('../routes/agent.routes.js');
const { default: alertRoutes } = await import('../routes/alert.routes.js');
const { default: reportRoutes } = await import('../routes/report.routes.js');
const { useMemoryStore, fromFinding, isWindowsEventFinding, isOldNoiseAlert } = await import('../services/alertStore.js');

let server;
let base;
const ADMIN = jwt.sign({ id: 'a', role: 'admin', email: 'a@test', name: 'a' }, 'test-secret');

const call = async (method, path, { body, agent, raw } = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (agent) { headers['x-api-key'] = 'test-agent-key'; headers['x-endpoint-id'] = 'gorilla'; } else headers.Authorization = `Bearer ${ADMIN}`;
  const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  if (raw) return res;
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
};

before(async () => {
  useMemoryStore();
  const app = express();
  app.use(express.json());
  app.use('/api/agent', agentRoutes);
  app.use('/api/alerts', alertRoutes);
  app.use('/api/reports', reportRoutes);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server?.close());

const wait = () => new Promise((r) => setTimeout(r, 60));
const listAll = async () => (await call('GET', '/api/alerts?days=90&limit=500')).data;

test('re-sent finding keeps the agent id and time: one alert, not two', async () => {
  const f = {
    id: 'evt-1234-abcd', agent_name: 'CyberThreatAgent', threat_type: 'network_intrusion', severity: 'high',
    confidence: 0.85, summary: 'Malicious process detected: evil.exe', actions: [], metadata: {},
    timestamp: '2026-10-02T05:00:00.000Z',
  };
  const r1 = await call('POST', '/api/agent/findings', { body: f, agent: true });
  assert.equal(r1.status, 201);
  assert.equal(r1.data.id, 'evt-1234-abcd');
  assert.equal(r1.data.timestamp, '2026-10-02T05:00:00.000Z');
  const r2 = await call('POST', '/api/agent/findings', { body: f, agent: true });
  assert.equal(r2.status, 200);
  assert.equal(r2.data.duplicate, true);
  await wait();
  const mine = (await listAll()).alerts.filter((a) => a.alertId === 'fd_evt-1234-abcd');
  assert.equal(mine.length, 1);
});

test('bad / future agent time falls back to now; bad id gets a fresh one', async () => {
  const future = new Date(Date.now() + 86400000).toISOString();
  const r = await call('POST', '/api/agent/findings', {
    agent: true,
    body: { id: 'bad id with spaces', agent_name: 'X', threat_type: 'malware', severity: 'medium', summary: 's', timestamp: future },
  });
  assert.equal(r.status, 201);
  assert.match(r.data.id, /^remote_/);
  assert.ok(new Date(r.data.timestamp).getTime() <= Date.now() + 1000);
});

test('findings made from Windows events are not extra alerts', async () => {
  const win = { id: 'w1', severity: 'high', agent_name: 'ZeroTrustAgent', threat_type: 'identity_mismatch',
    summary: '[Windows 4625] Possible password guessing: 5 failed logons on gorilla',
    metadata: { windows_event_id: 4625, source: 'windows_event_log:Security' } };
  assert.equal(isWindowsEventFinding(win), true);
  assert.equal(fromFinding(win), null);
  // summary alone is enough (older agents without metadata)
  assert.equal(fromFinding({ ...win, metadata: {} }), null);
  // a real non-Windows finding still becomes an alert
  const mem = { id: 'm1', severity: 'high', agent_name: 'CyberThreatAgent', threat_type: 'network_intrusion',
    summary: 'Malicious process detected: evil.exe', metadata: { pid: 4 } };
  assert.equal(isWindowsEventFinding(mem), false);
  assert.equal(fromFinding(mem).alertId, 'fd_m1');

  await call('POST', '/api/agent/findings', { body: { ...win, id: 'win-evt-1' }, agent: true });
  await wait();
  assert.equal((await listAll()).alerts.some((a) => a.alertId === 'fd_win-evt-1'), false);
});

test('clear-alerts --old-noise matches only the known junk', () => {
  assert.equal(isOldNoiseAlert({ kind: 'finding', title: 'identity mismatch (ZeroTrustAgent)' }), true);
  assert.equal(isOldNoiseAlert({ kind: 'finding', title: 'identity mismatch (IdentityAgent)' }), true);
  assert.equal(isOldNoiseAlert({ kind: 'finding', title: 'insider threat (CyberThreatAgent)' }), true);
  assert.equal(isOldNoiseAlert({ kind: 'finding', title: 'network intrusion (CyberThreatAgent)', description: '[Windows 4688] x' }), true);
  assert.equal(isOldNoiseAlert({ kind: 'incident', title: '[CORRELATED] Identity compromise with lateral movement' }), true);
  // kept
  assert.equal(isOldNoiseAlert({ kind: 'incident', title: 'Possible attack chain: Persistence -> Privilege Escalation' }), false);
  assert.equal(isOldNoiseAlert({ kind: 'trigate', title: 'Password guessing (many failed logons) - aibootest' }), false);
  assert.equal(isOldNoiseAlert({ kind: 'finding', title: 'network intrusion (CyberThreatAgent)', description: 'Malicious process detected: evil.exe' }), false);
});

test('CSV: endpoints are plain numbers, no "x / y" text Excel turns into a date', async () => {
  for (const type of ['executive', 'risk']) {
    const res = await call('GET', `/api/reports/${type}?format=csv&days=30`, { raw: true });
    assert.equal(res.status, 200);
    const csv = await res.text();
    assert.match(csv, /\r\nEndpoints online,\d+\r\n/);
    assert.match(csv, /\r\nEndpoints known,\d+\r\n/);
    assert.doesNotMatch(csv, /,\d+ \/ \d+\r\n/);
  }
});

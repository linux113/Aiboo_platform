// End-to-end test for alert management, analytics, reports and playbooks.
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
const { default: analyticsRoutes } = await import('../routes/analytics.routes.js');
const { default: reportRoutes } = await import('../routes/report.routes.js');
const { useMemoryStore } = await import('../services/alertStore.js');

let server;
let base;
let badgeServer;
let badgeCalls = [];
const token = (role) => jwt.sign({ id: role, role, email: `${role}@test`, name: role }, 'test-secret');
const AUTH = { admin: token('admin'), analyst: token('analyst'), viewer: token('viewer') };

const call = async (method, path, { body, role, agent, raw } = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (role) headers.Authorization = `Bearer ${AUTH[role]}`;
  if (agent) { headers['x-api-key'] = 'test-agent-key'; headers['x-endpoint-id'] = 'gorilla'; }
  const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  if (raw) return res;
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
};

const gate = (id, verdict, risk, level, pattern = 'brute_force', entity = 'lalit', ip = '45.95.147.3') => ({
  gate: 3, event_id: id, threat_type: 'brute_force', severity: level, verdict, confidence: risk / 100,
  reason: `${verdict} risk ${risk}`, actions: [], source: 'gorilla', timestamp: new Date().toISOString(),
  metadata: { trigate: {
    pattern, entity,
    context: { pattern, pattern_label: 'Password guessing', entity, subject: entity, src_ip: ip, description: '6 wrong passwords', mitre_id: 'T1110', mitre_name: 'Brute Force' },
    trust: { score: 40 }, intent: { score: 80 }, impact: { score: 60 }, risk: { score: risk, level },
    recommended: [{ action: 'block_access', target: ip }],
  } },
});

before(async () => {
  useMemoryStore();
  const app = express();
  app.use(express.json());
  app.use('/api/agent', agentRoutes);
  app.use('/api/alerts', alertRoutes);
  app.use('/api/analytics', analyticsRoutes);
  app.use('/api/reports', reportRoutes);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;

  badgeServer = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => {
      badgeCalls.push({ auth: req.headers.authorization, body: JSON.parse(b || '{}') });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"frozen":true}');
    });
  });
  await new Promise((r) => badgeServer.listen(0, '127.0.0.1', r));
});

after(() => { server?.close(); badgeServer?.close(); });

test('agent data becomes alerts (PASS ignored, HOLD/BLOCK kept, high findings, incidents)', async () => {
  assert.equal((await call('POST', '/api/agent/gate-decision', { agent: true, body: gate('e1', 'pass', 20, 'low') })).status, 200);
  await call('POST', '/api/agent/gate-decision', { agent: true, body: gate('e2', 'hold', 44, 'medium', 'new_user', 'aibootest') });
  await call('POST', '/api/agent/gate-decision', { agent: true, body: gate('e3', 'block', 66, 'high') });
  await call('POST', '/api/agent/gate-decision', { agent: true, body: gate('e3', 'block', 66, 'high') }); // retry
  await call('POST', '/api/agent/findings', { agent: true, body: { agent_name: 'UEBA', threat_type: 'behavioral_anomaly', severity: 'high', confidence: 0.7, summary: 'login at 3am' } });
  await call('POST', '/api/agent/findings', { agent: true, body: { agent_name: 'X', threat_type: 'noise', severity: 'low', summary: 'ignore' } });
  const inc = { alert_id: 'inc_abc', severity: 'high', confidence: 0.8, description: 'Attack chain on lalit. 2 stages', findings: [],
    incident: { stages: [{ key: 'credential_access', label: 'Credential access' }], users: ['lalit'], ips: ['45.95.147.3'], max_risk: 66 } };
  await call('POST', '/api/agent/correlated', { agent: true, body: inc });
  await call('POST', '/api/agent/correlated', { agent: true, body: { ...inc, severity: 'critical', description: 'Attack chain on lalit. 3 stages' } });

  const r = await call('GET', '/api/alerts', { role: 'viewer' });
  assert.equal(r.status, 200);
  assert.equal(r.data.total, 4, JSON.stringify(r.data.alerts.map((a) => a.alertId)));
  const byId = Object.fromEntries(r.data.alerts.map((a) => [a.alertId, a]));
  assert.ok(byId.tg_e2 && byId.tg_e3 && byId.inc_abc);
  assert.equal(byId.tg_e3.occurrences, 2);
  assert.equal(byId.inc_abc.severity, 'critical'); // severity only goes up
  assert.equal(byId.tg_e3.srcIp, '45.95.147.3');
  assert.equal(byId.tg_e3.entity, 'lalit');
  assert.equal(r.data.storage, 'memory');

  const corr = await call('GET', '/api/agent/correlated', { role: 'viewer' });
  assert.equal(corr.data.length, 1); // grown incident replaces the old row
});

test('filters and search', async () => {
  assert.equal((await call('GET', '/api/alerts?kind=trigate', { role: 'viewer' })).data.total, 2);
  const openOnly = await call('GET', '/api/alerts?status=closed', { role: 'viewer' });
  assert.equal(openOnly.data.total, 0);
  assert.equal(openOnly.data.counts.open, 4); // tab counts ignore the status filter
  assert.equal((await call('GET', '/api/alerts?severity=critical', { role: 'viewer' })).data.total, 1);
  assert.equal((await call('GET', '/api/alerts?q=aibootest', { role: 'viewer' })).data.total, 1);
  const s = await call('GET', '/api/alerts?sort=risk', { role: 'viewer' });
  assert.ok(s.data.alerts[0].riskScore >= s.data.alerts[1].riskScore);
});

test('viewer cannot change alerts; analyst can ack / assign / note / close / reopen', async () => {
  assert.equal((await call('POST', '/api/alerts/tg_e3/acknowledge', { role: 'viewer' })).status, 403);
  assert.equal((await call('POST', '/api/alerts/tg_e3/acknowledge')).status, 401);

  let r = await call('POST', '/api/alerts/tg_e3/acknowledge', { role: 'analyst', body: { note: 'looking' } });
  assert.equal(r.status, 200);
  assert.equal(r.data.status, 'acknowledged');
  assert.equal(r.data.assignee, 'analyst'); // auto-assigned to whoever acknowledged
  assert.ok(r.data.acknowledgedAt);

  r = await call('POST', '/api/alerts/tg_e3/assign', { role: 'admin', body: { assignee: 'soc-team' } });
  assert.equal(r.data.assignee, 'soc-team');
  r = await call('POST', '/api/alerts/tg_e3/notes', { role: 'analyst', body: { text: 'IP is on Feodo list' } });
  assert.equal(r.data.notes.length, 2);
  assert.equal((await call('POST', '/api/alerts/tg_e3/notes', { role: 'analyst', body: { text: '  ' } })).status, 400);

  assert.equal((await call('POST', '/api/alerts/tg_e3/close', { role: 'analyst', body: { reason: 'nonsense' } })).status, 400);
  r = await call('POST', '/api/alerts/tg_e3/close', { role: 'analyst', body: { reason: 'resolved', note: 'IP blocked' } });
  assert.equal(r.data.status, 'closed');
  assert.equal(r.data.closeReason, 'resolved');
  r = await call('POST', '/api/alerts/tg_e3/reopen', { role: 'analyst' });
  assert.equal(r.data.status, 'open');
  assert.equal(r.data.closeReason, '');
  r = await call('POST', '/api/alerts/tg_e3/close', { role: 'analyst', body: { reason: 'resolved' } });

  const full = await call('GET', '/api/alerts/tg_e3', { role: 'viewer' });
  assert.deepEqual(full.data.history.map((h) => h.action),
    ['created', 'acknowledged', 'assigned', 'note', 'closed', 'reopened', 'closed']);
  assert.equal((await call('GET', '/api/alerts/nope', { role: 'viewer' })).status, 404);

  const bulk = await call('POST', '/api/alerts/bulk', { role: 'analyst', body: { ids: ['tg_e2', 'nope'], action: 'close', reason: 'false_positive' } });
  assert.equal(bulk.data.updated, 1);
});

test('compliance and agent-status are stored and shown', async () => {
  const report = { checked_at: new Date().toISOString(), score: 62, counts: { pass: 8, fail: 3, warn: 2, unknown: 2 },
    frameworks: { 'ISO 27001:2022': { controls: 14, met: 6, failing: ['A.8.24'], assessed: 12, score: 60 }, 'NIST CSF 2.0': { controls: 15, met: 7, failing: [], assessed: 13, score: 64 } },
    checks: [
      { id: 'disk_encrypted', title: 'System drive is encrypted (BitLocker)', status: 'fail', detail: 'BitLocker off', iso27001: ['A.8.24 Use of cryptography'], nist_csf: ['PR.DS-01'], weight: 2, fix: 'Turn on BitLocker' },
      { id: 'firewall_on', title: 'Windows Firewall is on', status: 'pass', detail: '', iso27001: ['A.8.20 Networks security'], nist_csf: ['PR.IR-01'], weight: 3, fix: '' },
    ] };
  assert.equal((await call('POST', '/api/agent/compliance', { agent: true, body: { foo: 1 } })).status, 400);
  assert.equal((await call('POST', '/api/agent/compliance', { agent: true, body: report })).status, 200);
  const c = await call('GET', '/api/agent/compliance', { role: 'viewer' });
  assert.equal(c.data[0].endpoint, 'gorilla');
  assert.equal(c.data[0].score, 62);

  await call('POST', '/api/agent/agent-status', { agent: true, body: {
    threat_intel: { feed_entries: 1200, matches: 1, scans: 10, feeds: [] }, behaviour: { users: 2, learned: 1, alerts: 0 },
    correlation: { emitted: 1 }, access_control: { restrictions: [], throttles: [{ segment: '45.95.147.0/24' }] }, auto_response: false } });
  const s = await call('GET', '/api/agent/agent-status', { role: 'viewer' });
  assert.equal(s.data[0].threat_intel.feed_entries, 1200);
});

test('analytics overview: KPIs, posture, trend, breakdowns', async () => {
  const r = await call('GET', '/api/analytics/overview?days=7', { role: 'viewer' });
  assert.equal(r.status, 200);
  const a = r.data;
  assert.equal(a.tz, 'Asia/Kolkata');
  assert.equal(a.trend.length, 7);
  assert.equal(a.trend.reduce((s, d) => s + d.total, 0), 4);
  assert.equal(a.kpis.totalAlerts, 4);
  assert.equal(a.kpis.closed, 2);
  assert.equal(a.kpis.falsePositiveRate, 50);
  assert.equal(a.kpis.avgCompliance, 62);
  assert.ok(a.kpis.mttaMinutes !== null && a.kpis.mttrMinutes !== null);
  // open: inc_abc (critical 15) + finding (high 8) = 23; compliance 0.4*38 = 15.2 -> 100-23-15 = 62
  assert.equal(a.posture.score, 62);
  assert.equal(a.intel.feedEntries, 1200);
  assert.equal(a.intel.throttles, 1);
  assert.equal(a.compliance.failing[0].id, 'disk_encrypted');
  assert.equal(a.alerts, undefined); // raw list not sent to the dashboard
  assert.equal((await call('GET', '/api/analytics/trends?days=14&tz=Not/AZone', { role: 'viewer' })).data.tz, 'UTC');
});

test('reports: json, csv (Excel-safe) and pdf for all three types', async () => {
  assert.equal((await call('GET', '/api/reports/foo?format=pdf', { role: 'viewer' })).status, 400);
  assert.equal((await call('GET', '/api/reports/risk?format=doc', { role: 'viewer' })).status, 400);
  assert.equal((await call('GET', '/api/reports/risk?format=pdf')).status, 401);

  const j = await call('GET', '/api/reports/executive?format=json&days=7', { role: 'viewer' });
  assert.equal(j.data.type, 'executive');

  // formula injection: a user name starting with "=" must be neutralised in CSV
  await call('POST', '/api/agent/gate-decision', { agent: true, body: gate('e9', 'block', 80, 'critical', 'brute_force', '=HYPERLINK("x")') });
  const csv = await call('GET', '/api/reports/risk?format=csv&days=7', { role: 'viewer', raw: true });
  assert.equal(csv.status, 200);
  assert.match(csv.headers.get('content-disposition'), /aiboo-risk-report-.*\.csv/);
  const csvText = await csv.text();
  assert.ok(csvText.includes("'=HYPERLINK"), 'formula must be prefixed');
  assert.ok(csvText.includes('Alert ID,First seen'));

  for (const type of ['executive', 'risk', 'compliance']) {
    const res = await call('GET', `/api/reports/${type}?format=pdf&days=7`, { role: 'viewer', raw: true });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/pdf');
    const buf = Buffer.from(await res.arrayBuffer());
    assert.equal(buf.subarray(0, 5).toString(), '%PDF-');
    assert.ok(buf.length > 2000, `${type} pdf too small`);
    if (process.env.SAVE_PDF) (await import('node:fs')).writeFileSync(`${process.env.SAVE_PDF}/${type}.pdf`, buf);
  }
});

test('freeze badge playbook: 501 without webhook, real POST with webhook', async () => {
  delete process.env.BADGE_WEBHOOK_URL;
  assert.equal((await call('GET', '/api/agent/playbooks/status', { role: 'viewer' })).data.badge.configured, false);
  assert.equal((await call('POST', '/api/agent/playbooks/freeze-badge', { role: 'viewer', body: { badge_id: 'B1' } })).status, 403);
  assert.equal((await call('POST', '/api/agent/playbooks/freeze-badge', { role: 'analyst', body: {} })).status, 400);
  const no = await call('POST', '/api/agent/playbooks/freeze-badge', { role: 'analyst', body: { badge_id: 'B1' } });
  assert.equal(no.status, 501);
  assert.match(no.data.error, /BADGE_WEBHOOK_URL/);

  process.env.BADGE_WEBHOOK_URL = `http://127.0.0.1:${badgeServer.address().port}/hook`;
  process.env.BADGE_WEBHOOK_TOKEN = 'tok';
  const ok = await call('POST', '/api/agent/playbooks/freeze-badge', { role: 'analyst', body: { badge_id: 'EMP-1042', reason: 'stolen badge' } });
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  assert.equal(badgeCalls.length, 1);
  assert.equal(badgeCalls[0].auth, 'Bearer tok');
  assert.equal(badgeCalls[0].body.badge_id, 'EMP-1042');
  assert.equal(badgeCalls[0].body.action, 'freeze_badge');
  const actions = await call('GET', '/api/agent/actions', { role: 'viewer' });
  const list = Array.isArray(actions.data) ? actions.data : actions.data.actions || [];
  assert.ok(list.some((x) => x.action === 'freeze_badge' && x.status === 'success'));

  process.env.BADGE_WEBHOOK_URL = 'http://127.0.0.1:1/hook'; // nothing listening
  const bad = await call('POST', '/api/agent/playbooks/freeze-badge', { role: 'analyst', body: { badge_id: 'EMP-1' } });
  assert.equal(bad.status, 502);
  delete process.env.BADGE_WEBHOOK_URL;
});

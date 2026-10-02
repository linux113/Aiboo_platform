// backend/services/alertStore.js
// Alert management: turns agent data into alerts and handles
// acknowledge / assign / close / reopen / notes, with a full history.
//
// Storage: MongoDB (Alert + ComplianceReport models) when connected.
// When MongoDB is not connected (unit tests, or ALERT_STORE=memory) the same
// API works in memory - so the dashboard never breaks because of storage.
import mongoose from 'mongoose';
import Alert from '../models/Alert.js';
import ComplianceReport from '../models/ComplianceReport.js';
import logger from '../utils/logger.js';

export const STATUSES = ['open', 'acknowledged', 'closed'];
export const CLOSE_REASONS = ['resolved', 'false_positive', 'duplicate', 'accepted_risk'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const MAX_MEMORY = 5000;

const clip = (v, n = 500) => String(v ?? '').slice(0, n);
const sev = (v) => (SEVERITIES.includes(String(v || '').toLowerCase()) ? String(v).toLowerCase() : 'medium');
const clone = (o) => JSON.parse(JSON.stringify(o));

// ------------------------------------------------------------------ repos
class MemoryRepo {
  constructor() {
    this.alerts = new Map();
    this.compliance = [];
  }
  async get(alertId) {
    const a = this.alerts.get(alertId);
    return a ? clone(a) : null;
  }
  async insert(doc) {
    if (this.alerts.size >= MAX_MEMORY) {
      const oldest = [...this.alerts.values()].sort((a, b) => new Date(a.lastSeen) - new Date(b.lastSeen))[0];
      if (oldest) this.alerts.delete(oldest.alertId);
    }
    const now = new Date().toISOString();
    const full = { _id: doc.alertId, createdAt: now, updatedAt: now, ...clone(doc) };
    this.alerts.set(doc.alertId, full);
    return clone(full);
  }
  async save(doc) {
    const full = { ...clone(doc), updatedAt: new Date().toISOString() };
    this.alerts.set(doc.alertId, full);
    return clone(full);
  }
  async since(date) {
    const t = date ? new Date(date).getTime() : 0;
    return [...this.alerts.values()].filter((a) => new Date(a.lastSeen).getTime() >= t).map(clone);
  }
  async addCompliance(doc) {
    const full = { _id: `c${Date.now()}${Math.random().toString(36).slice(2, 6)}`, createdAt: new Date().toISOString(), ...clone(doc) };
    this.compliance.unshift(full);
    if (this.compliance.length > 2000) this.compliance.pop();
    return full;
  }
  async complianceSince(date) {
    const t = date ? new Date(date).getTime() : 0;
    return this.compliance.filter((c) => new Date(c.checkedAt).getTime() >= t).map(clone);
  }
}

class MongoRepo {
  async get(alertId) {
    return Alert.findOne({ alertId }).lean();
  }
  async insert(doc) {
    const created = await Alert.create(doc);
    return created.toObject();
  }
  async save(doc) {
    const { _id, createdAt, updatedAt, __v, ...rest } = doc;
    return Alert.findOneAndUpdate({ alertId: doc.alertId }, { $set: rest }, { new: true }).lean();
  }
  async since(date) {
    const q = date ? { lastSeen: { $gte: new Date(date) } } : {};
    return Alert.find(q).sort({ lastSeen: -1 }).limit(20000).lean();
  }
  async addCompliance(doc) {
    return (await ComplianceReport.create(doc)).toObject();
  }
  async complianceSince(date) {
    const q = date ? { checkedAt: { $gte: new Date(date) } } : {};
    return ComplianceReport.find(q).sort({ checkedAt: -1 }).limit(5000).lean();
  }
}

const memoryRepo = new MemoryRepo();
const mongoRepo = new MongoRepo();
let forcedRepo = null;

export const useMemoryStore = () => {
  forcedRepo = new MemoryRepo();
  return forcedRepo;
};

export const repo = () => {
  if (forcedRepo) return forcedRepo;
  if (process.env.ALERT_STORE === 'memory') return memoryRepo;
  return mongoose.connection?.readyState === 1 ? mongoRepo : memoryRepo;
};

export const storageKind = () => (repo() === mongoRepo ? 'mongodb' : 'memory');

// ------------------------------------------------------------- listeners
let emitter = () => {};
export const setAlertEmitter = (fn) => {
  emitter = typeof fn === 'function' ? fn : () => {};
};
const emit = (ev, data) => {
  try {
    emitter(ev, data);
  } catch (err) {
    logger.error(`alert emit failed: ${err.message}`);
  }
};

// --------------------------------------------------------------- mapping
export const fromGateDecision = (d) => {
  const tri = d?.metadata?.trigate || {};
  const ctx = tri.context || {};
  const risk = Number(tri.risk?.score ?? 0);
  const level = sev(tri.risk?.level || d?.severity);
  const verdict = String(d?.verdict || '').toLowerCase();
  if (verdict === 'pass' || risk < 35) return null; // normal activity - not an alert
  const who = ctx.entity || ctx.subject || '';
  return {
    alertId: `tg_${d.event_id}`,
    kind: 'trigate',
    source: clip(d.source || d.endpoint || 'unknown', 120),
    title: clip(`${ctx.pattern_label || d.threat_type || 'TriGate alert'}${who ? ` - ${who}` : ''}`, 200),
    description: clip(ctx.description || d.reason || '', 600),
    severity: level,
    riskScore: risk,
    verdict,
    pattern: clip(tri.pattern || ctx.pattern || '', 80),
    entity: clip(ctx.entity || '', 120),
    subject: clip(ctx.subject || '', 120),
    srcIp: clip(ctx.src_ip || '', 64),
    firstSeen: d.timestamp || new Date().toISOString(),
    data: {
      event_id: d.event_id,
      mitre: ctx.mitre_id ? `${ctx.mitre_id} ${ctx.mitre_name || ''}`.trim() : '',
      trust: tri.trust?.score,
      intent: tri.intent?.score,
      impact: tri.impact?.score,
      recommended: (tri.recommended || []).slice(0, 6),
      // used by PseudoLock response rules ("test against old alerts")
      importance: tri.impact?.importance || null,
      ip_kind: ctx.ip_kind || null,
      local_hour: Number.isInteger(ctx.local_hour) ? ctx.local_hour : null,
    },
  };
};

// A finding made from a Windows Event Log record is a copy of something
// TriGate already scored (TriGate sees every Windows event and makes its own,
// better alert for HOLD/BLOCK). Turning both into alerts doubled the count.
export const isWindowsEventFinding = (f) => {
  const md = f?.metadata || {};
  if (md.windows_event_id !== undefined && md.windows_event_id !== null && md.windows_event_id !== '') return true;
  if (String(md.source || '').startsWith('windows_event_log')) return true;
  return /^\[Windows \d+\]/.test(String(f?.summary || ''));
};

export const fromFinding = (f) => {
  const s = sev(f?.severity);
  if (!['high', 'critical'].includes(s)) return null;
  if (isWindowsEventFinding(f)) return null; // TriGate already covers it
  return {
    alertId: `fd_${f.id}`,
    kind: 'finding',
    source: clip(f.source || 'unknown', 120),
    title: clip(`${String(f.threat_type || 'finding').replace(/_/g, ' ')} (${f.agent_name || 'agent'})`, 200),
    description: clip(f.summary || '', 600),
    severity: s,
    riskScore: Math.round(Number(f.confidence || 0) * 100),
    pattern: clip(f.threat_type || '', 80),
    firstSeen: f.timestamp || new Date().toISOString(),
    data: { agent: f.agent_name, actions: (f.actions || []).slice(0, 6) },
  };
};

// Alerts made before the fixes of 2 Oct 2026 that are known noise:
//  - finding alerts copied from Windows events (TriGate has its own alert)
//  - "identity mismatch (...)" / "insider threat (...)" finding alerts that an
//    old offline-queue file re-sent from September
//  - "[CORRELATED] ..." cards from the old correlation engine (now off)
// Used by `npm run clear-alerts -- --old-noise`.
export const isOldNoiseAlert = (a) => {
  if (!a) return false;
  const title = String(a.title || '');
  if (a.kind === 'finding') {
    if (/^\[Windows \d+\]/.test(String(a.description || ''))) return true;
    return /^(identity mismatch|insider threat) \(/i.test(title);
  }
  if (a.kind === 'incident') return title.startsWith('[CORRELATED]');
  return false;
};

export const fromCorrelated = (c) => {
  const inc = c?.incident || {};
  return {
    alertId: `inc_${String(c.alert_id || '').replace(/^inc_/, '')}`,
    kind: 'incident',
    source: clip(c.source || 'unknown', 120),
    title: clip(String(c.description || 'Correlated incident').split('. ')[0], 200),
    description: clip(c.description || '', 600),
    severity: sev(c.severity),
    riskScore: Number(inc.max_risk ?? Math.round(Number(c.confidence || 0) * 100)),
    pattern: 'correlated_attack',
    entity: clip((inc.users || [])[0] || '', 120),
    srcIp: clip((inc.ips || [])[0] || '', 64),
    firstSeen: c.timestamp || new Date().toISOString(),
    data: {
      stages: (inc.stages || []).map((s) => s.label || s),
      users: inc.users || [],
      ips: inc.ips || [],
      linked: (c.findings || []).length,
    },
  };
};

// --------------------------------------------------------------- upsert
export const ingest = async (mapped, retry = true) => {
  if (!mapped) return null;
  try {
    const r = repo();
    const now = new Date().toISOString();
    const existing = await r.get(mapped.alertId);
    if (!existing) {
      const doc = await r.insert({
        ...mapped,
        status: 'open',
        assignee: '',
        closeReason: '',
        notes: [],
        history: [{ by: 'agent', action: 'created', to: 'open', text: mapped.title, at: now }],
        occurrences: 1,
        lastSeen: now,
      });
      emit('alert:new', doc);
      return doc;
    }
    // same alert sent again (incident grew / retry): refresh details
    const updated = {
      ...existing,
      title: mapped.title || existing.title,
      description: mapped.description || existing.description,
      severity: SEVERITIES.indexOf(mapped.severity) > SEVERITIES.indexOf(existing.severity)
        ? mapped.severity : existing.severity,
      riskScore: Math.max(Number(existing.riskScore || 0), Number(mapped.riskScore || 0)),
      data: { ...(existing.data || {}), ...(mapped.data || {}) },
      occurrences: Number(existing.occurrences || 1) + 1,
      lastSeen: now,
    };
    if (existing.status === 'closed' && mapped.kind === 'incident') {
      updated.status = 'open';
      updated.history = [...(existing.history || []),
        { by: 'agent', action: 'reopened', from: 'closed', to: 'open', text: 'Incident grew after it was closed', at: now }];
    }
    const doc = await r.save(updated);
    emit('alert:updated', doc);
    return doc;
  } catch (err) {
    // same alert inserted twice at the same moment (MongoDB unique id): update instead
    if (retry && err?.code === 11000) return ingest(mapped, false);
    logger.error(`alert ingest failed (${mapped.alertId}): ${err.message}`);
    return null;
  }
};

// --------------------------------------------------------------- actions
const actor = (user) => clip(user?.name || user?.email || 'analyst', 120);

export const changeStatus = async (alertId, status, user, { note = '', reason = '' } = {}) => {
  if (!STATUSES.includes(status)) throw Object.assign(new Error(`status must be one of ${STATUSES.join(', ')}`), { statusCode: 400 });
  if (status === 'closed' && reason && !CLOSE_REASONS.includes(reason)) {
    throw Object.assign(new Error(`reason must be one of ${CLOSE_REASONS.join(', ')}`), { statusCode: 400 });
  }
  const r = repo();
  const a = await r.get(alertId);
  if (!a) throw Object.assign(new Error('Alert not found'), { statusCode: 404 });
  const now = new Date().toISOString();
  const by = actor(user);
  const from = a.status;
  const action = status === 'acknowledged' ? 'acknowledged' : status === 'closed' ? 'closed' : 'reopened';
  a.status = status;
  if (status === 'acknowledged') {
    a.acknowledgedAt = a.acknowledgedAt || now;
    a.acknowledgedBy = a.acknowledgedBy || by;
    if (!a.assignee) a.assignee = by;
  }
  if (status === 'closed') {
    a.closedAt = now;
    a.closedBy = by;
    a.closeReason = reason || 'resolved';
    a.acknowledgedAt = a.acknowledgedAt || now;
    a.acknowledgedBy = a.acknowledgedBy || by;
  }
  if (status === 'open') {
    a.closedAt = null;
    a.closedBy = '';
    a.closeReason = '';
  }
  a.history = [...(a.history || []), { by, action, from, to: status, text: clip(note || reason, 300), at: now }];
  if (note) a.notes = [...(a.notes || []), { by, text: clip(note, 2000), at: now }];
  const doc = await r.save(a);
  emit('alert:updated', doc);
  return doc;
};

export const assign = async (alertId, assignee, user) => {
  const r = repo();
  const a = await r.get(alertId);
  if (!a) throw Object.assign(new Error('Alert not found'), { statusCode: 404 });
  const by = actor(user);
  const to = clip(assignee, 120).trim();
  const now = new Date().toISOString();
  a.history = [...(a.history || []), { by, action: 'assigned', from: a.assignee || '', to, at: now }];
  a.assignee = to;
  const doc = await r.save(a);
  emit('alert:updated', doc);
  return doc;
};

export const addNote = async (alertId, text, user) => {
  const t = clip(text, 2000).trim();
  if (!t) throw Object.assign(new Error('Note text is required'), { statusCode: 400 });
  const r = repo();
  const a = await r.get(alertId);
  if (!a) throw Object.assign(new Error('Alert not found'), { statusCode: 404 });
  const by = actor(user);
  const now = new Date().toISOString();
  a.notes = [...(a.notes || []), { by, text: t, at: now }];
  a.history = [...(a.history || []), { by, action: 'note', text: clip(t, 300), at: now }];
  const doc = await r.save(a);
  emit('alert:updated', doc);
  return doc;
};

export const getAlert = async (alertId) => repo().get(alertId);

// ---------------------------------------------------------------- query
export const listAlerts = async (q = {}) => {
  const days = Math.min(365, Math.max(1, Number(q.days) || 30));
  const since = new Date(Date.now() - days * 86400000);
  let rows = await repo().since(since);
  const pick = (v) => String(v || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
  const st = pick(q.status);
  const sv = pick(q.severity);
  const kd = pick(q.kind);
  if (sv.length) rows = rows.filter((a) => sv.includes(a.severity));
  if (kd.length) rows = rows.filter((a) => kd.includes(a.kind));
  if (q.source) rows = rows.filter((a) => a.source === q.source);
  if (q.assignee === 'unassigned') rows = rows.filter((a) => !a.assignee);
  else if (q.assignee) rows = rows.filter((a) => String(a.assignee).toLowerCase() === String(q.assignee).toLowerCase());
  if (q.q) {
    const needle = String(q.q).toLowerCase();
    rows = rows.filter((a) => [a.title, a.description, a.entity, a.subject, a.srcIp, a.source, a.pattern]
      .some((v) => String(v || '').toLowerCase().includes(needle)));
  }
  // tab counts use every filter except status, so all tabs show real numbers
  const counts = { open: 0, acknowledged: 0, closed: 0 };
  rows.forEach((a) => { counts[a.status] = (counts[a.status] || 0) + 1; });
  if (st.length) rows = rows.filter((a) => st.includes(a.status));
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  const sort = String(q.sort || 'newest');
  rows.sort((a, b) => {
    if (sort === 'severity') return (order[b.severity] - order[a.severity]) || (b.riskScore - a.riskScore);
    if (sort === 'risk') return b.riskScore - a.riskScore;
    if (sort === 'oldest') return new Date(a.lastSeen) - new Date(b.lastSeen);
    return new Date(b.lastSeen) - new Date(a.lastSeen);
  });
  const limit = Math.min(500, Math.max(1, Number(q.limit) || 50));
  const page = Math.max(1, Number(q.page) || 1);
  return {
    total: rows.length,
    page,
    limit,
    counts,
    alerts: rows.slice((page - 1) * limit, page * limit).map(({ history, ...rest }) => ({
      ...rest, historyCount: (history || []).length,
    })),
    storage: storageKind(),
  };
};

export const alertsSince = async (date) => repo().since(date);

// ----------------------------------------------------------- compliance
export const saveCompliance = async (endpoint, body) => {
  const doc = {
    endpoint: clip(endpoint, 120),
    checkedAt: body.checked_at || new Date().toISOString(),
    score: body.score ?? null,
    counts: body.counts || {},
    frameworks: body.frameworks || {},
    checks: Array.isArray(body.checks) ? body.checks.slice(0, 60) : [],
    posture: body.posture || {},
  };
  try {
    return await repo().addCompliance(doc);
  } catch (err) {
    logger.error(`compliance save failed: ${err.message}`);
    return null;
  }
};

export const complianceSince = async (date) => repo().complianceSince(date);

export const latestCompliance = async () => {
  const rows = await repo().complianceSince(new Date(Date.now() - 90 * 86400000));
  const latest = {};
  rows.forEach((r) => {
    const cur = latest[r.endpoint];
    if (!cur || new Date(r.checkedAt) > new Date(cur.checkedAt)) latest[r.endpoint] = r;
  });
  return Object.values(latest).sort((a, b) => String(a.endpoint).localeCompare(String(b.endpoint)));
};

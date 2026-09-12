import express from 'express';
import axios from 'axios';
import { getIO } from '../config/socket.js';
import { protect, authorize } from '../middleware/auth.js';
import logger from '../utils/logger.js';
import AgentEvent from '../models/AgentEvent.js';

const router = express.Router();

// How long we consider an endpoint "live" after its last heartbeat (2 minutes)
const ACTIVE_WINDOW_MS = 2 * 60 * 1000;

// ---- In‑memory store – each item now has a `source` field ----
const store = {
  findings: [],      // each: { ...AgentFinding, source: string, lastSeen?: timestamp }
  correlated: [],
  gateDecisions: [],
  pseudoLocks: {},
  responseLog: [],
  endpoints: {},     // keyed by source, stores last heartbeat
};

const MAX = 200;
const push = (arr, item) => { arr.unshift(item); if (arr.length > MAX) arr.pop(); };

// ---- MongoDB persistence (fire-and-forget; memory stays the primary read path) ----
const persist = (kind, key, data) => {
  if (!key) return;
  AgentEvent.findOneAndUpdate({ kind, key }, { kind, key, data }, { upsert: true })
    .catch((err) => logger.debug(`persist ${kind} skipped: ${err.message}`));
};

// ---- Hydration: once after boot, load the latest items back from MongoDB ----
const hydratePromises = {};
const hydrate = (kind) => {
  if (!hydratePromises[kind]) {
    hydratePromises[kind] = AgentEvent.find({ kind }).sort({ createdAt: -1 }).limit(MAX).lean()
      .then((docs) => {
        if (!docs || docs.length === 0) return;
        if (kind === 'findings' && store.findings.length === 0) {
          store.findings = docs.map((d) => d.data);
        } else if (kind === 'correlated' && store.correlated.length === 0) {
          store.correlated = docs.map((d) => d.data);
        } else if (kind === 'gateDecisions' && store.gateDecisions.length === 0) {
          store.gateDecisions = docs.map((d) => d.data);
        } else if (kind === 'responseLog' && store.responseLog.length === 0) {
          store.responseLog = docs.map((d) => d.data);
        } else if (kind === 'pseudoLocks' && Object.keys(store.pseudoLocks).length === 0) {
          docs.reverse().forEach((d) => { store.pseudoLocks[d.key] = d.data; });
        } else if (kind === 'endpoints') {
          docs.forEach((d) => {
            const ep = d.data;
            const cur = store.endpoints[ep.source];
            if (!cur || new Date(ep.lastSeen) > new Date(cur.lastSeen)) store.endpoints[ep.source] = ep;
          });
        }
        logger.info(`Hydrated ${kind} from MongoDB (${docs.length} items)`);
      })
      .catch((err) => logger.debug(`hydrate ${kind} skipped: ${err.message}`));
  }
  return hydratePromises[kind];
};

const emit = (ev, data) => {
  try {
    getIO().emit(ev, data);
  } catch (err) {
    logger.error(`Socket emit error (${ev}): ${err.message}`);
  }
};

// ---- Helpers ----
const getSource = (req) => {
  // Prefer header, fallback to body.source, then 'unknown'
  return req.headers['x-endpoint-id'] || req.body?.source || 'unknown';
};

// Check if an endpoint is still active based on its lastSeen timestamp
const isActive = (lastSeen) => {
  if (!lastSeen) return false;
  const now = Date.now();
  const diff = now - new Date(lastSeen).getTime();
  return diff < ACTIVE_WINDOW_MS;
};

// ---- API Key Middleware (for agent endpoints) ----
const validateAgentApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || '';
  const expectedKey = process.env.AGENT_API_KEY || 'dev-key-change-in-production';

  if (!apiKey || apiKey !== expectedKey) {
    logger.warn(`Invalid API key attempt from ${req.ip} (source: ${getSource(req)})`);
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  next();
};

// ---- JWT **or** agent API key (the remote agent pushes with X-API-Key only) ----
const protectOrAgentKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || '';
  const expectedKey = process.env.AGENT_API_KEY || 'dev-key-change-in-production';
  if (apiKey && apiKey === expectedKey) return next();
  return protect(req, res, next);
};

// ---- Record endpoint heartbeat ----
const updateEndpointHeartbeat = (source) => {
  if (source && source !== 'unknown') {
    store.endpoints[source] = {
      lastSeen: new Date().toISOString(),
      source,
    };
    persist('endpoint', source, store.endpoints[source]);
  }
};

// ============================================================
//  PUBLIC AGENT ENDPOINTS (used by remote AiBoO agents)
//  All require x-api-key header.
// ============================================================

// POST /api/agent/findings – Agent sends a detection
router.post('/findings', validateAgentApiKey, async (req, res) => {
  try {
    const {
      agent_name,
      threat_type,
      severity,
      confidence,
      summary,
      actions,
      metadata,
    } = req.body;

    const source = getSource(req);
    updateEndpointHeartbeat(source);

    const finding = {
      id: `remote_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      agent_name: agent_name || 'UnknownAgent',
      threat_type,
      severity,
      confidence: confidence || 0.5,
      summary: summary || 'No summary provided',
      actions: actions || [],
      metadata: metadata || {},
      source,
      timestamp: new Date().toISOString(),
    };

    push(store.findings, finding);
    persist('finding', finding.id, finding);
    emit('agent:finding', finding);
    logger.info(`Agent finding from ${source}: ${threat_type} (${severity})`);

    res.status(201).json(finding);
  } catch (error) {
    logger.error(`Error processing agent finding: ${error.message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/agent/heartbeat – Agent keeps alive
router.post('/heartbeat', validateAgentApiKey, (req, res) => {
  const source = getSource(req);
  updateEndpointHeartbeat(source);
  logger.debug(`Heartbeat from ${source}`);
  res.status(200).json({ ok: true, source });
});

// GET /api/agent/sources – List only LIVE endpoints (recent heartbeat)
router.get('/sources', async (req, res) => {
  await hydrate('endpoints');
  const liveSources = Object.values(store.endpoints)
    .filter((ep) => isActive(ep.lastSeen))
    .map((ep) => ep.source)
    .filter((s) => s !== 'unknown');

  // Return unique sources (already unique because they are keys)
  res.json(liveSources);
});

// GET /api/agent/findings – Query findings (filter by source? optional)
router.get('/findings', async (req, res) => {
  await hydrate('findings');
  const { source, limit = 50 } = req.query;
  let result = store.findings;
  if (source) {
    result = result.filter(f => f.source === source);
  }
  res.json(result.slice(0, parseInt(limit, 10)));
});

// GET /api/agent/endpoints – Detailed endpoint status (with active flag)
router.get('/endpoints', async (req, res) => {
  await hydrate('endpoints');
  const now = Date.now();
  const list = Object.values(store.endpoints).map((ep) => ({
    ...ep,
    active: isActive(ep.lastSeen),
  }));
  list.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
  res.json(list);
});

// ============================================================
//  INTERNAL PROTECTED ROUTES (for dashboard, use JWT)
// ============================================================

router.post('/finding', protect, (req, res) => {
  const finding = { ...req.body, id: req.body.id || `local_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`, source: getSource(req) };
  push(store.findings, finding);
  persist('finding', finding.id, finding);
  emit('agent:finding', finding);
  res.json({ ok: true });
});

router.post('/correlated', protectOrAgentKey, (req, res) => {
  const corr = { ...req.body, alert_id: req.body.alert_id || `corr_${Date.now()}` };
  push(store.correlated, corr);
  persist('correlated', corr.alert_id, corr);
  emit('agent:correlated', corr);
  if (['critical', 'high'].includes(corr.severity))
    emit('alert:critical', { ...corr, message: corr.description });
  res.json({ ok: true });
});

router.post('/gate-decision', protectOrAgentKey, (req, res) => {
  const gate = { ...req.body, gate_id: `${req.body.event_id || 'evt'}:${req.body.gate || 0}:${Date.now()}` };
  push(store.gateDecisions, gate);
  persist('gate', gate.gate_id, gate);
  emit('agent:gate', gate);
  res.json({ ok: true });
});

router.post('/pseudo-lock', protectOrAgentKey, (req, res) => {
  store.pseudoLocks[req.body.lock_id] = req.body;
  persist('lock', req.body.lock_id, req.body);
  emit('agent:pseudo-lock', req.body);
  res.json({ ok: true });
});

router.post('/pseudo-lock-restore', protectOrAgentKey, (req, res) => {
  const { lock_id } = req.body;
  if (store.pseudoLocks[lock_id]) {
    store.pseudoLocks[lock_id].active = false;
    persist('lock', lock_id, store.pseudoLocks[lock_id]);
    emit('agent:pseudo-lock-restore', { lock_id });
  }
  res.json({ ok: true });
});

// ---- Internal GET endpoints ----
router.get('/correlated', protect, async (req, res) => { await hydrate('correlated'); res.json(store.correlated.slice(0, 20)); });
router.get('/gate-decisions', protect, (req, res) => res.json(store.gateDecisions.slice(0, 50)));
router.get('/pseudo-locks', protect, async (req, res) => { await hydrate('pseudoLocks'); res.json(Object.values(store.pseudoLocks)); });
router.get('/response-log', protect, async (req, res) => { await hydrate('responseLog'); res.json(store.responseLog.slice(0, 50)); });

// POST /response-log — agents mirror executed containment actions here
router.post('/response-log', validateAgentApiKey, (req, res) => {
  const entry = {
    ...req.body,
    id: req.body.id || `resp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    source: getSource(req),
    loggedAt: new Date().toISOString(),
  };
  push(store.responseLog, entry);
  persist('response', entry.id, entry);
  emit('response:log', entry);
  res.status(201).json({ ok: true, id: entry.id });
});

// ---- GET /identities — per-user rollup derived from live agent findings ----
// Frontend IntelligenceModule expects: { id, user, role, lastSeen, access, anomaly }
router.get('/identities', protect, (req, res) => {
  const byUser = {};
  store.findings.forEach((f) => {
    const uid = f.metadata?.user_id || f.metadata?.entity_id;
    if (!uid || uid === 'unknown') return;
    if (!byUser[uid]) byUser[uid] = { user: uid, findings: 0, anomaly: 0, lastSeen: f.timestamp, access: 'allowed' };
    const row = byUser[uid];
    row.findings += 1;
    if (new Date(f.timestamp) > new Date(row.lastSeen)) row.lastSeen = f.timestamp;
    // confidence of the highest-severity finding doubles as the anomaly signal
    const sevWeight = { low: 0.2, medium: 0.5, high: 0.8, critical: 1.0 }[f.severity] || 0.5;
    row.anomaly = Math.min(1, Math.max(row.anomaly, (f.confidence || 0.5) * sevWeight));
    if (Array.isArray(f.actions)) {
      if (f.actions.includes('revoke_identity') || f.actions.includes('block_access')) row.access = 'revoked';
      else if (f.actions.includes('challenge_mfa') || f.actions.includes('step_up_auth')) row.access = 'challenged';
      else if (row.access !== 'revoked' && f.actions.includes('force_logout')) row.access = 'challenged';
    }
  });
  const rows = Object.entries(byUser).map(([uid, r], i) => ({
    id: i + 1,
    user: r.user,
    role: r.findings > 5 ? 'high-activity' : 'user',
    lastSeen: r.lastSeen,
    access: r.access,
    anomaly: Math.round(r.anomaly * 100) / 100,
  }));
  res.json(rows);
});

router.get('/stats', protect, (req, res) => {
  const sc = {}; const tc = {};
  store.findings.forEach(f => {
    sc[f.severity] = (sc[f.severity] || 0) + 1;
    tc[f.threat_type] = (tc[f.threat_type] || 0) + 1;
  });
  res.json({
    total_findings: store.findings.length,
    correlated_alerts: store.correlated.length,
    active_locks: Object.values(store.pseudoLocks).filter(l => l.active).length,
    by_severity: sc,
    by_type: tc,
    endpoints: Object.keys(store.endpoints).length,
  });
});

// ---- Restore lock (existing) ----
router.post('/pseudo-locks/:lockId/restore', protectOrAgentKey, async (req, res) => {
  const { lockId } = req.params;
  if (store.pseudoLocks[lockId]) {
    store.pseudoLocks[lockId].active = false;
    emit('agent:pseudo-lock-restore', { lock_id: lockId });
  }
  const agentUrl = process.env.AGENT_SERVICE_URL || 'http://localhost:8001';
  axios.post(`${agentUrl}/pseudo-locks/${lockId}/restore`).catch((err) => {
    logger.warn(`Failed to notify agent service: ${err.message}`);
  });
  res.json({ ok: true });
});

// ---- Health check (no auth) ----
router.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// ============================================================
//  SEEDER (demo data)
// ============================================================
export function seedDemoAgentData() {
  if (store.findings.length > 0) return;

  const ago = (ms) => new Date(Date.now() - ms).toISOString();

  const demoFindings = [
    {
      id: 'f001', agent_name: 'CyberThreatAgent', event_id: 'evt_demo_1',
      threat_type: 'network_intrusion', severity: 'critical', confidence: 0.92,
      summary: 'SSH_BRUTE_FORCE detected from 10.0.0.45 on port 22 at 12,500 pkt/s.',
      actions: ['log', 'alert_dashboard', 'isolate_asset', 'pseudo_lock', 'notify_security', 'escalate_soc'],
      metadata: { src_ip: '10.0.0.45', dst_port: 22, signature: 'SSH_BRUTE_FORCE' },
      timestamp: ago(600000),
      source: 'demo',
    },
    {
      id: 'f002', agent_name: 'SurveillanceAgent', event_id: 'evt_demo_2',
      threat_type: 'physical_intrusion', severity: 'high', confidence: 0.78,
      summary: 'Unauthorized access detected in server_room zone.',
      actions: ['log', 'alert_dashboard', 'lock_zone', 'notify_security'],
      metadata: { zone: 'server_room', face_match: false, badge_scan: false },
      timestamp: ago(480000),
      source: 'demo',
    },
    {
      id: 'f003', agent_name: 'IdentityVerificationAgent', event_id: 'evt_demo_3',
      threat_type: 'identity_mismatch', severity: 'high', confidence: 0.84,
      summary: 'Impossible travel detected for user admin_04.',
      actions: ['log', 'alert_dashboard', 'revoke_identity', 'escalate_soc'],
      metadata: { user_id: 'admin_04', location1: 'New York, US', location2: 'Mumbai, IN' },
      timestamp: ago(360000),
      source: 'demo',
    },
    {
      id: 'f004', agent_name: 'PseudoLockAgent', event_id: 'evt_demo_4',
      threat_type: 'network_intrusion', severity: 'critical', confidence: 0.95,
      summary: 'Endpoint 10.0.0.45 pseudo-locked.',
      actions: ['log', 'pseudo_lock', 'alert_dashboard'],
      metadata: { endpoint: '10.0.0.45', decoy: '10.99.0.1' },
      timestamp: ago(300000),
      source: 'demo',
    },
    {
      id: 'f005', agent_name: 'CyberThreatAgent', event_id: 'evt_demo_5',
      threat_type: 'insider_threat', severity: 'high', confidence: 0.71,
      summary: 'User contractor_17 transferred 15.2 GB to external USB off-hours.',
      actions: ['log', 'alert_dashboard', 'revoke_identity', 'escalate_soc'],
      metadata: { user_id: 'contractor_17', volume_gb: 15.2, destination: 'external_usb' },
      timestamp: ago(240000),
      source: 'demo',
    },
    {
      id: 'f006', agent_name: 'SurveillanceAgent', event_id: 'evt_demo_6',
      threat_type: 'physical_intrusion', severity: 'medium', confidence: 0.62,
      summary: 'Tailgating detected at restricted corridor.',
      actions: ['log', 'alert_dashboard', 'notify_security'],
      metadata: { zone: 'restricted_corridor', motion_score: 0.87 },
      timestamp: ago(180000),
      source: 'demo',
    },
  ];

  const demGates = [
    { gate: 1, gate_label: 'Perimeter', event_id: 'evt_demo_1', threat_type: 'network_intrusion', severity: 'critical', verdict: 'escalate', confidence: 0.92, reason: 'SSH_BRUTE_FORCE signature matched.', actions: ['isolate_asset', 'notify_security'], timestamp: ago(600000) },
    { gate: 2, gate_label: 'Behavioural', event_id: 'evt_demo_3', threat_type: 'identity_mismatch', severity: 'high', verdict: 'block', confidence: 0.84, reason: 'Impossible travel confirmed.', actions: ['revoke_identity', 'escalate_soc'], timestamp: ago(360000) },
    { gate: 3, gate_label: 'Adaptive Response', event_id: 'evt_demo_4', threat_type: 'network_intrusion', severity: 'critical', verdict: 'block', confidence: 0.95, reason: 'Attack confirmed. Endpoint pseudo-locked.', actions: ['pseudo_lock', 'escalate_soc', 'notify_security'], timestamp: ago(300000) },
    { gate: 1, gate_label: 'Perimeter', event_id: 'evt_demo_2', threat_type: 'physical_intrusion', severity: 'high', verdict: 'hold', confidence: 0.78, reason: 'Zone access outside hours.', actions: ['lock_zone', 'notify_security'], timestamp: ago(480000) },
    { gate: 2, gate_label: 'Behavioural', event_id: 'evt_demo_2', threat_type: 'physical_intrusion', severity: 'high', verdict: 'block', confidence: 0.85, reason: 'Profile deviation confirmed.', actions: ['lock_zone', 'escalate_soc'], timestamp: ago(470000) },
  ];

  const demCorrelated = [{
    alert_id: 'corr_001', threat_type: 'correlated_attack', severity: 'critical', confidence: 0.94,
    description: 'Coordinated cyber-physical attack detected.',
    actions: ['escalate_soc', 'pseudo_lock', 'lock_zone', 'notify_security', 'revoke_identity'],
    findings: [demoFindings[0], demoFindings[1], demoFindings[2]],
    timestamp: ago(290000),
  }];

  const demLock = {
    lock_id: 'lock_evt_demo_4', event_id: 'evt_demo_4',
    agent: 'PseudoLockAgent', severity: 'critical',
    summary: 'Endpoint 10.0.0.45 isolated.',
    active: true, locked_at: ago(300000),
  };

  demoFindings.forEach(f => push(store.findings, f));
  demGates.forEach(g => push(store.gateDecisions, g));
  demCorrelated.forEach(c => push(store.correlated, c));
  store.pseudoLocks[demLock.lock_id] = demLock;

  // Add demo endpoint with a fresh heartbeat so it appears as "live" initially
  store.endpoints['demo'] = { source: 'demo', lastSeen: new Date().toISOString() };

  logger.info('Demo agent data seeded (with source="demo")');
}

export default router;
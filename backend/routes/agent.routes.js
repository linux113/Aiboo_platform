import express from 'express';
import { getIO } from '../config/socket.js';
import { protect, authorize } from '../middleware/auth.js';
import logger from '../utils/logger.js';

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
  actions: [],       // NEW: response actions for the "Isolation & Termination" tab
};

const MAX = 200;
const ACTIONS_MAX = 500; // Response actions accumulate faster than findings
const push = (arr, item) => { arr.unshift(item); if (arr.length > MAX) arr.pop(); };
// Upsert by id: an action is reported several times as it progresses
// (pending -> success/failed). Keep one row per action, newest state first.
const pushAction = (item) => {
  const idx = store.actions.findIndex((a) => a.id === item.id);
  if (idx !== -1) store.actions.splice(idx, 1);
  store.actions.unshift(item);
  if (store.actions.length > ACTIONS_MAX) store.actions.pop();
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
  return req.headers['x-endpoint-id'] || req.body?.source || 'unknown';
};

const isActive = (lastSeen) => {
  if (!lastSeen) return false;
  const now = Date.now();
  const diff = now - new Date(lastSeen).getTime();
  return diff < ACTIVE_WINDOW_MS;
};

// ---- Action label + containment maps (used to enrich records) ----
const ACTION_LABELS = {
  terminate_process: 'Process Terminated',
  isolate_asset: 'Asset Isolated',
  quarantine_device: 'Device Quarantined',
  pseudo_lock: 'Pseudo-Lock Deployed',
  revoke_identity: 'Identity Revoked',
  block_access: 'Access Blocked',
  lock_zone: 'Zone Locked',
  force_logout: 'Session Forced Logout',
  quarantine_file: 'File Quarantined',
};

const CONTAINMENT_ACTIONS = new Set([
  'isolate_asset',
  'quarantine_device',
  'lock_zone',
  'block_access',
]);

const VALID_ACTION_STATUSES = new Set(['pending', 'success', 'failed', 'active']);

// ---- Normalise an incoming action record ----
const normaliseAction = (raw, source) => {
  const action = String(raw.action || raw.type || 'unknown').toLowerCase().trim();
  const status = VALID_ACTION_STATUSES.has(String(raw.status || '').toLowerCase())
    ? String(raw.status).toLowerCase()
    : 'pending';

  return {
    id: String(raw.id || raw.action_id || `act_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`),
    timestamp: raw.timestamp || new Date().toISOString(),
    received_at: new Date().toISOString(),

    endpoint: raw.endpoint || raw.source || source || 'unknown',
    source: raw.source || raw.endpoint || source || 'unknown',

    action,
    action_label: raw.action_label || ACTION_LABELS[action] || action.replace(/_/g, ' '),
    containment: typeof raw.containment === 'boolean'
      ? raw.containment
      : CONTAINMENT_ACTIONS.has(action),

    target: String(raw.target || ''),
    target_type: String(raw.target_type || 'unknown'),
    status,
    details: String(raw.details || raw.summary || ''),
    reason: String(raw.reason || ''),
    agent: String(raw.agent || raw.agent_name || ''),
    severity: String(raw.severity || 'medium').toLowerCase(),
    triggered_by: String(raw.triggered_by || raw.event_id || ''),
    success: typeof raw.success === 'boolean' ? raw.success : status !== 'failed',
    error: raw.error || null,
    dry_run: !!raw.dry_run,
    retried_from: raw.retried_from || null,
    metadata: raw.metadata && typeof raw.metadata === 'object' ? raw.metadata : {},
  };
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

// ---- Accept EITHER API key OR JWT ----
// Useful for correlated / gate-decision / pseudo-lock endpoints where
// the agent has an API key but no JWT.
const validateAgentOrJWT = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || '';
  const expectedKey = process.env.AGENT_API_KEY || 'dev-key-change-in-production';

  if (apiKey && apiKey === expectedKey) {
    return next();  // Agent with API key → allow
  }
  // Fall back to JWT auth
  return protect(req, res, next);
};

// ---- Record endpoint heartbeat ----
const updateEndpointHeartbeat = (source) => {
  if (source && source !== 'unknown') {
    store.endpoints[source] = {
      lastSeen: new Date().toISOString(),
      source,
    };
  }
};

// ============================================================
//  PUBLIC AGENT ENDPOINTS (used by remote AiBoO agents)
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

// GET /api/agent/sources – List only LIVE endpoints
router.get('/sources', (req, res) => {
  const liveSources = Object.values(store.endpoints)
    .filter((ep) => isActive(ep.lastSeen))
    .map((ep) => ep.source)
    .filter((s) => s !== 'unknown');
  res.json(liveSources);
});

// GET /api/agent/findings – Query findings (filter by source?)
router.get('/findings', (req, res) => {
  const { source, limit = 50 } = req.query;
  let result = store.findings;
  if (source) {
    result = result.filter(f => f.source === source);
  }
  res.json(result.slice(0, parseInt(limit, 10)));
});

// GET /api/agent/endpoints – Detailed endpoint status
router.get('/endpoints', (req, res) => {
  const list = Object.values(store.endpoints).map((ep) => ({
    ...ep,
    active: isActive(ep.lastSeen),
  }));
  list.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
  res.json(list);
});

// ============================================================
//  RESPONSE ACTION ENDPOINTS (Isolation & Termination tab)
// ============================================================

// POST /api/agent/actions – Agent forwards an executed response action
// Accepts either a single action object or an array (offline-queue batch flush)
router.post('/actions', validateAgentOrJWT, (req, res) => {
  try {
    const body = req.body;
    const rawItems = Array.isArray(body)
      ? body
      : Array.isArray(body && body.items)
        ? body.items
        : [body];

    const source = getSource(req);
    updateEndpointHeartbeat(source);

    const stored = [];
    for (const raw of rawItems) {
      if (!raw || typeof raw !== 'object') continue;
      const record = normaliseAction(raw, source);
      pushAction(record);
      stored.push(record);
      emit('agent:action', record);
    }

    logger.info(`Received ${stored.length} action(s) from ${source}`);
    res.status(201).json({ ok: true, received: stored.length, actions: stored });
  } catch (error) {
    logger.error(`Error processing agent action: ${error.message}`);
    res.status(500).json({ ok: false, error: 'Failed to store actions' });
  }
});

// GET /api/agent/actions – Query response actions
// Query params: action, status, endpoint, source, severity, target,
//               since, until, limit, offset, order
router.get('/actions', protect, (req, res) => {
  try {
    const {
      action,
      status,
      endpoint,
      source,
      severity,
      target,
      since,
      until,
      limit = 200,
      offset = 0,
      order = 'desc',
    } = req.query;

    let result = store.actions;

    if (action) {
      const wanted = String(action).split(',').map(s => s.trim().toLowerCase());
      result = result.filter(r => wanted.includes(r.action));
    }
    if (status) {
      const wanted = String(status).split(',').map(s => s.trim().toLowerCase());
      result = result.filter(r => wanted.includes(r.status));
    }
    if (endpoint) result = result.filter(r => r.endpoint === endpoint);
    if (source) result = result.filter(r => r.source === source);
    if (severity) result = result.filter(r => r.severity === String(severity).toLowerCase());
    if (target) {
      const t = String(target).toLowerCase();
      result = result.filter(r => r.target.toLowerCase().includes(t));
    }
    if (since) {
      const cutoff = new Date(since).getTime();
      if (!Number.isNaN(cutoff)) {
        result = result.filter(r => new Date(r.timestamp).getTime() >= cutoff);
      }
    }
    if (until) {
      const cutoff = new Date(until).getTime();
      if (!Number.isNaN(cutoff)) {
        result = result.filter(r => new Date(r.timestamp).getTime() <= cutoff);
      }
    }

    if (String(order).toLowerCase() === 'asc') {
      result = [...result].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    }

    const total = result.length;
    const off = Math.max(parseInt(offset, 10) || 0, 0);
    const lim = Math.min(parseInt(limit, 10) || 200, 1000);
    const page = result.slice(off, off + lim);

    res.json({ ok: true, total, limit: lim, offset: off, count: page.length, actions: page });
  } catch (error) {
    logger.error(`Error querying actions: ${error.message}`);
    res.status(500).json({ ok: false, error: 'Failed to read actions' });
  }
});

// GET /api/agent/actions/stats – Aggregated stats for the actions tab
router.get('/actions/stats', protect, (req, res) => {
  try {
    const windowHours = parseInt(req.query.window || '24', 10) || 24;
    const cutoff = Date.now() - windowHours * 3600 * 1000;

    const scoped = store.actions.filter(
      r => new Date(r.timestamp).getTime() >= cutoff
    );

    const byAction = {};
    const byStatus = { pending: 0, success: 0, failed: 0, active: 0 };
    const byEndpoint = {};
    const bySeverity = { low: 0, medium: 0, high: 0, critical: 0 };
    const timeline = {};

    for (const r of scoped) {
      byAction[r.action] = (byAction[r.action] || 0) + 1;
      byStatus[r.status] = (byStatus[r.status] || 0) + 1;
      byEndpoint[r.endpoint] = (byEndpoint[r.endpoint] || 0) + 1;
      bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1;

      const bucket = r.timestamp.slice(0, 13) + ':00:00Z';
      timeline[bucket] = (timeline[bucket] || 0) + 1;
    }

    const total = scoped.length;
    const succeeded = byStatus.success || 0;
    const failed = byStatus.failed || 0;

    res.json({
      ok: true,
      window_hours: windowHours,
      total,
      by_action: byAction,
      by_status: byStatus,
      by_endpoint: byEndpoint,
      by_severity: bySeverity,
      timeline: Object.entries(timeline)
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([bucket, count]) => ({ bucket, count })),
      success_rate: total ? Number(((succeeded / total) * 100).toFixed(2)) : 0,
      failure_rate: total ? Number(((failed / total) * 100).toFixed(2)) : 0,
      last_action_at: scoped.length
        ? scoped.reduce(
            (latest, r) => (r.timestamp > latest ? r.timestamp : latest),
            scoped[0].timestamp
          )
        : null,
    });
  } catch (error) {
    logger.error(`Error computing action stats: ${error.message}`);
    res.status(500).json({ ok: false, error: 'Failed to compute action stats' });
  }
});

// ============================================================
//  REMOTE COMMAND DISPATCH (Isolation & Termination tab)
//  JWT-only — the dashboard dispatches actions to remote agents.
//  Agents themselves never call these; they connect via Socket.IO
//  namespace /agent-channel (see backend/sockets/agentChannel.js).
// ============================================================

// POST /api/agent/commands – dispatch an action to a specific agent
// Remote actions change the endpoint (kill processes, firewall rules), so
// viewers are not allowed to dispatch them.
router.post('/commands', protect, authorize('admin', 'analyst'), (req, res) => {
  try {
    const { endpoint_id, action, target, params } = req.body || {};

    if (!endpoint_id || !action) {
      return res
        .status(400)
        .json({ ok: false, error: 'endpoint_id and action are required' });
    }

    const channel = req.app.get('agentChannel');
    if (!channel) {
      logger.error('Remote dispatch attempted but agentChannel is not initialized');
      return res
        .status(503)
        .json({ ok: false, error: 'Agent channel not initialized' });
    }

    const result = channel.dispatch(
      String(endpoint_id),
      String(action),
      target ? String(target) : '',
      params && typeof params === 'object' ? params : {}
    );

    if (!result.ok) {
      logger.warn(
        `Remote dispatch failed for ${endpoint_id}: ${result.error}`
      );
      return res.status(404).json(result);
    }

    logger.info(
      `Remote command dispatched: ${action} → ${endpoint_id} (${result.cmd_id})`
    );

    // Broadcast so other dashboard tabs can show the pending command
    emit('command:sent', {
      cmd_id: result.cmd_id,
      endpoint_id,
      action,
      target: target || '',
      sent_at: new Date().toISOString(),
    });

    res.status(202).json(result);
  } catch (error) {
    logger.error(`Error dispatching remote command: ${error.message}`);
    res.status(500).json({ ok: false, error: 'Failed to dispatch command' });
  }
});

// GET /api/agent/commands – list recent remote commands
router.get('/commands', protect, (req, res) => {
  try {
    const channel = req.app.get('agentChannel');
    if (!channel) {
      return res
        .status(503)
        .json({ ok: false, error: 'Agent channel not initialized' });
    }
    const commands = channel.listCommands();
    res.json({ ok: true, count: commands.length, commands });
  } catch (error) {
    logger.error(`Error listing commands: ${error.message}`);
    res.status(500).json({ ok: false, error: 'Failed to list commands' });
  }
});

// GET /api/agent/agents-online – list agents currently connected via WebSocket
router.get('/agents-online', protect, (req, res) => {
  try {
    const channel = req.app.get('agentChannel');
    if (!channel) {
      return res
        .status(503)
        .json({ ok: false, error: 'Agent channel not initialized' });
    }
    const agents = channel.listAgents();
    res.json({ ok: true, count: agents.length, agents });
  } catch (error) {
    logger.error(`Error listing online agents: ${error.message}`);
    res.status(500).json({ ok: false, error: 'Failed to list online agents' });
  }
});

// ============================================================
//  INTERNAL ROUTES (accept API key OR JWT)
// ============================================================

router.post('/finding', validateAgentOrJWT, (req, res) => {
  const finding = { ...req.body, source: getSource(req) };
  updateEndpointHeartbeat(finding.source);
  push(store.findings, finding);
  emit('agent:finding', finding);
  res.json({ ok: true });
});

router.post('/correlated', validateAgentOrJWT, (req, res) => {
  push(store.correlated, req.body);
  emit('agent:correlated', req.body);
  if (['critical', 'high'].includes(req.body.severity))
    emit('alert:critical', { ...req.body, message: req.body.description });
  res.json({ ok: true });
});

router.post('/gate-decision', validateAgentOrJWT, (req, res) => {
  push(store.gateDecisions, req.body);
  emit('agent:gate', req.body);
  res.json({ ok: true });
});

router.post('/pseudo-lock', validateAgentOrJWT, (req, res) => {
  store.pseudoLocks[req.body.lock_id] = req.body;
  emit('agent:pseudo-lock', req.body);
  res.json({ ok: true });
});

// Agent reports that a decoy port was really closed
router.post('/pseudo-lock-restore', validateAgentOrJWT, (req, res) => {
  const { lock_id, restored_at, message, hits } = req.body || {};
  const lock = store.pseudoLocks[lock_id];
  if (lock) {
    lock.active = false;
    lock.restoring = false;
    lock.restored_at = restored_at || new Date().toISOString();
    if (message) lock.restore_message = String(message);
    if (hits !== undefined) lock.hits = hits;
    emit('agent:pseudo-lock-restore', {
      lock_id,
      restored_at: lock.restored_at,
      message: lock.restore_message || '',
    });
  }
  res.json({ ok: true });
});

// ---- Internal GET endpoints ----
router.get('/correlated', protect, (req, res) => res.json(store.correlated.slice(0, 20)));
router.get('/gate-decisions', protect, (req, res) => res.json(store.gateDecisions.slice(0, 50)));
router.get('/pseudo-locks', protect, (req, res) => res.json(Object.values(store.pseudoLocks)));
router.get('/response-log', protect, (req, res) => res.json(store.responseLog.slice(0, 50)));

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
    total_actions: store.actions.length,
    by_severity: sc,
    by_type: tc,
    endpoints: Object.keys(store.endpoints).length,
  });
});

// ---- Restore lock: ask the agent that owns the decoy to close it ----
// The agent closes the real listening port and then reports back via
// POST /pseudo-lock-restore, which flips the lock to "restored".
router.post('/pseudo-locks/:lockId/restore', protect, authorize('admin', 'analyst'), (req, res) => {
  const { lockId } = req.params;
  const lock = store.pseudoLocks[lockId];
  if (!lock) {
    return res.status(404).json({ ok: false, error: `Lock '${lockId}' not found` });
  }
  if (!lock.active) {
    return res.json({ ok: true, already_restored: true });
  }

  const channel = req.app.get('agentChannel');
  const endpoint = lock.source;
  if (channel && endpoint && channel.isOnline(endpoint)) {
    const result = channel.dispatch(endpoint, 'restore_pseudo_lock', lockId, {});
    if (!result.ok) return res.status(404).json(result);
    lock.restoring = true;
    emit('agent:pseudo-lock', lock);
    logger.info(`Restore of ${lockId} dispatched to ${endpoint} (${result.cmd_id})`);
    return res.status(202).json({ ok: true, dispatched: true, cmd_id: result.cmd_id, endpoint });
  }

  // The agent that opened the decoy is not connected. If its process has
  // stopped, the decoy port closed with it; if it is only disconnected,
  // the port stays open until it reconnects or restarts. Say so honestly.
  lock.active = false;
  lock.restoring = false;
  lock.restored_at = new Date().toISOString();
  lock.restore_message =
    `Agent '${endpoint || 'unknown'}' is not connected - cleared on the dashboard only. ` +
    'Decoy ports close automatically when the agent stops.';
  emit('agent:pseudo-lock-restore', {
    lock_id: lockId,
    restored_at: lock.restored_at,
    message: lock.restore_message,
  });
  return res.json({ ok: true, dispatched: false, note: lock.restore_message });
});

// ---- Send Event tab: inject a test event on a connected agent ----
const TEST_EVENT_TYPES = new Set([
  'network_intrusion', 'identity_mismatch', 'physical_intrusion',
  'insider_threat', 'anomalous_behavior', 'correlated_attack',
]);
const TEST_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);

router.post('/test-event', protect, authorize('admin', 'analyst'), (req, res) => {
  const { endpoint_id, event } = req.body || {};
  if (!endpoint_id) {
    return res.status(400).json({ ok: false, error: 'endpoint_id is required' });
  }
  const ev = event && typeof event === 'object' ? event : {};
  const eventType = String(ev.event_type || '').toLowerCase();
  const severity = String(ev.severity || '').toLowerCase();
  if (!TEST_EVENT_TYPES.has(eventType)) {
    return res.status(400).json({ ok: false, error: `Unknown event type '${ev.event_type}'` });
  }
  if (!TEST_SEVERITIES.has(severity)) {
    return res.status(400).json({ ok: false, error: `Unknown severity '${ev.severity}'` });
  }
  const channel = req.app.get('agentChannel');
  if (!channel) {
    return res.status(503).json({ ok: false, error: 'Agent channel not initialized' });
  }
  const spec = {
    source: String(ev.source || 'dashboard-test').slice(0, 64),
    event_type: eventType,
    severity,
    message: String(ev.message || '').slice(0, 500),
    payload: ev.payload && typeof ev.payload === 'object' ? ev.payload : {},
  };
  const result = channel.dispatch(String(endpoint_id), 'inject_test_event', '', { event: spec });
  if (!result.ok) return res.status(404).json(result);
  logger.info(`Test event (${eventType}/${severity}) sent to ${endpoint_id} (${result.cmd_id})`);
  res.status(202).json(result);
});

// ---- Dashboard playbook: Open War Room ----
// Alerts every logged-in dashboard at once (real-time broadcast).
router.post('/war-room', protect, authorize('admin', 'analyst'), (req, res) => {
  const entry = {
    id: `war_${Date.now()}`,
    type: 'war_room',
    opened_by: req.user?.name || req.user?.email || String(req.user?.id || 'unknown'),
    note: String(req.body?.note || '').slice(0, 300),
    timestamp: new Date().toISOString(),
  };
  push(store.responseLog, entry);
  emit('war-room:opened', entry);
  logger.warn(`War room opened by ${entry.opened_by}${entry.note ? `: ${entry.note}` : ''}`);
  res.status(201).json({ ok: true, ...entry });
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

  // Demo response actions for the "Isolation & Termination" tab
  const demoActions = [
    {
      id: 'act_demo_1', action: 'terminate_process', target: 'powershell.exe (PID: 1234)',
      target_type: 'process', status: 'success', details: 'Killed suspicious process',
      reason: 'Encoded PowerShell payload detected', agent: 'RealResponseEngine',
      severity: 'critical', triggered_by: 'evt_demo_1', success: true,
      endpoint: 'gorilla', source: 'gorilla', timestamp: ago(32000),
      metadata: { pid: 1234, process_name: 'powershell.exe' },
    },
    {
      id: 'act_demo_2', action: 'isolate_asset', target: '203.0.113.100',
      target_type: 'ip', status: 'success', details: 'Network isolation via firewall',
      reason: 'Outbound C2 traffic confirmed', agent: 'RealResponseEngine',
      severity: 'critical', triggered_by: 'evt_demo_1', success: true,
      endpoint: 'gorilla', source: 'gorilla', timestamp: ago(45000),
      metadata: { src_ip: '203.0.113.100' },
    },
    {
      id: 'act_demo_3', action: 'quarantine_device', target: 'DEV-ABC123',
      target_type: 'device', status: 'success', details: 'Device moved to quarantine VLAN',
      reason: 'Compliance policy violation', agent: 'RealResponseEngine',
      severity: 'high', triggered_by: 'evt_demo_2', success: true,
      endpoint: 'friend-pc', source: 'friend-pc', timestamp: ago(60000),
      metadata: { device_id: 'DEV-ABC123', vlan: 999 },
    },
    {
      id: 'act_demo_4', action: 'pseudo_lock', target: 'alice_demo',
      target_type: 'identity', status: 'active', details: 'Decoy deployed at decoy-xyz.internal:45678',
      reason: 'Attacker session trapped in decoy', agent: 'RealResponseEngine',
      severity: 'high', triggered_by: 'evt_demo_4', success: true,
      endpoint: 'gorilla', source: 'gorilla', timestamp: ago(90000),
      metadata: { lock_id: 'lock_evt_demo_4', decoy_host: 'decoy-xyz.internal', decoy_port: 45678 },
    },
    {
      id: 'act_demo_5', action: 'revoke_identity', target: 'admin_04',
      target_type: 'identity', status: 'success', details: 'Identity revoked via Azure AD',
      reason: 'Impossible travel', agent: 'RealResponseEngine',
      severity: 'high', triggered_by: 'evt_demo_3', success: true,
      endpoint: 'gorilla', source: 'gorilla', timestamp: ago(120000),
      metadata: { provider: 'azure_ad' },
    },
    {
      id: 'act_demo_6', action: 'block_access', target: '10.0.0.45',
      target_type: 'ip', status: 'failed', details: '',
      reason: 'Firewall policy rejected rule', agent: 'RealResponseEngine',
      severity: 'critical', triggered_by: 'evt_demo_1', success: false,
      error: 'Access denied: requires elevated privileges',
      endpoint: 'gorilla', source: 'gorilla', timestamp: ago(150000),
      metadata: { src_ip: '10.0.0.45' },
    },
    {
      id: 'act_demo_7', action: 'force_logout', target: 'contractor_17',
      target_type: 'identity', status: 'success', details: 'Session terminated',
      reason: 'Insider threat — off-hours exfiltration', agent: 'RealResponseEngine',
      severity: 'high', triggered_by: 'evt_demo_5', success: true,
      endpoint: 'friend-pc', source: 'friend-pc', timestamp: ago(200000),
      metadata: { session_id: 'sess_9f3a2b' },
    },
  ];

  demoFindings.forEach(f => push(store.findings, f));
  demGates.forEach(g => push(store.gateDecisions, g));
  demCorrelated.forEach(c => push(store.correlated, c));
  store.pseudoLocks[demLock.lock_id] = demLock;

  // Normalise and store demo actions
  demoActions.forEach(a => pushAction(normaliseAction(a, a.source)));

  // Demo endpoint with a fresh heartbeat
  store.endpoints['demo'] = { source: 'demo', lastSeen: new Date().toISOString() };

  logger.info('Demo agent data seeded (with source="demo")');
}

export default router;
import express from 'express';
import { getIO } from '../config/socket.js';
import { protect, authorize } from '../middleware/auth.js';
import { requireOrganization, requirePlanFeature } from '../middleware/tenant.js';
import { validateTenantAgentCredential, validateTenantAgentCommand, validateTenantAgentHeartbeat } from '../middleware/agentTenantAuth.js';
import { getAgentPlanFeatures } from '../services/agentCredential.service.js';
import logger from '../utils/logger.js';
import { IMPORTANCE_LEVELS } from '../sockets/agentChannel.js';
import {
  ingest as ingestAlert, fromFinding, fromGateDecision, fromCorrelated,
  saveCompliance, latestCompliance, setAlertEmitter,
} from '../services/alertStore.js';
import { badgeConfigured } from '../services/badge.service.js';
import { onTriGateDecision } from '../services/responseRules.service.js';
import { approvalsFromDecision, withResponseOrganization } from '../services/pseudolock.service.js';
import {
  getCommandState, queueCommand as queueRestCommand,
  takePendingCommands, finishCommand as finishQueuedCommand, findCommand,
} from '../services/commandQueue.service.js';

const router = express.Router();
const tenantUser = [protect, requireOrganization];
const belongsToTenant = (row, organizationId, isLegacy = false) =>
  String(row?.organization || '') === String(organizationId || '') || (isLegacy && !row?.organization);
const tenantUnavailable = (req, res) => res.status(503).json({
  ok: false,
  error: 'This operation is not yet enabled for company endpoints',
});

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
  importance: {},    // TriGate: endpoint -> low|normal|high|critical (last known)
  agentStatus: {},   // endpoint -> latest agent-status report (threat intel, behaviour, ...)
  compliance: {},    // endpoint -> latest compliance report
  // Remote commands for agents that CANNOT keep a Socket.IO connection open
  // (the Linux Sentinel polls over HTTPS). Windows agents keep using the
  // socket channel; both paths share the queue in services/commandQueue.service.js
  // so approvals and playbooks can reach REST agents too.
  commandQueue: getCommandState().commandQueue,
  commandHistory: getCommandState().commandHistory,
};

// Read-only view used by analytics / reports
export const getAgentStore = () => store;

const MAX = 200;
const ACTIONS_MAX = 500; // Response actions accumulate faster than findings
const push = (arr, item) => { arr.unshift(item); if (arr.length > MAX) arr.pop(); };
const endpointKey = (source, organizationId = null) => organizationId ? `${organizationId}::${source}` : source;
// Upsert by id: an action is reported several times as it progresses
// (pending -> success/failed). Keep one row per action, newest state first.
const pushAction = (item) => {
  const idx = store.actions.findIndex((a) => a.id === item.id && String(a.organization || '') === String(item.organization || ''));
  if (idx !== -1) store.actions.splice(idx, 1);
  store.actions.unshift(item);
  if (store.actions.length > ACTIONS_MAX) store.actions.pop();
};

const emit = (ev, data, organizationId = null) => {
  // Agent records without a verified tenant must not be broadcast to every
  // company's dashboard. Legacy/unassigned ingestion is retained for review,
  // but waits for tenant assignment before live delivery.
  if (!organizationId) return;
  try {
    getIO().to(`org:${organizationId}`).emit(ev, data);
  } catch (err) {
    logger.error(`Socket emit error (${ev}): ${err.message}`);
  }
};
// Alert management pushes alert:new / alert:updated to every dashboard
setAlertEmitter(emit);

// ---- Helpers ----
const getSource = (req) => {
  return req.endpointId || req.headers['x-endpoint-id'] || req.body?.source || 'unknown';
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
  restrict_identity: 'Account Restricted (temporary)',
  lift_restriction: 'Account Restriction Lifted',
  throttle_segment: 'Network Segment Throttled',
  remove_throttle: 'Throttle Removed',
  revoke_session: 'Sessions Logged Off',
  step_up_auth: 'Screen Locked (re-authenticate)',
  challenge_mfa: 'Screen Locked (re-authenticate)',
};

const CONTAINMENT_ACTIONS = new Set([
  'isolate_asset',
  'quarantine_device',
  'lock_zone',
  'block_access',
]);

const VALID_ACTION_STATUSES = new Set(['pending', 'success', 'failed', 'active']);

// ---- Normalise an incoming action record ----
const normaliseAction = (raw, source, organizationId = null) => {
  const action = String(raw.action || raw.type || 'unknown').toLowerCase().trim();
  const status = VALID_ACTION_STATUSES.has(String(raw.status || '').toLowerCase())
    ? String(raw.status).toLowerCase()
    : 'pending';

  return {
    id: String(raw.metadata?.cmd_id ? `act_${raw.source || raw.endpoint || source || 'unknown'}_${raw.metadata.cmd_id}` : (raw.id || raw.action_id || `act_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`)),
    timestamp: raw.timestamp || new Date().toISOString(),
    received_at: new Date().toISOString(),

    endpoint: raw.endpoint || raw.source || source || 'unknown',
    source: raw.source || raw.endpoint || source || 'unknown',
    ...(organizationId ? { organization: organizationId } : {}),

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
  if (String(apiKey).startsWith('aiboo1_')) return validateTenantAgentCredential(req, res, next);
  const expectedKey = process.env.AGENT_API_KEY || 'dev-key-change-in-production';
  if (apiKey && apiKey === expectedKey) return next();
  return protect(req, res, next);
};

// Old shared-key agents remain available for legacy migration. New company
// endpoints authenticate only through their individual tenant-bound key.
const validateAgentApiKeyOrTenant = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || '';
  if (String(apiKey).startsWith('aiboo1_')) return validateTenantAgentCredential(req, res, next);
  return validateAgentApiKey(req, res, next);
};

const validateAgentCommandKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || '';
  if (String(apiKey).startsWith('aiboo1_')) return validateTenantAgentCommand(req, res, next);
  return validateAgentApiKey(req, res, next);
};

// ---- Record endpoint heartbeat ----
// platform is optional ('windows' | 'linux' | 'darwin'); it is only replaced
// when the agent sends one, so a Windows agent that never sends it keeps its
// earlier value (or stays unknown).
const updateEndpointHeartbeat = (source, platform, organizationId = null) => {
  if (source && source !== 'unknown') {
    const key = endpointKey(source, organizationId);
    const prev = store.endpoints[key] || {};
    const pl = String(platform || '').toLowerCase().trim();
    store.endpoints[key] = {
      ...prev,
      lastSeen: new Date().toISOString(),
      source,
      ...(organizationId ? { organization: organizationId } : {}),
      platform: ['windows', 'linux', 'darwin', 'freebsd'].includes(pl) ? pl : (prev.platform || ''),
    };
  }
};

// Agent clock time if it is a real date and not in the future; else now.
const validAgentTime = (value) => {
  const t = value ? new Date(value).getTime() : NaN;
  const now = Date.now();
  return Number.isFinite(t) && t <= now + 5 * 60 * 1000 ? new Date(t).toISOString() : new Date(now).toISOString();
};

// ============================================================
//  PUBLIC AGENT ENDPOINTS (used by remote AiBoO agents)
// ============================================================

// POST /api/agent/findings – Agent sends a detection
router.post('/findings', validateAgentApiKeyOrTenant, async (req, res) => {
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
    const platform = req.body.platform || metadata?.platform || metadata?.os;
    updateEndpointHeartbeat(source, platform, req.organizationId);

    // Keep the agent's own id and time when they look valid. Before, every
    // finding got a new random id + "now", so a finding re-sent from the
    // agent's offline queue showed up again as a brand-new alert.
    const agentId = String(req.body.id || '');
    const id = /^[A-Za-z0-9_.:-]{4,100}$/.test(agentId)
      ? agentId
      : `remote_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    if (store.findings.some((f) => f.id === id)) {
      return res.status(200).json({ ok: true, duplicate: true, id });
    }

    const finding = {
      id,
      ...(req.organizationId ? { organization: req.organizationId } : {}),
      agent_name: agent_name || 'UnknownAgent',
      threat_type,
      severity,
      confidence: confidence || 0.5,
      summary: summary || 'No summary provided',
      actions: actions || [],
      metadata: metadata || {},
      platform: store.endpoints[endpointKey(source, req.organizationId)]?.platform || '',
      source,
      timestamp: validAgentTime(req.body.timestamp),
    };

    push(store.findings, finding);
    emit('agent:finding', finding, req.organizationId);
    logger.info(`Agent finding from ${source}: ${threat_type} (${severity})`);
    ingestAlert(fromFinding(finding), true, req.organizationId); // high/critical -> Alert Management

    res.status(201).json(finding);
  } catch (error) {
    logger.error(`Error processing agent finding: ${error.message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Minimal license heartbeat remains callable after expiry. It carries no finding
// or command payload; agents must pause non-heartbeat work when active is false.
router.post('/license-heartbeat', validateTenantAgentHeartbeat, (req, res) => {
  updateEndpointHeartbeat(req.endpointId, req.body?.platform || req.agent.platform, req.organizationId);
  res.status(200).json({
    ok: true,
    endpointId: req.endpointId,
    organizationId: req.organizationId,
    active: req.agent.subscriptionActive,
    access: req.agent.subscriptionActive ? 'active' : 'restricted',
    expiresAt: req.agent.subscriptionExpiresAt,
    features: req.agent.features || {},
    checkedAt: new Date().toISOString(),
  });
});

// POST /api/agent/heartbeat – legacy/shared-key heartbeat
router.post('/heartbeat', validateAgentApiKeyOrTenant, (req, res) => {
  const source = getSource(req);
  const platform = req.body?.platform || req.body?.os;
  updateEndpointHeartbeat(source, platform, req.organizationId);
  logger.debug(`Heartbeat from ${source}${platform ? ` (${platform})` : ''}`);
  res.status(200).json({
    ok: true,
    source,
    platform: store.endpoints[endpointKey(source, req.organizationId)]?.platform || '',
    ...(req.agent ? { active: req.agent.subscriptionActive, expiresAt: req.agent.subscriptionExpiresAt } : {}),
  });
});

// GET /api/agent/sources – List only LIVE endpoints
router.get('/sources', ...tenantUser, (req, res) => {
  const liveSources = Object.values(store.endpoints)
    .filter((ep) => belongsToTenant(ep, req.organizationId, req.organization?.isLegacy) && isActive(ep.lastSeen))
    .map((ep) => ep.source)
    .filter((s) => s !== 'unknown');
  res.json(liveSources);
});

// GET /api/agent/findings – Query findings (filter by source?)
router.get('/findings', ...tenantUser, (req, res) => {
  const { source, limit = 50 } = req.query;
  let result = store.findings.filter((finding) => belongsToTenant(finding, req.organizationId, req.organization?.isLegacy));
  if (source) {
    result = result.filter(f => f.source === source);
  }
  res.json(result.slice(0, parseInt(limit, 10)));
});

// GET /api/agent/endpoints – Detailed endpoint status
// Includes agents connected over the command channel (even before their
// first finding) and the TriGate importance of each PC.
router.get('/endpoints', ...tenantUser, (req, res) => {
  const byId = {};
  for (const ep of Object.values(store.endpoints).filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy))) {
    byId[ep.source] = { ...ep, active: isActive(ep.lastSeen) };
  }
  // Active company sockets are excluded until their handshake is tenant-bound.
  const channel = req.organization?.isLegacy ? req.app.get('agentChannel') : null;
  const online = channel ? channel.listAgents() : [];
  for (const a of online) {
    const prev = byId[a.endpointId] || { source: a.endpointId, lastSeen: a.lastSeen };
    byId[a.endpointId] = {
      ...prev,
      hostname: a.hostname,
      connected: true,
      active: true,
      lastSeen: new Date(a.lastSeen) > new Date(prev.lastSeen || 0) ? a.lastSeen : prev.lastSeen,
      importance: a.importance || store.importance[endpointKey(a.endpointId, req.organizationId)] || null,
      trigate: a.trigate || null,
    };
  }
  const list = Object.values(byId).map((ep) => ({
    ...ep,
    connected: Boolean(ep.connected),
    importance: ep.importance || store.importance[endpointKey(ep.source, req.organizationId)] || null,
  }));
  list.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
  res.json(list);
});

// POST /api/agent/endpoints/:id/importance  { importance: low|normal|high|critical }
// TriGate Gate 3 (Impact): how important is this PC? Sent to the agent,
// which saves it on disk (trigate_memory.json) and uses it for Impact.
router.post('/endpoints/:id/importance', ...tenantUser, authorize('admin', 'analyst'), tenantUnavailable);

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
    updateEndpointHeartbeat(source, undefined, req.organizationId);

    const stored = [];
    for (const raw of rawItems) {
      if (!raw || typeof raw !== 'object') continue;
      const record = normaliseAction(raw, source, req.organizationId);
      pushAction(record);
      stored.push(record);
      emit('agent:action', record, req.organizationId);
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
router.get('/actions', ...tenantUser, (req, res) => {
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

    let result = store.actions.filter((actionRecord) => belongsToTenant(actionRecord, req.organizationId, req.organization?.isLegacy));

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
router.get('/actions/stats', ...tenantUser, (req, res) => {
  try {
    const windowHours = parseInt(req.query.window || '24', 10) || 24;
    const cutoff = Date.now() - windowHours * 3600 * 1000;

    const scoped = store.actions.filter(
      r => belongsToTenant(r, req.organizationId, req.organization?.isLegacy) && new Date(r.timestamp).getTime() >= cutoff
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
//  Two delivery paths:
//    * Socket.IO namespace /agent-channel  (Windows agent)
//    * REST queue, polled by the agent      (Linux Sentinel, no socket.io)
//  Both end up in store.commandHistory and emit 'command:sent'.
// ============================================================

// Queue/dispatch helpers live in services/commandQueue.service.js so the response
// engine (approvals, playbooks) can queue commands for REST agents as well.
const queueCommand = (endpoint_id, action, target, params, organizationId = null, isLegacy = false) => {
  const scope = organizationId && !isLegacy ? { organization: organizationId } : {};
  const queued = queueRestCommand(endpoint_id, action, target, params, scope);
  if (queued.ok) {
    emit('command:sent', {
      cmd_id: queued.cmd_id, endpoint_id, action,
      target: target || '', sent_at: queued.entry.queued_at, queued: true, organization: organizationId,
    }, organizationId);
  }
  return queued;
};

const finishCommand = (cmd_id, status, error, result, organizationId = null, endpointId = null) => finishQueuedCommand(cmd_id, status, error, result, organizationId, endpointId);

// POST /api/agent/commands – dispatch an action to a specific agent
// Remote actions change the endpoint (kill processes, firewall rules), so
// viewers are not allowed to dispatch them.
router.post('/commands', ...tenantUser, authorize('admin', 'analyst'), requirePlanFeature('responseActions'), (req, res) => {
  try {
    const { endpoint_id, action, target, params } = req.body || {};
    if (!endpoint_id || !action) return res.status(400).json({ ok: false, error: 'endpoint_id and action are required' });
    const safeParams = params && typeof params === 'object' ? params : {};
    // Company endpoints use tenant-bound REST polling. Never dispatch their
    // commands through the legacy global Socket.IO channel.
    if (!req.organization?.isLegacy) {
      const queued = queueCommand(String(endpoint_id), String(action), target ? String(target) : '', safeParams, req.organizationId, !!req.organization?.isLegacy);
      return res.status(202).json({ ...queued, note: 'Queued for this company endpoint to poll' });
    }
    const channel = req.app.get('agentChannel');
    if (!channel) {
      const queued = queueCommand(String(endpoint_id), String(action), target ? String(target) : '', safeParams, req.organizationId, !!req.organization?.isLegacy);
      return res.status(202).json({ ...queued, note: 'No live agent channel - queued for the endpoint next poll' });
    }
    const result = channel.dispatch(String(endpoint_id), String(action), target ? String(target) : '', safeParams);
    if (!result.ok) {
      const queued = queueCommand(String(endpoint_id), String(action), target ? String(target) : '', safeParams, req.organizationId, !!req.organization?.isLegacy);
      return res.status(202).json({ ...queued, note: 'Endpoint not on the live channel - queued for its next poll' });
    }
    logger.info(`Remote command dispatched: ${action} -> ${endpoint_id} (${result.cmd_id})`);
    emit('command:sent', { cmd_id: result.cmd_id, endpoint_id, action, target: target || '', sent_at: new Date().toISOString(), organization: req.organizationId }, req.organizationId);
    return res.status(202).json(result);
  } catch (error) {
    logger.error(`Error dispatching remote command: ${error.message}`);
    return res.status(500).json({ ok: false, error: 'Failed to dispatch command' });
  }
});


// GET /api/agent/commands – list recent remote commands
router.get('/commands', ...tenantUser, (req, res) => {
  try {
    const channel = req.app.get('agentChannel');
    if (!channel) {
      return res
        .status(503)
        .json({ ok: false, error: 'Agent channel not initialized' });
    }
    const commands = channel.listCommands().filter((cmd) => belongsToTenant(cmd, req.organizationId, req.organization?.isLegacy));
    res.json({ ok: true, count: commands.length, commands });
  } catch (error) {
    logger.error(`Error listing commands: ${error.message}`);
    res.status(500).json({ ok: false, error: 'Failed to list commands' });
  }
});

// ---- REST command channel (Linux Sentinel and any REST-only agent) ----
// GET /api/agent/commands/pending  (agent, x-api-key + x-endpoint-id)
//   Hands the endpoint its waiting commands and marks them 'sent'. The agent
//   must ack each one; an unfinshed command stays 'sent' in the history.
router.get('/commands/pending', validateAgentCommandKey, (req, res) => {
  const endpoint = String(req.endpointId || req.headers['x-endpoint-id'] || req.query.endpoint_id || '').trim();
  if (!endpoint) return res.status(400).json({ ok: false, error: 'x-endpoint-id header required' });
  if (req.endpointId && endpoint !== req.endpointId) return res.status(403).json({ ok: false, error: 'Endpoint credential mismatch' });
  const mine = takePendingCommands(endpoint, req.organizationId || null);
  if (mine.length) logger.info(`${endpoint} picked up ${mine.length} queued command(s)`);
  res.json({ ok: true, count: mine.length, commands: mine });
});

// POST /api/agent/commands/:cmdId/ack  (agent)
//   Body: { status: executed|failed, error?, result?: {message, details, metadata} }
//   Records the outcome, tells the dashboards and writes the ActionRecord the
//   "Isolation & Termination" tab shows - the same shape the socket path uses.
router.post('/commands/:cmdId/ack', validateAgentCommandKey, (req, res) => {
  const cmdId = String(req.params.cmdId || '');
  const status = String(req.body?.status || 'executed').toLowerCase();
  if (!['executed', 'failed'].includes(status)) return res.status(400).json({ ok: false, error: 'status must be executed or failed' });
  const error = req.body?.error ? String(req.body.error).slice(0, 400) : null;
  const result = req.body?.result && typeof req.body.result === 'object' ? req.body.result : {};

  const source = getSource(req);
  if (req.endpointId && source !== req.endpointId) return res.status(403).json({ ok: false, error: 'Endpoint credential mismatch' });
  const entry = finishCommand(cmdId, status, error, result, req.organizationId || null, source);
  if (!entry) return res.status(404).json({ ok: false, error: 'Command not found for this endpoint' });
  emit('command:ack', { cmd_id: cmdId, status, error, result, organization: req.organizationId }, req.organizationId);

  updateEndpointHeartbeat(source, req.body?.platform || 'linux', req.organizationId);
  // normaliseAction() maps 'summary'/'details' (there is no 'message' field),
  // so both are filled in - the Isolation & Termination tab shows details.
  const text = result.message || error || (status === 'executed' ? 'Done' : 'Failed');
  const actionRecord = normaliseAction({
    id: `act_${source}_${cmdId}`,
    action: entry?.action || req.body?.action || 'unknown',
    target: entry?.target || req.body?.target || '',
    status: status === 'executed' ? 'success' : 'failed',
    summary: text,
    details: [text, result.details].filter(Boolean).join(' - '),
    reason: entry?.params?.reason || '',
    agent: 'AiBoO-Linux-Sentinel',
    error: status === 'executed' ? null : text,
    dry_run: !!result.metadata?.dry_run,
    metadata: { ...(result.metadata || {}), cmd_id: cmdId, via: 'rest' },
  }, source, req.organizationId);
  pushAction(actionRecord);
  emit('agent:action', actionRecord, req.organizationId);

  logger.info(`Command ack (REST) ${cmdId} -> ${status}${error ? ` (${error})` : ''}`);
  res.json({ ok: true, cmd_id: cmdId, status, action: actionRecord });
});

// GET /api/agent/commands/history – what was dispatched and what happened
router.get('/commands/history', ...tenantUser, (req, res) => {
  const endpoint = String(req.query.endpoint_id || '').trim();
  const list = endpoint
    ? store.commandHistory.filter((c) => c.endpoint_id === endpoint && belongsToTenant(c, req.organizationId, req.organization?.isLegacy))
    : store.commandHistory.filter((c) => belongsToTenant(c, req.organizationId, req.organization?.isLegacy));
  res.json({ ok: true, count: list.length, commands: list.slice(0, 100) });
});

// GET /api/agent/agents-online – every agent you can send an action to:
//   * socket agents (the Windows agent) straight from the command channel,
//   * REST-polling company agents (Windows and Linux) from the tenant-scoped
//     endpoint store, as long as they checked in recently.
router.get('/agents-online', ...tenantUser, (req, res) => {
  try {
    // Socket agents are visible only to the internal legacy workspace until
    // their connection credential carries a company tenant.
    const channel = req.organization?.isLegacy ? req.app.get('agentChannel') : null;
    const socketAgents = channel ? channel.listAgents() : [];
    const seen = new Set(socketAgents.map((a) => a.endpointId || a.endpoint_id));

    const restAgents = Object.values(store.endpoints || {})
      .filter((ep) => ep && belongsToTenant(ep, req.organizationId, req.organization?.isLegacy) && ep.source && isActive(ep.lastSeen) && !seen.has(ep.source))
      .map((ep) => ({
        endpointId: ep.source,
        hostname: ep.hostname || ep.source,
        lastSeen: ep.lastSeen,
        platform: ep.platform || 'linux',
        channel: 'rest',
        importance: store.importance[endpointKey(ep.source, req.organizationId)] || null,
      }));

    const agents = [...socketAgents, ...restAgents];
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
  const finding = { ...req.body, source: getSource(req), ...(req.organizationId ? { organization: req.organizationId } : {}) };
  updateEndpointHeartbeat(finding.source, undefined, req.organizationId);
  push(store.findings, finding);
  emit('agent:finding', finding, req.organizationId);
  if (finding.id) ingestAlert(fromFinding(finding), true, req.organizationId);
  res.json({ ok: true });
});

router.post('/correlated', validateAgentOrJWT, (req, res) => {
  const incident = { ...req.body, source: req.body?.source || getSource(req), ...(req.organizationId ? { organization: req.organizationId } : {}) };
  // the same incident is re-sent when it grows: keep one row, newest first
  const idx = store.correlated.findIndex((c) => c.alert_id && c.alert_id === incident.alert_id
    && String(c.organization || '') === String(incident.organization || ''));
  if (idx !== -1) store.correlated.splice(idx, 1);
  push(store.correlated, incident);
  emit('agent:correlated', incident, req.organizationId);
  if (incident.alert_id) ingestAlert(fromCorrelated(incident), true, req.organizationId);
  if (['critical', 'high'].includes(req.body.severity))
    emit('alert:critical', { ...req.body, message: req.body.description }, req.organizationId);
  res.json({ ok: true });
});

router.post('/gate-decision', validateAgentOrJWT, async (req, res) => {
  const decision = { ...req.body, source: getSource(req), ...(req.organizationId ? { organization: req.organizationId } : {}) };
  const decidedPlatform = req.body?.platform || req.body?.metadata?.platform
    || store.endpoints[endpointKey(decision.source, req.organizationId)]?.platform || '';
  decision.platform = decidedPlatform;
  updateEndpointHeartbeat(decision.source, decidedPlatform, req.organizationId);
  const imp = decision.metadata?.trigate?.impact?.importance;
  if (IMPORTANCE_LEVELS.has(String(imp || ''))) store.importance[endpointKey(decision.source, req.organizationId)] = String(imp);
  push(store.gateDecisions, decision);
  emit('agent:gate', decision, req.organizationId);
  if (decision.event_id) ingestAlert(fromGateDecision(decision), true, req.organizationId); // HOLD/BLOCK only
  const status = { ...(store.agentStatus[endpointKey(decision.source, req.organizationId)] || {}), importance: store.importance[endpointKey(decision.source, req.organizationId)] };

  // The old shared key is unbound and must never drive workspace automation.
  // Legacy organization callers retain their existing null-organization store.
  if (req.organization?.isLegacy) {
    withResponseOrganization(null, () => onTriGateDecision(decision, status), req.organizationId)
      .catch((err) => logger.error(`Legacy response rules / approvals failed: ${err.message}`));
  } else if (req.agent?.organizationId && req.agent.endpointId === decision.source) {
    // Tenant agents may create approvals only when their current subscription
    // enables response actions. Playbook-backed rules need both entitlements;
    // otherwise process the ordinary TriGate approval recommendations only.
    try {
      const features = await getAgentPlanFeatures(req.organizationId);
      if (features.responseActions === true) {
        const runTenantResponse = () => features.playbooks === true
          ? onTriGateDecision(decision, status)
          : approvalsFromDecision(decision, status);
        withResponseOrganization(req.organizationId, runTenantResponse)
          .catch((err) => logger.error(`Tenant response rules / approvals failed: ${err.message}`));
      }
    } catch (err) {
      // Monitoring and alert ingestion still succeed if billing data is
      // temporarily unavailable; no automated response runs without a fresh check.
      logger.warn(`Tenant response automation skipped: ${err.message}`);
    }
  }
  res.json({ ok: true });
});

// ---- Playbooks that talk to outside systems ----
// Freeze Badge still supports one legacy process-wide webhook. Company
// workspaces report it as unconfigured and cannot invoke it until a separate
// tenant-scoped integration and secret-management flow is implemented.
router.get('/playbooks/status', ...tenantUser, (req, res) => {
  // The env-backed hook is shared legacy configuration, not a company integration.
  res.json({ badge: { configured: Boolean(req.organization?.isLegacy && badgeConfigured()) } });
});

router.post('/playbooks/freeze-badge', ...tenantUser, authorize('admin', 'analyst'), tenantUnavailable);

// POST /api/agent/compliance - agent sends its ISO 27001 / NIST CSF check
router.post('/compliance', validateAgentOrJWT, async (req, res) => {
  const source = getSource(req);
  updateEndpointHeartbeat(source, undefined, req.organizationId);
  const body = req.body || {};
  if (!Array.isArray(body.checks)) return res.status(400).json({ ok: false, error: 'checks[] is required' });
  const report = { ...body, endpoint: source, received_at: new Date().toISOString() };
  store.compliance[endpointKey(source, req.organizationId)] = { ...report, ...(req.organizationId ? { organization: req.organizationId } : {}) };
  await saveCompliance(source, body, req.organizationId);
  emit('agent:compliance', { endpoint: source, score: body.score, counts: body.counts, checked_at: body.checked_at }, req.organizationId);
  res.json({ ok: true });
});

// POST /api/agent/agent-status - agent reports which engines are running
router.post('/agent-status', validateAgentOrJWT, (req, res) => {
  const source = getSource(req);
  updateEndpointHeartbeat(source, undefined, req.organizationId);
  store.agentStatus[endpointKey(source, req.organizationId)] = { ...(req.body || {}), endpoint: source, received_at: new Date().toISOString(), ...(req.organizationId ? { organization: req.organizationId } : {}) };
  emit('agent:status', store.agentStatus[endpointKey(source, req.organizationId)], req.organizationId);
  res.json({ ok: true });
});

router.get('/agent-status', ...tenantUser, (req, res) => res.json(Object.values(store.agentStatus).filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy))));

router.get('/compliance', ...tenantUser, async (req, res) => {
  // memory copy has the full detail for live agents; DB keeps history
  let rows = Object.values(store.compliance).filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy));
  if (!rows.length) {
    try { rows = await latestCompliance(req.organizationId); } catch { rows = []; }
  }
  res.json(rows);
});

// POST /api/agent/gate-decisions/:eventId/feedback  { feedback: false_alarm|confirmed }
// TriGate learning: the agent stores the feedback on disk; future events of
// the same kind for the same user score lower (false alarm) / higher (confirmed).
router.post('/gate-decisions/:eventId/feedback', ...tenantUser, authorize('admin', 'analyst'), tenantUnavailable);

router.post('/pseudo-lock', validateAgentOrJWT, (req, res) => {
  if (req.organizationId) return tenantUnavailable(req, res);
  store.pseudoLocks[req.body.lock_id] = req.body;
  emit('agent:pseudo-lock', req.body);
  res.json({ ok: true });
});

// Agent reports that a decoy port was really closed
router.post('/pseudo-lock-restore', validateAgentOrJWT, (req, res) => {
  if (req.organizationId) return tenantUnavailable(req, res);
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
router.get('/correlated', ...tenantUser, (req, res) => res.json(store.correlated.filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy)).slice(0, 20)));
router.get('/gate-decisions', ...tenantUser, (req, res) => {
  const channel = req.app.get('agentChannel');
  const { source } = req.query;
  const scopedDecisions = store.gateDecisions.filter((d) => belongsToTenant(d, req.organizationId, req.organization?.isLegacy));
  const list = (source ? scopedDecisions.filter((d) => d.source === source) : scopedDecisions)
    .slice(0, 50)
    .map((d) => {
      if (!d.feedback?.cmd_id || !channel?.getCommand) return d;
      const cmd = channel.getCommand(d.feedback.cmd_id);
      return cmd ? { ...d, feedback: { ...d.feedback, status: cmd.status, error: cmd.error } } : d;
    });
  res.json(list);
});
router.get('/pseudo-locks', ...tenantUser, (req, res) => res.json(Object.values(store.pseudoLocks).filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy))));
router.get('/response-log', ...tenantUser, (req, res) => res.json(store.responseLog.filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy)).slice(0, 50)));

router.get('/stats', ...tenantUser, (req, res) => {
  const sc = {}; const tc = {};
  const findings = store.findings.filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy));
  const incidents = store.correlated.filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy));
  const locks = Object.values(store.pseudoLocks).filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy));
  const actions = store.actions.filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy));
  const endpoints = Object.values(store.endpoints).filter((row) => belongsToTenant(row, req.organizationId, req.organization?.isLegacy));
  findings.forEach(f => {
    sc[f.severity] = (sc[f.severity] || 0) + 1;
    tc[f.threat_type] = (tc[f.threat_type] || 0) + 1;
  });
  res.json({
    total_findings: findings.length,
    correlated_alerts: incidents.length,
    active_locks: locks.filter(l => l.active).length,
    total_actions: actions.length,
    by_severity: sc,
    by_type: tc,
    endpoints: endpoints.length,
  });
});

// ---- Restore lock: ask the agent that owns the decoy to close it ----
// The agent closes the real listening port and then reports back via
// POST /pseudo-lock-restore, which flips the lock to "restored".
router.post('/pseudo-locks/:lockId/restore', ...tenantUser, authorize('admin', 'analyst'), tenantUnavailable);

// ---- Send Event tab: inject a test event on a connected agent ----
const TEST_EVENT_TYPES = new Set([
  'network_intrusion', 'identity_mismatch', 'physical_intrusion',
  'insider_threat', 'anomalous_behavior', 'correlated_attack',
]);
const TEST_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);

router.post('/test-event', ...tenantUser, authorize('admin', 'analyst'), tenantUnavailable);

// ---- Dashboard playbook: Open War Room ----
// Alerts every logged-in dashboard at once (real-time broadcast).
router.post('/war-room', ...tenantUser, authorize('admin', 'analyst'), (req, res) => {
  const entry = {
    id: `war_${Date.now()}`,
    type: 'war_room',
    organization: req.organizationId,
    opened_by: req.user?.name || req.user?.email || String(req.user?.id || 'unknown'),
    note: String(req.body?.note || '').slice(0, 300),
    timestamp: new Date().toISOString(),
  };
  push(store.responseLog, entry);
  emit('war-room:opened', entry, req.organizationId);
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

  // Label every sample row so it can never be mistaken for a real alert:
  // "[DEMO]" prefix on the visible text, demo:true flag, and everything
  // belongs to the "demo" endpoint (never a real PC name like "gorilla").
  const tag = (text) => (text && !String(text).startsWith('[DEMO]') ? `[DEMO] ${text}` : text);
  demoFindings.forEach(f => { f.summary = tag(f.summary); f.demo = true; f.source = 'demo'; });
  demGates.forEach(g => { g.reason = tag(g.reason); g.demo = true; g.source = 'demo'; });
  demCorrelated.forEach(c => { c.description = tag(c.description); c.demo = true; c.source = 'demo'; });
  Object.assign(demLock, { summary: tag(demLock.summary), demo: true, source: 'demo' });
  demoActions.forEach(a => {
    a.details = tag(a.details) || '[DEMO] sample action';
    if (a.error) a.error = tag(a.error);
    a.endpoint = 'demo';
    a.source = 'demo';
    a.metadata = { ...(a.metadata || {}), demo: true };
  });

  demoFindings.forEach(f => push(store.findings, f));
  demGates.forEach(g => push(store.gateDecisions, g));
  demCorrelated.forEach(c => push(store.correlated, c));
  store.pseudoLocks[demLock.lock_id] = demLock;

  // Normalise and store demo actions
  demoActions.forEach(a => pushAction(normaliseAction(a, a.source)));

  // Demo endpoint (sample data only - no real agent behind it)
  store.endpoints['demo'] = { source: 'demo', demo: true, lastSeen: new Date().toISOString() };

  logger.warn('DEMO DATA LOADED (SEED_DEMO_DATA=true) - every sample row is marked [DEMO]');
}

export default router;
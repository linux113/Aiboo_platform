// backend/services/pseudolock.service.js
// PseudoLock orchestration (see PSEUDOLOCK_SPECIFICATION_v1.0.md):
//
//   1. APPROVALS  - "Pending approvals" list. A response action waits here
//      until an admin / analyst presses Approve or Reject, or it expires.
//      Created automatically from TriGate BLOCK decisions (when the agent's
//      auto_response is OFF) and by the "approval" step of a playbook.
//   2. PLAYBOOKS  - several steps that run one after the other:
//        action   - a PseudoLock action on the PC (block IP, disable account...)
//        approval - stop until a person approves (rejected / expired = stop)
//        notify   - message to every open dashboard
//        wait     - pause N seconds
//      Built-in templates are read-only (copy them to change them).
//   3. RUNS       - one execution of a playbook, with a status per step.
//
// Actions are sent to the agent over the command channel (sockets/agentChannel.js)
// and we wait for the agent's "executed" / "failed" answer.
// Storage: MongoDB when connected, otherwise memory (same as alertStore.js).
import net from 'node:net';
import mongoose from 'mongoose';
import ApprovalModel from '../models/Approval.js';
import PlaybookModel from '../models/Playbook.js';
import PlaybookRunModel from '../models/PlaybookRun.js';
import ResponseRuleModel from '../models/ResponseRule.js';
import RuleEventModel from '../models/RuleEvent.js';
import { queueCommand, waitForCommand } from './commandQueue.service.js';
import logger from '../utils/logger.js';
import { freezeBadge } from './badge.service.js';

// ------------------------------------------------------------------ settings
const intEnv = (name, def, min, max) => {
  const n = Number.parseInt(process.env[name], 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def;
};
export const approvalExpiryMinutes = () => intEnv('APPROVAL_EXPIRY_MINUTES', 30, 1, 1440);
const actionTimeoutMs = () => intEnv('PLAYBOOK_ACTION_TIMEOUT_SECONDS', 90, 5, 600) * 1000;
const fourEyes = () => String(process.env.APPROVAL_FOUR_EYES || '').toLowerCase() === 'true';
const approvalsFromTriGate = () => String(process.env.APPROVALS_FROM_TRIGATE ?? 'true').toLowerCase() !== 'false';
const approvalVerdicts = () => new Set(String(process.env.APPROVAL_VERDICTS || 'block')
  .toLowerCase().split(',').map((s) => s.trim()).filter(Boolean));

const MAX_STEPS = 15;
const MAX_WAIT_SECONDS = 3600;
const clip = (v, n = 300) => String(v ?? '').slice(0, n);
const clone = (o) => JSON.parse(JSON.stringify(o));
const nowIso = () => new Date().toISOString();
const newId = (p) => `${p}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;
export const whoIs = (user) => clip(user?.email || user?.name || user?.id || 'unknown', 120);

// ------------------------------------------------------------------ catalogue
// What a playbook / approval may run. `agent: false` = done by the backend.
const TARGETS = {
  ip: { hint: 'IP address, e.g. 45.95.147.3' },
  segment: { hint: 'IP address or range, e.g. 45.95.147.3 or 192.168.1.0/24' },
  user: { hint: 'Windows user name, e.g. guest' },
  process: { hint: 'Process ID (PID) or program name, e.g. 4321 or notepad.exe' },
  label: { hint: 'Label (optional)', optional: true },
  badge: { hint: 'Badge number / employee ID, e.g. EMP-1042' },
};
const MIN = { key: 'minutes', label: 'Minutes', def: 30, min: 1, max: 1440 };
const KBPS = { key: 'kbps', label: 'Speed limit (kbit/s)', def: 256, min: 64, max: 100000 };
export const ACTIONS = {
  block_access: { label: 'Block IP (Windows Firewall)', target: 'ip', help: 'Firewall rule AiBoO_Block_* that blocks incoming traffic from this IP.' },
  isolate_asset: { label: 'Isolate - cut the PC off from an IP', target: 'ip', help: 'Firewall rule AiBoO_Isolate_* that blocks incoming traffic from this IP (same as Isolate Host).' },
  throttle_segment: { label: 'Slow down traffic (throttle)', target: 'segment', params: [KBPS, MIN], help: 'Limits the speed of traffic to this IP / range; removed automatically.' },
  remove_throttle: { label: 'Remove slow-down', target: 'segment', help: 'Removes an earlier throttle.' },
  restrict_identity: { label: 'Disable account for N minutes', target: 'user', params: [MIN], help: 'Disables the account and logs it off; turned back on automatically.' },
  lift_restriction: { label: 'Re-enable account now', target: 'user', help: 'Ends an earlier "disable for N minutes".' },
  revoke_identity: { label: 'Disable account (until someone re-enables it)', target: 'user', help: 'net user <name> /active:no' },
  force_logout: { label: 'Log off user', target: 'user', help: 'Ends the user\'s Windows sessions.' },
  step_up_auth: { label: 'Lock the screen (sign in again)', target: 'user', help: 'Locks the Windows screen; the user must type the password again.' },
  terminate_process: { label: 'Stop a program', target: 'process', help: 'Kills the process (by PID or name).' },
  pseudo_lock: { label: 'Open decoy port (Lock Perimeter)', target: 'label', help: 'Opens a honeypot port on the PC and logs who connects.' },
  freeze_badge: { label: 'Freeze door badge', target: 'badge', agent: false, help: 'Asks the badge system to block this badge (needs BADGE_WEBHOOK_URL).' },
};
// TriGate BLOCK recommendations that become approval requests (same set the
// agent would run itself with auto_response = true, minus "notify").
const TRIGATE_APPROVAL_ACTIONS = new Set(['block_access', 'restrict_identity', 'revoke_identity', 'isolate_asset']);

export const VARIABLES = {
  ip: { label: 'IP address', example: '45.95.147.3' },
  user: { label: 'User name', example: 'guest' },
  pc: { label: 'PC (endpoint) name', example: 'gorilla', auto: true },
  pid: { label: 'Process ID', example: '4321' },
  badge: { label: 'Badge / employee ID', example: 'EMP-1042' },
  alert: { label: 'Alert ID', example: 'tg_abc123', auto: true },
};
const VAR_RE = /\{(\w+)\}/g;
const varsIn = (s) => [...String(s ?? '').matchAll(VAR_RE)].map((m) => m[1]);
const fill = (s, vars) => String(s ?? '').replace(VAR_RE, (_, k) => (vars[k] ?? '').toString());

const USER_RE = /^[A-Za-z0-9 ._\-@\\$]{1,64}$/;
export function checkTarget(kind, value) {
  const v = String(value ?? '').trim();
  switch (kind) {
    case 'ip': return net.isIP(v) ? null : `"${v}" is not an IP address`;
    case 'segment': {
      const [ip, bits, extra] = v.split('/');
      if (extra !== undefined || !net.isIP(ip)) return `"${v}" is not an IP address or range`;
      if (bits === undefined) return null;
      const max = net.isIP(ip) === 4 ? 32 : 128;
      return /^\d+$/.test(bits) && Number(bits) <= max ? null : `"${v}" has a wrong range size`;
    }
    case 'user': return USER_RE.test(v) ? null : `"${v}" is not a valid user name`;
    case 'process': return /^\d{1,7}$/.test(v) || /^[\w.\- ]{1,100}$/.test(v) ? null : `"${v}" is not a PID or program name`;
    case 'label': return v.length <= 80 ? null : 'Label is too long (max 80)';
    case 'badge': return v && v.length <= 120 ? null : 'Badge number is required';
    default: return 'Unknown target type';
  }
}

function cleanParams(action, raw = {}) {
  const out = {};
  for (const p of ACTIONS[action]?.params || []) {
    const n = Number(raw?.[p.key]);
    out[p.key] = Number.isFinite(n) ? Math.round(Math.min(p.max, Math.max(p.min, n))) : p.def;
  }
  return out;
}

// Same actions, but named the way each operating system does them. A Linux
// endpoint must never show "Windows Firewall" on a button.
const LINUX_LABELS = {
  block_access: 'Block IP (Linux firewall / fail2ban)',
  isolate_asset: 'Isolate - cut the host off from an IP (iptables / ufw)',
  throttle_segment: 'Slow down traffic (tc / iptables)',
  remove_throttle: 'Remove slow-down',
  restrict_identity: 'Lock the account for N minutes',
  lift_restriction: 'Unlock the account now',
  revoke_identity: 'Lock the account (until someone unlocks it)',
  force_logout: 'Log the user out of their sessions',
  step_up_auth: 'Lock the sessions (sign in again)',
  terminate_process: 'Stop a process',
  pseudo_lock: 'Open decoy port (honeypot listener)',
};
const isLinux = (platform) => String(platform || '').toLowerCase().startsWith('linux');

export const actionLabel = (a, platform) =>
  (isLinux(platform) ? (LINUX_LABELS[a] || ACTIONS[a]?.label) : ACTIONS[a]?.label) || a;
export const catalog = () => ({
  actions: Object.entries(ACTIONS).map(([id, a]) => ({
    id, label: a.label, help: a.help, target: a.target, targetHint: TARGETS[a.target].hint,
    targetOptional: Boolean(TARGETS[a.target].optional), params: a.params || [], runsOn: a.agent === false ? 'backend' : 'pc',
  })),
  variables: Object.entries(VARIABLES).map(([id, v]) => ({ id, ...v })),
  stepTypes: ['action', 'approval', 'notify', 'wait'],
  approvalExpiryMinutes: approvalExpiryMinutes(),
  fourEyes: fourEyes(),
  maxSteps: MAX_STEPS,
});

// ------------------------------------------------------------------ storage
class MemoryCol {
  constructor(max) { this.max = max; this.rows = new Map(); }
  async get(id) { const r = this.rows.get(id); return r ? clone(r) : null; }
  async save(doc) {
    const prev = this.rows.get(doc.id);
    const full = { ...clone(doc), createdAt: prev?.createdAt || doc.createdAt || nowIso(), updatedAt: nowIso() };
    this.rows.delete(doc.id);
    this.rows.set(doc.id, full);
    while (this.rows.size > this.max) this.rows.delete(this.rows.keys().next().value);
    return clone(full);
  }
  async remove(id) { return this.rows.delete(id); }
  async list({ status, limit = 200 } = {}) {
    const st = status ? new Set([].concat(status)) : null;
    return [...this.rows.values()].filter((r) => !st || st.has(r.status))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, limit).map(clone);
  }
  async count({ status } = {}) { return (await this.list({ status, limit: Infinity })).length; }
}

class MongoCol {
  constructor(Model) { this.Model = Model; }
  static strip(d) {
    if (!d) return null;
    const { _id, __v, ...rest } = d;
    return { ...rest, createdAt: d.createdAt ? new Date(d.createdAt).toISOString() : undefined,
      updatedAt: d.updatedAt ? new Date(d.updatedAt).toISOString() : undefined };
  }
  async get(id) { return MongoCol.strip(await this.Model.findOne({ id }).lean()); }
  async save(doc) {
    const { _id, __v, createdAt, updatedAt, ...set } = clone(doc);
    const r = await this.Model.findOneAndUpdate({ id: doc.id }, { $set: set }, { upsert: true, new: true, lean: true });
    return MongoCol.strip(r);
  }
  async remove(id) { return (await this.Model.deleteOne({ id })).deletedCount > 0; }
  async list({ status, limit = 200 } = {}) {
    const q = status ? { status: { $in: [].concat(status) } } : {};
    return (await this.Model.find(q).sort({ createdAt: -1 }).limit(limit).lean()).map(MongoCol.strip);
  }
  async count({ status } = {}) { return this.Model.countDocuments(status ? { status: { $in: [].concat(status) } } : {}); }
}

const memory = {
  approvals: new MemoryCol(3000), playbooks: new MemoryCol(500), runs: new MemoryCol(1000),
  rules: new MemoryCol(200), ruleEvents: new MemoryCol(2000),
};
const mongo = {
  approvals: new MongoCol(ApprovalModel), playbooks: new MongoCol(PlaybookModel), runs: new MongoCol(PlaybookRunModel),
  rules: new MongoCol(ResponseRuleModel), ruleEvents: new MongoCol(RuleEventModel),
};
let forceMemory = false;
const db = () => {
  if (forceMemory || process.env.ALERT_STORE === 'memory' || process.env.RESPONSE_STORE === 'memory') return memory;
  return mongoose.connection?.readyState === 1 ? mongo : memory;
};
/** Storage used by services/responseRules.service.js (same MongoDB / memory switch). */
export const store = () => db();

// ------------------------------------------------------------------ wiring
let emitFn = () => {};
let channel = null;
let sweeper = null;
const ackWaiters = new Map(); // cmd_id -> resolve(ack)

export function setPseudoLockEmitter(fn) { emitFn = typeof fn === 'function' ? fn : () => {}; }
export const emit = (ev, data) => { try { emitFn(ev, data); } catch (err) { logger.error(`PseudoLock emit ${ev}: ${err.message}`); } };

/** Called once from server.js (and by tests with a fake channel). */
export function initPseudoLock({ agentChannel, emitter, sweepSeconds = 15 } = {}) {
  if (emitter) setPseudoLockEmitter(emitter);
  channel = agentChannel || null;
  channel?.onAck?.((ack) => {
    const st = String(ack?.status || '');
    if (st !== 'executed' && st !== 'failed') return; // "received" = still working
    const done = ackWaiters.get(ack.cmd_id);
    if (done) { ackWaiters.delete(ack.cmd_id); done(ack); }
  });
  if (sweeper) clearInterval(sweeper);
  if (sweepSeconds > 0) {
    sweeper = setInterval(() => sweepExpired().catch((e) => logger.error(`Approval sweep: ${e.message}`)), sweepSeconds * 1000);
    sweeper.unref?.();
  }
  // runs that were mid-step when the backend stopped cannot be resumed safely
  setTimeout(() => recoverRuns().catch(() => {}), 15000).unref?.();
}

export function useMemoryResponseStore() {
  forceMemory = true;
  for (const col of Object.values(memory)) col.rows.clear();
}
/** Tests only: overwrite an approval as-is (e.g. to move its expiry into the past). */
export const __saveApprovalForTests = (a) => db().approvals.save(a);
export function stopPseudoLock() { if (sweeper) clearInterval(sweeper); sweeper = null; }

// ------------------------------------------------------------------ executing one action
/** Runs one action and waits for the result. Returns { ok, status, error, result, cmd_id }. */
export async function executeAction({ endpoint, action, target, params = {}, by = 'PseudoLock', reason = '' }) {
  const def = ACTIONS[action];
  if (!def) return { ok: false, status: 'failed', error: `Unknown action ${action}` };
  if (def.agent === false) {
    const out = await freezeBadge({ badgeId: target, reason, by });
    return { ok: out.ok, status: out.ok ? 'executed' : 'failed', error: out.ok ? null : out.error, result: { message: out.message || out.error } };
  }
  if (!endpoint) return { ok: false, status: 'failed', error: 'No PC (endpoint) chosen for this action' };
  // Windows agents live on the socket channel; Linux agents poll the REST queue.
  const sent = channel ? channel.dispatch(String(endpoint), action, String(target ?? ''), params) : { ok: false };
  if (!sent?.ok) {
    // Windows agents answer on the socket. A Linux agent has no socket.io - it
    // polls /api/agent/commands/pending, so queue the command for it instead.
    const queued = queueCommand(String(endpoint), action, String(target ?? ''), params,
                                { requested_by: by, reason: reason ? String(reason).slice(0, 200) : '' });
    if (!queued.ok) {
      return { ok: false, status: 'failed',
               error: `PC '${endpoint}' is not connected - start the agent on that PC and try again` };
    }
    emit('command:sent', { cmd_id: queued.cmd_id, endpoint_id: endpoint, action,
                           target: target || '', sent_at: nowIso(), queued: true });
    const restAck = await waitForCommand(queued.cmd_id, actionTimeoutMs());
    return { ok: restAck.ok, status: restAck.status, cmd_id: queued.cmd_id,
             error: restAck.error || null, result: restAck.result || null };
  }
  emit('command:sent', { cmd_id: sent.cmd_id, endpoint_id: endpoint, action, target: target || '', sent_at: nowIso() });
  const ack = await new Promise((resolve) => {
    const timer = setTimeout(() => { ackWaiters.delete(sent.cmd_id); resolve(null); }, actionTimeoutMs());
    timer.unref?.();
    ackWaiters.set(sent.cmd_id, (a) => { clearTimeout(timer); resolve(a); });
    // already answered (very fast agent / fake channel)?
    const known = channel.getCommand?.(sent.cmd_id);
    if (known && ['executed', 'failed'].includes(known.status)) {
      ackWaiters.get(sent.cmd_id)?.({ cmd_id: sent.cmd_id, status: known.status, error: known.error, result: known.result });
    }
  });
  if (!ack) {
    return { ok: false, status: 'timeout', cmd_id: sent.cmd_id,
      error: `No answer from '${endpoint}' in ${Math.round(actionTimeoutMs() / 1000)} s - it may still have run, check Agent Console` };
  }
  return { ok: ack.status === 'executed', status: ack.status, cmd_id: sent.cmd_id, error: ack.error || null, result: ack.result || null };
}

// ------------------------------------------------------------------ approvals
export const APPROVAL_OPEN = 'pending';
const publicApproval = (a) => a && ({ ...a, expiresInSeconds: a.status === 'pending' ? Math.max(0, Math.round((new Date(a.expiresAt) - Date.now()) / 1000)) : null });

async function saveApproval(a, event = 'approval:updated') {
  const saved = await db().approvals.save(a);
  emit(event, publicApproval(saved));
  return saved;
}

/**
 * Create a pending approval. The same action on the same PC + target that is
 * already pending is NOT duplicated: it counts the repeat and resets the timer.
 */
export async function createApproval(input) {
  const action = String(input.action || '');
  if (!ACTIONS[action]) throw new Error(`Unknown action ${action}`);
  const target = clip(input.target ?? '', 200).trim();
  const kind = ACTIONS[action].target;
  if (!(TARGETS[kind].optional && !target)) {
    const err = checkTarget(kind, target);
    if (err) throw new Error(err);
  }
  const minutes = Math.min(1440, Math.max(1, Number(input.expiresMinutes) || approvalExpiryMinutes()));
  const endpoint = clip(input.endpoint || '', 120);
  const expiresAt = new Date(Date.now() + minutes * 60000).toISOString();
  if (!input.runId) {
    const open = await db().approvals.list({ status: 'pending', limit: 1000 });
    const same = open.find((a) => !a.runId && a.endpoint === endpoint && a.action === action && a.target === target);
    if (same) {
      same.occurrences = (same.occurrences || 1) + 1;
      same.expiresAt = expiresAt;
      if (input.eventId) same.eventIds = [...new Set([...(same.eventIds || []), input.eventId])].slice(-20);
      if (Number(input.risk) > Number(same.risk || 0)) { same.risk = Number(input.risk); same.level = input.level || same.level; }
      same.history = [...(same.history || []), { at: nowIso(), by: input.requestedBy || 'TriGate', what: 'repeated - timer restarted' }].slice(-30);
      return { approval: await saveApproval(same), created: false };
    }
  }
  const a = {
    id: newId('apr'),
    status: 'pending',
    kind: input.runId ? 'playbook_step' : 'action',
    title: clip(input.title || `${actionLabel(action, input.platform)}${target ? `: ${target}` : ''}`, 200),
    action, actionLabel: actionLabel(action, input.platform), target,
    platform: input.platform || '',
    params: cleanParams(action, input.params),
    endpoint,
    reason: clip(input.reason, 600),
    risk: input.risk != null ? Number(input.risk) : null,
    level: clip(input.level || '', 20),
    verdict: clip(input.verdict || '', 20),
    pattern: clip(input.pattern || '', 80),
    origin: input.origin || 'manual', // trigate | playbook | manual
    alertId: input.alertId || null,
    eventIds: input.eventId ? [input.eventId] : [],
    runId: input.runId || null, stepIndex: input.stepIndex ?? null, playbookName: input.playbookName || null,
    requestedBy: clip(input.requestedBy || 'TriGate', 120),
    requestedAt: nowIso(), expiresAt, expiresMinutes: minutes,
    decidedBy: null, decidedAt: null, note: '',
    cmdId: null, result: null, error: null, finishedAt: null,
    occurrences: 1,
    history: [{ at: nowIso(), by: input.requestedBy || 'TriGate', what: 'requested' }],
  };
  return { approval: await saveApproval(a, 'approval:new'), created: true };
}

/** Approval steps of a playbook carry no action (they only gate the next steps). */
async function createGateApproval({ run, stepIndex, message, expiresMinutes }) {
  const minutes = Math.min(1440, Math.max(1, Number(expiresMinutes) || approvalExpiryMinutes()));
  const a = {
    id: newId('apr'), status: 'pending', kind: 'playbook_step',
    title: clip(message || `Continue playbook "${run.playbookName}"?`, 200),
    action: null, actionLabel: 'Continue playbook', target: '', params: {},
    endpoint: run.endpoint || '', reason: clip(`Step ${stepIndex + 1} of playbook "${run.playbookName}". Next steps: ${run.steps.slice(stepIndex + 1).map((s) => s.label).join(' -> ') || 'none'}`, 600),
    risk: run.vars?.risk ? Number(run.vars.risk) : null, level: '', verdict: '', pattern: '',
    origin: 'playbook', alertId: run.alertId || null, eventIds: [],
    runId: run.id, stepIndex, playbookName: run.playbookName,
    requestedBy: run.startedBy, requestedAt: nowIso(),
    expiresAt: new Date(Date.now() + minutes * 60000).toISOString(), expiresMinutes: minutes,
    decidedBy: null, decidedAt: null, note: '', cmdId: null, result: null, error: null, finishedAt: null,
    occurrences: 1, history: [{ at: nowIso(), by: run.startedBy, what: 'requested by playbook' }],
  };
  return saveApproval(a, 'approval:new');
}

/**
 * Response rule in "Ask first" mode: approving this starts the playbook.
 * The same rule + PC + variables already pending is counted, not duplicated.
 */
export async function createPlaybookStartApproval({ rule, playbook, endpoint, vars, alertId, eventId, reason, risk, level, verdict, pattern }) {
  const open = await db().approvals.list({ status: 'pending', limit: 1000 });
  const sameVars = (a) => JSON.stringify(a.vars || {}) === JSON.stringify(vars || {});
  const same = open.find((a) => a.kind === 'playbook_start' && a.ruleId === rule.id && a.endpoint === endpoint && sameVars(a));
  const minutes = approvalExpiryMinutes();
  const expiresAt = new Date(Date.now() + minutes * 60000).toISOString();
  if (same) {
    same.occurrences = (same.occurrences || 1) + 1;
    same.expiresAt = expiresAt;
    if (eventId) same.eventIds = [...new Set([...(same.eventIds || []), eventId])].slice(-20);
    same.history = [...(same.history || []), { at: nowIso(), by: `Rule "${rule.name}"`, what: 'matched again - timer restarted' }].slice(-30);
    return { approval: await saveApproval(same), created: false };
  }
  const shown = Object.entries(vars || {}).filter(([k, v]) => v && v !== '-' && k !== 'pc' && k !== 'alert').map(([k, v]) => `${k} ${v}`).join(', ');
  const a = {
    id: newId('apr'), status: 'pending', kind: 'playbook_start',
    title: clip(`Rule "${rule.name}" wants to run "${playbook.name}"${endpoint ? ` on ${endpoint}` : ''}${shown ? ` (${shown})` : ''}`, 200),
    action: null, actionLabel: 'Start playbook', target: '', params: {},
    endpoint: endpoint || '', reason: clip(reason, 600),
    risk: risk != null ? Number(risk) : null, level: clip(level || '', 20), verdict: clip(verdict || '', 20), pattern: clip(pattern || '', 80),
    origin: 'rule', alertId: alertId || null, eventIds: eventId ? [eventId] : [],
    runId: null, stepIndex: null, playbookName: playbook.name, playbookId: playbook.id,
    ruleId: rule.id, ruleName: rule.name, vars: vars || {}, startedRunId: null,
    requestedBy: `Rule "${rule.name}"`, requestedAt: nowIso(), expiresAt, expiresMinutes: minutes,
    decidedBy: null, decidedAt: null, note: '', cmdId: null, result: null, error: null, finishedAt: null,
    occurrences: 1, history: [{ at: nowIso(), by: `Rule "${rule.name}"`, what: 'requested' }],
  };
  return { approval: await saveApproval(a, 'approval:new'), created: true };
}

/** TriGate BLOCK -> pending approvals (only when the agent did not run them itself). */
export async function approvalsFromDecision(decision, agentStatus) {
  if (!approvalsFromTriGate() || !decision) return [];
  const verdict = String(decision.verdict || '').toLowerCase();
  if (!approvalVerdicts().has(verdict)) return [];
  const auto = typeof decision.auto_response === 'boolean' ? decision.auto_response : Boolean(agentStatus?.auto_response);
  if (auto) return []; // agent already ran them (auto_response = true)
  // old decisions replayed from the agent's offline queue: too late to approve
  const ts = new Date(decision.timestamp || Date.now()).getTime();
  if (Number.isFinite(ts) && Date.now() - ts > approvalExpiryMinutes() * 60000) return [];
  const tri = decision.metadata?.trigate || {};
  const ctx = tri.context || {};
  const out = [];
  for (const rec of Array.isArray(tri.recommended) ? tri.recommended : []) {
    if (!TRIGATE_APPROVAL_ACTIONS.has(rec?.action)) continue;
    if (checkTarget(ACTIONS[rec.action].target, rec.target)) continue; // e.g. isolate "this PC" (no IP)
    try {
      const r = await createApproval({
        action: rec.action, target: String(rec.target).trim(),
        params: rec.action === 'restrict_identity' ? { minutes: 30 } : {},
        endpoint: decision.source || decision.endpoint || '',
        platform: decision.platform || decision.metadata?.platform || '',
        title: clip(rec.text || `${actionLabel(rec.action, decision.platform)}: ${rec.target}`, 200),
        reason: clip(`TriGate BLOCK (risk ${tri.risk?.score ?? '?'}): ${ctx.pattern_label || tri.pattern || decision.threat_type || ''}${ctx.description ? ` - ${ctx.description}` : ''}`, 600),
        risk: tri.risk?.score, level: tri.risk?.level, verdict, pattern: tri.pattern || ctx.pattern,
        origin: 'trigate', alertId: decision.event_id ? `tg_${decision.event_id}` : null, eventId: decision.event_id,
        requestedBy: `TriGate (${decision.source || 'agent'})`,
      });
      out.push(r.approval);
      if (r.created) logger.warn(`Approval needed: ${rec.action} ${rec.target} on ${decision.source} (${r.approval.id})`);
    } catch (err) {
      logger.warn(`TriGate approval skipped (${rec.action} ${rec.target}): ${err.message}`);
    }
  }
  return out;
}

export async function listApprovals({ status, limit = 200 } = {}) {
  await sweepExpired();
  const st = status && status !== 'all' ? String(status).split(',').map((s) => s.trim()).filter(Boolean) : undefined;
  return (await db().approvals.list({ status: st, limit: Math.min(1000, Number(limit) || 200) })).map(publicApproval);
}
export async function getApproval(id) { return publicApproval(await db().approvals.get(id)); }
export async function pendingCount() { await sweepExpired(); return db().approvals.count({ status: 'pending' }); }

const httpError = (status, message) => Object.assign(new Error(message), { status });

/** decision: 'approve' | 'reject'. Resolves with the updated approval (action keeps running in the background). */
export async function decideApproval(id, decision, user, note = '') {
  const a = await db().approvals.get(id);
  if (!a) throw httpError(404, 'Approval not found');
  if (a.status === 'pending' && new Date(a.expiresAt).getTime() <= Date.now()) {
    await expireApproval(a);
    throw httpError(409, 'Too late - this approval has expired');
  }
  if (a.status !== 'pending') throw httpError(409, `Already ${a.status}${a.decidedBy ? ` by ${a.decidedBy}` : ''}`);
  const by = whoIs(user);
  if (fourEyes() && decision === 'approve' && by === a.requestedBy) {
    throw httpError(403, 'Four-eyes rule: someone else must approve a request you made (APPROVAL_FOUR_EYES=true)');
  }
  a.decidedBy = by;
  a.decidedAt = nowIso();
  a.note = clip(note, 500);
  if (decision === 'reject') {
    a.status = 'rejected';
    a.history = [...(a.history || []), { at: a.decidedAt, by, what: `rejected${a.note ? `: ${a.note}` : ''}` }];
    const saved = await saveApproval(a);
    logger.info(`Approval ${a.id} rejected by ${by}`);
    if (a.runId) resumeRun(a.runId, a.stepIndex, 'rejected', by).catch((e) => logger.error(`Run resume: ${e.message}`));
    return publicApproval(saved);
  }
  a.history = [...(a.history || []), { at: a.decidedAt, by, what: `approved${a.note ? `: ${a.note}` : ''}` }];
  if (a.kind === 'playbook_start') { // response rule in "Ask first" mode
    try {
      const run = await startRun(a.playbookId, { endpoint: a.endpoint, vars: a.vars, alertId: a.alertId, ruleId: a.ruleId, ruleName: a.ruleName },
        user, `Rule "${a.ruleName}" (approved by ${by})`);
      a.status = 'done';
      a.startedRunId = run.id;
      a.result = `Playbook "${a.playbookName}" started - see Response → Runs`;
    } catch (err) {
      a.status = 'failed';
      a.error = err.message;
    }
    a.finishedAt = nowIso();
    a.history = [...a.history, { at: a.finishedAt, by: 'system', what: a.status === 'done' ? `playbook run ${a.startedRunId} started` : `could not start: ${a.error}` }];
    const saved = await saveApproval(a);
    logger.info(`Approval ${a.id} (rule ${a.ruleName}) approved by ${by}: ${a.status}`);
    return publicApproval(saved);
  }
  if (!a.action) { // playbook gate
    a.status = 'approved';
    const saved = await saveApproval(a);
    logger.info(`Approval ${a.id} (playbook gate) approved by ${by}`);
    resumeRun(a.runId, a.stepIndex, 'approved', by).catch((e) => logger.error(`Run resume: ${e.message}`));
    return publicApproval(saved);
  }
  a.status = 'running';
  const saved = await saveApproval(a);
  logger.info(`Approval ${a.id} approved by ${by}: running ${a.action} ${a.target} on ${a.endpoint}`);
  a._done = executeAction({ endpoint: a.endpoint, action: a.action, target: a.target, params: a.params, by, reason: a.reason })
    .then(async (out) => {
      const cur = (await db().approvals.get(a.id)) || saved;
      cur.status = out.ok ? 'done' : 'failed';
      cur.cmdId = out.cmd_id || null;
      cur.error = out.error || null;
      cur.result = out.result?.message ? clip(out.result.message, 500) : (out.ok ? 'Done' : null);
      cur.finishedAt = nowIso();
      cur.history = [...(cur.history || []), { at: cur.finishedAt, by: cur.endpoint || 'agent', what: out.ok ? 'executed on the PC' : `failed: ${out.error}` }];
      await saveApproval(cur);
      return cur;
    })
    .catch((err) => logger.error(`Approval ${a.id} execution error: ${err.message}`));
  pendingExecutions.set(a.id, a._done);
  a._done.finally(() => pendingExecutions.delete(a.id));
  return publicApproval(saved);
}
const pendingExecutions = new Map();
/** Tests: wait until an approved action finished. */
export const waitForApprovalExecution = (id) => pendingExecutions.get(id) || Promise.resolve();

async function expireApproval(a) {
  a.status = 'expired';
  a.finishedAt = nowIso();
  a.history = [...(a.history || []), { at: a.finishedAt, by: 'system', what: `expired - nobody decided within ${a.expiresMinutes} min` }];
  await saveApproval(a);
  logger.info(`Approval ${a.id} expired`);
  if (a.runId) await resumeRun(a.runId, a.stepIndex, 'expired', 'system').catch((e) => logger.error(`Run resume: ${e.message}`));
}

let sweeping = false;
export async function sweepExpired() {
  if (sweeping) return 0;
  sweeping = true;
  try {
    const open = await db().approvals.list({ status: 'pending', limit: 1000 });
    const late = open.filter((a) => new Date(a.expiresAt).getTime() <= Date.now());
    for (const a of late) await expireApproval(a);
    return late.length;
  } finally { sweeping = false; }
}

// ------------------------------------------------------------------ playbooks
const T = (type, extra) => ({ type, ...extra });
export const BUILT_IN = [
  {
    id: 'builtin_password_guessing', name: 'Contain password guessing',
    description: 'For brute force / many wrong passwords: block the attacker IP, disable the targeted account for 30 minutes, tell the team.',
    steps: [
      T('action', { action: 'block_access', target: '{ip}' }),
      T('action', { action: 'restrict_identity', target: '{user}', params: { minutes: 30 }, onFailure: 'continue' }),
      T('notify', { level: 'warning', message: 'Blocked {ip} and disabled account {user} for 30 min on {pc}' }),
    ],
  },
  {
    id: 'builtin_new_admin', name: 'Suspicious new admin / new account',
    description: 'Someone was added to Administrators or a new account appeared: ask for approval, then disable the account and log it off.',
    steps: [
      T('approval', { message: 'Disable account {user} on {pc}? Check first that it was not a planned IT change.', expiresMinutes: 30 }),
      T('action', { action: 'revoke_identity', target: '{user}' }),
      T('action', { action: 'force_logout', target: '{user}', onFailure: 'continue' }),
      T('notify', { level: 'critical', message: 'Account {user} on {pc} was disabled - confirm with its owner' }),
    ],
  },
  {
    id: 'builtin_bad_ip', name: 'Known-bad IP (threat intelligence)',
    description: 'A program talked to an IP on a threat list: slow the traffic down at once, then block it completely after approval.',
    steps: [
      T('action', { action: 'throttle_segment', target: '{ip}', params: { kbps: 256, minutes: 30 } }),
      T('approval', { message: 'Traffic to {ip} is slowed down. Block {ip} completely on {pc}?', expiresMinutes: 30 }),
      T('action', { action: 'block_access', target: '{ip}' }),
      T('notify', { level: 'warning', message: 'Known-bad IP {ip} blocked on {pc}' }),
    ],
  },
  {
    id: 'builtin_stop_program', name: 'Stop program talking to a bad IP',
    description: 'Kill the program (PID) and block the IP it was talking to.',
    steps: [
      T('action', { action: 'terminate_process', target: '{pid}' }),
      T('action', { action: 'block_access', target: '{ip}' }),
      T('notify', { level: 'warning', message: 'Stopped process {pid} and blocked {ip} on {pc}' }),
    ],
  },
  {
    id: 'builtin_compromised_pc', name: 'Compromised PC - escalate and isolate',
    description: 'Alert every analyst, then after approval cut the PC off from the attacker and open a decoy to watch for more.',
    steps: [
      T('notify', { level: 'critical', message: 'Possible compromise on {pc} (attacker {ip}) - war room' }),
      T('approval', { message: 'Cut {pc} off from {ip} and open a decoy port?', expiresMinutes: 15 }),
      T('action', { action: 'isolate_asset', target: '{ip}' }),
      T('action', { action: 'pseudo_lock', target: '{pc}', onFailure: 'continue' }),
      T('notify', { level: 'critical', message: '{pc} isolated from {ip}; decoy watching for more attempts' }),
    ],
  },
  {
    id: 'builtin_safe_test', name: 'Safe test (changes nothing on the PC)',
    description: 'To try playbooks and approvals safely: a message, a 5 second wait, an approval, a final message.',
    steps: [
      T('notify', { level: 'info', message: 'Test playbook started on {pc}' }),
      T('wait', { seconds: 5 }),
      T('approval', { message: 'Test approval - press Approve or Reject (nothing will change on {pc})', expiresMinutes: 10 }),
      T('notify', { level: 'info', message: 'Test playbook finished on {pc}' }),
    ],
  },
].map((p) => ({ ...p, builtIn: true, enabled: true, createdBy: 'AiBoO', status: 'active' }));

/** Validates / normalises a playbook from the editor. Returns { playbook, errors[] }. */
export function validatePlaybook(body = {}) {
  const errors = [];
  const name = clip(body.name, 80).trim();
  if (!name) errors.push('Name is required');
  const rawSteps = Array.isArray(body.steps) ? body.steps : [];
  if (!rawSteps.length) errors.push('Add at least one step');
  if (rawSteps.length > MAX_STEPS) errors.push(`At most ${MAX_STEPS} steps`);
  const steps = rawSteps.slice(0, MAX_STEPS).map((s, i) => {
    const n = `Step ${i + 1}`;
    const type = String(s?.type || '');
    const onFailure = s?.onFailure === 'continue' ? 'continue' : 'stop';
    const unknownVars = (txt) => varsIn(txt).filter((v) => !VARIABLES[v]);
    if (type === 'action') {
      const action = String(s.action || '');
      if (!ACTIONS[action]) { errors.push(`${n}: choose an action`); return { type, action, target: '', params: {}, onFailure }; }
      const target = clip(s.target ?? '', 200).trim();
      const kind = ACTIONS[action].target;
      const bad = unknownVars(target);
      if (bad.length) errors.push(`${n}: unknown variable {${bad[0]}} (use ${Object.keys(VARIABLES).map((v) => `{${v}}`).join(' ')})`);
      else if (!varsIn(target).length) {
        if (!target && !TARGETS[kind].optional) errors.push(`${n}: target is required (${TARGETS[kind].hint})`);
        else if (target) { const e = checkTarget(kind, target); if (e) errors.push(`${n}: ${e}`); }
      }
      return { type, action, target, params: cleanParams(action, s.params), onFailure };
    }
    if (type === 'approval') {
      const message = clip(s.message, 300).trim() || 'Continue this playbook?';
      const bad = unknownVars(message);
      if (bad.length) errors.push(`${n}: unknown variable {${bad[0]}}`);
      const m = Number(s.expiresMinutes);
      return { type, message, expiresMinutes: Number.isFinite(m) && m > 0 ? Math.min(1440, Math.round(m)) : approvalExpiryMinutes() };
    }
    if (type === 'notify') {
      const message = clip(s.message, 300).trim();
      if (!message) errors.push(`${n}: message is required`);
      const bad = unknownVars(message);
      if (bad.length) errors.push(`${n}: unknown variable {${bad[0]}}`);
      return { type, message, level: ['info', 'warning', 'critical'].includes(s.level) ? s.level : 'info' };
    }
    if (type === 'wait') {
      const sec = Number(s.seconds);
      if (!Number.isFinite(sec) || sec < 1 || sec > MAX_WAIT_SECONDS) errors.push(`${n}: wait 1-${MAX_WAIT_SECONDS} seconds`);
      return { type, seconds: Math.min(MAX_WAIT_SECONDS, Math.max(1, Math.round(sec) || 1)) };
    }
    errors.push(`${n}: unknown step type "${type}"`);
    return { type };
  });
  return {
    errors,
    playbook: { name, description: clip(body.description, 400).trim(), enabled: body.enabled !== false, steps },
  };
}

export const playbookVars = (pb) => {
  const used = new Set();
  for (const s of pb.steps || []) for (const v of [...varsIn(s.target), ...varsIn(s.message)]) used.add(v);
  return [...used];
};
const withVars = (pb) => pb && ({ ...pb, variables: playbookVars(pb), needsPc: (pb.steps || []).some((s) => s.type === 'action' && ACTIONS[s.action]?.agent !== false) });

export async function listPlaybooks() {
  const custom = (await db().playbooks.list({ limit: 500 })).filter((p) => p.status !== 'deleted');
  return [...BUILT_IN.map(clone), ...custom.map((p) => ({ ...p, builtIn: false }))].map(withVars);
}
export async function getPlaybook(id) {
  const b = BUILT_IN.find((p) => p.id === id);
  if (b) return withVars(clone(b));
  const p = await db().playbooks.get(id);
  return p && p.status !== 'deleted' ? withVars({ ...p, builtIn: false }) : null;
}
export async function savePlaybook(id, body, user) {
  if (id && BUILT_IN.some((p) => p.id === id)) throw httpError(400, 'Built-in playbooks cannot be changed - use "Copy & edit"');
  const { playbook, errors } = validatePlaybook(body);
  if (errors.length) throw Object.assign(httpError(400, errors[0]), { errors });
  let doc;
  if (id) {
    const old = await db().playbooks.get(id);
    if (!old || old.status === 'deleted') throw httpError(404, 'Playbook not found');
    doc = { ...old, ...playbook, updatedBy: whoIs(user), updatedAt: nowIso(), version: (old.version || 1) + 1 };
  } else {
    doc = { id: newId('pb'), ...playbook, status: 'active', createdBy: whoIs(user), version: 1 };
  }
  const saved = await db().playbooks.save(doc);
  emit('playbook:updated', { id: saved.id });
  return withVars({ ...saved, builtIn: false });
}
export async function deletePlaybook(id) {
  if (BUILT_IN.some((p) => p.id === id)) throw httpError(400, 'Built-in playbooks cannot be deleted');
  const old = await db().playbooks.get(id);
  if (!old || old.status === 'deleted') throw httpError(404, 'Playbook not found');
  await db().playbooks.remove(id);
  emit('playbook:updated', { id, deleted: true });
  return true;
}

// ------------------------------------------------------------------ runs
const stepLabel = (s) => {
  if (s.type === 'action') return `${actionLabel(s.action)}${s.target ? `: ${s.target}` : ''}${s.params?.minutes ? ` (${s.params.minutes} min)` : ''}`;
  if (s.type === 'approval') return `Wait for approval: ${s.message}`;
  if (s.type === 'notify') return `Notify (${s.level}): ${s.message}`;
  if (s.type === 'wait') return `Wait ${s.seconds} s`;
  return s.type;
};

async function saveRun(run) {
  const saved = await db().runs.save(run);
  emit('run:updated', saved);
  return saved;
}

/** Starts a playbook. vars: {ip, user, pid, badge}. Throws 400 with a clear message when something is missing. */
export async function startRun(playbookId, { endpoint = '', vars = {}, alertId = null, ruleId = null, ruleName = null } = {}, user, startedByText = null) {
  const pb = await getPlaybook(playbookId);
  if (!pb) throw httpError(404, 'Playbook not found');
  if (pb.enabled === false) throw httpError(400, 'This playbook is switched off - edit it and tick "Enabled"');
  const pc = clip(endpoint, 120).trim();
  if (pb.needsPc && !pc) throw httpError(400, 'Choose the PC (endpoint) to run this playbook on');
  if (pb.needsPc && channel && !channel.isOnline?.(pc)) throw httpError(409, `PC '${pc}' is not connected - start the agent on that PC first`);
  const v = {};
  for (const k of Object.keys(VARIABLES)) if (vars?.[k] != null && String(vars[k]).trim()) v[k] = clip(vars[k], 200).trim();
  v.pc = pc || v.pc || '';
  if (alertId) v.alert = clip(alertId, 120);
  const missing = pb.variables.filter((k) => !v[k] && !VARIABLES[k].auto);
  for (const k of pb.variables) if (!v[k]) v[k] = '-'; // {pc} / {alert} in a message, none chosen
  if (missing.length) throw httpError(400, `Please fill in: ${missing.map((k) => VARIABLES[k].label).join(', ')}`);
  const steps = pb.steps.map((s, i) => {
    const r = { ...s };
    if (s.type === 'action') {
      r.target = fill(s.target, v).trim();
      const kind = ACTIONS[s.action].target;
      if (r.target || !TARGETS[kind].optional) {
        const e = checkTarget(kind, r.target);
        if (e) throw httpError(400, `Step ${i + 1} (${actionLabel(s.action)}): ${e}`);
      }
    }
    if (s.message) r.message = fill(s.message, v);
    return { def: r, label: stepLabel(r), status: 'pending', startedAt: null, finishedAt: null, message: '', error: null, cmdId: null, approvalId: null };
  });
  const run = {
    id: newId('run'), playbookId: pb.id, playbookName: pb.name, builtIn: Boolean(pb.builtIn),
    endpoint: pc, vars: v, alertId: alertId || null,
    status: 'running', current: 0, steps,
    startedBy: startedByText ? clip(startedByText, 160) : whoIs(user), startedAt: nowIso(), finishedAt: null, message: '',
    trigger: ruleId ? 'rule' : 'manual', ruleId: ruleId || null, ruleName: ruleName || null,
  };
  const saved = await saveRun(run);
  logger.info(`Playbook "${pb.name}" started by ${run.startedBy} on ${pc || '-'} (${run.id})`);
  advance(run.id).catch((e) => logger.error(`Playbook run ${run.id}: ${e.message}`));
  return saved;
}

const advancing = new Map(); // runId -> promise (one loop per run)
/** Tests: wait until the run loop has paused or finished. */
export const waitForRun = async (runId) => { while (advancing.get(runId)) await advancing.get(runId); };

function advance(runId) {
  if (advancing.has(runId)) return advancing.get(runId);
  const p = (async () => {
    try { await loop(runId); } finally { advancing.delete(runId); }
  })();
  advancing.set(runId, p);
  return p;
}

async function finish(run, status, message) {
  run.status = status;
  run.message = message;
  run.finishedAt = nowIso();
  for (const s of run.steps) if (s.status === 'pending') s.status = 'skipped';
  await saveRun(run);
  logger.info(`Playbook run ${run.id} ${status}: ${message}`);
}

async function loop(runId) {
  for (;;) {
    const run = await db().runs.get(runId);
    if (!run || run.status !== 'running') return;
    const i = run.current;
    if (i >= run.steps.length) return finish(run, 'done', 'All steps finished');
    const step = run.steps[i];
    const def = step.def;
    step.status = 'running';
    step.startedAt = nowIso();
    await saveRun(run);

    if (def.type === 'approval') {
      const a = await createGateApproval({ run, stepIndex: i, message: def.message, expiresMinutes: def.expiresMinutes });
      step.status = 'waiting';
      step.approvalId = a.id;
      step.message = `Waiting for approval (expires ${new Date(a.expiresAt).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })})`;
      run.status = 'waiting_approval';
      await saveRun(run);
      return; // resumeRun() continues when someone decides
    }

    let ok = true;
    if (def.type === 'action') {
      const out = await executeAction({ endpoint: run.endpoint, action: def.action, target: def.target, params: def.params,
        by: run.startedBy, reason: `Playbook "${run.playbookName}"` });
      ok = out.ok;
      step.cmdId = out.cmd_id || null;
      step.error = out.error || null;
      step.message = out.ok ? clip(out.result?.message || 'Done on the PC', 300) : '';
    } else if (def.type === 'notify') {
      emit('pseudolock:notify', { level: def.level, title: `Playbook: ${run.playbookName}`, message: def.message, run_id: run.id, endpoint: run.endpoint });
      step.message = 'Sent to all open dashboards';
    } else if (def.type === 'wait') {
      await new Promise((r) => { const t = setTimeout(r, def.seconds * 1000); t.unref?.(); });
      step.message = `Waited ${def.seconds} s`;
    }

    const latest = await db().runs.get(runId); // cancelled while we were busy?
    if (!latest || latest.status !== 'running') {
      if (latest) { latest.steps[i] = { ...step, status: ok ? 'done' : 'failed', finishedAt: nowIso() }; await saveRun(latest); }
      return;
    }
    step.status = ok ? 'done' : 'failed';
    step.finishedAt = nowIso();
    latest.steps[i] = step;
    latest.current = i + 1;
    if (!ok && def.onFailure !== 'continue') {
      return finish(latest, 'failed', `Step ${i + 1} failed: ${step.error || 'error'} - remaining steps skipped`);
    }
    await saveRun(latest);
  }
}

/** Called when an approval step is approved / rejected / expires. */
export async function resumeRun(runId, stepIndex, outcome, by) {
  const run = await db().runs.get(runId);
  if (!run || run.status !== 'waiting_approval' || run.current !== stepIndex) return null;
  const step = run.steps[stepIndex];
  step.finishedAt = nowIso();
  if (outcome === 'approved') {
    step.status = 'done';
    step.message = `Approved by ${by}`;
    run.status = 'running';
    run.current = stepIndex + 1;
    await saveRun(run);
    advance(runId).catch((e) => logger.error(`Playbook run ${runId}: ${e.message}`));
    return run;
  }
  step.status = 'failed';
  step.message = outcome === 'rejected' ? `Rejected by ${by}` : 'Nobody approved in time (expired)';
  return finish(run, 'stopped', `Stopped at step ${stepIndex + 1}: ${step.message}`);
}

export async function cancelRun(runId, user) {
  const run = await db().runs.get(runId);
  if (!run) throw httpError(404, 'Run not found');
  if (!['running', 'waiting_approval'].includes(run.status)) throw httpError(409, `Run is already ${run.status}`);
  const step = run.steps[run.current];
  if (step?.approvalId) {
    const a = await db().approvals.get(step.approvalId);
    if (a && a.status === 'pending') {
      a.status = 'cancelled';
      a.finishedAt = nowIso();
      a.history = [...(a.history || []), { at: a.finishedAt, by: whoIs(user), what: 'cancelled with the playbook run' }];
      await saveApproval(a);
    }
  }
  if (step && ['waiting', 'running'].includes(step.status)) { step.status = 'failed'; step.message = 'Cancelled'; step.finishedAt = nowIso(); }
  await finish(run, 'cancelled', `Cancelled by ${whoIs(user)}`);
  return db().runs.get(runId);
}

export async function listRuns({ limit = 50, status } = {}) {
  const st = status && status !== 'all' ? String(status).split(',') : undefined;
  return db().runs.list({ status: st, limit: Math.min(500, Number(limit) || 50) });
}
export const getRun = (id) => db().runs.get(id);

async function recoverRuns() {
  const stuck = await db().runs.list({ status: 'running', limit: 200 });
  for (const run of stuck) {
    if (advancing.has(run.id)) continue;
    const step = run.steps[run.current];
    if (step && step.status === 'running') { step.status = 'failed'; step.error = 'Backend restarted during this step'; }
    await finish(run, 'failed', 'Backend restarted while this playbook was running - check the PC, then run it again if needed');
  }
}

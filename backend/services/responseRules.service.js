// backend/services/responseRules.service.js
// PseudoLock RESPONSE RULES: "WHEN this happens -> THEN do that".
// Every final TriGate decision (Gate 3) is checked against the enabled rules in
// order; the FIRST rule that matches decides what happens:
//   auto   - start a playbook at once (no person needed)
//   ask    - a "Pending approval": approving it starts the playbook
//   notify - only a message on every open dashboard
// Safety: cooldown per rule + PC + IP + user, max automatic runs per hour
// (above it the rule asks instead), test mode (only records "would have run"),
// and "test against old alerts" before switching a rule on.
// When no rule takes over, the default behaviour stays (TriGate BLOCK ->
// pending approvals, see pseudolock.service.js approvalsFromDecision).
// Spec: PSEUDOLOCK_SPECIFICATION_v1.0.md §7.7.
import net from 'node:net';
import logger from '../utils/logger.js';
import { alertsSince } from './alertStore.js';
import {
  store, emit, whoIs, getPlaybook, startRun, createPlaybookStartApproval, approvalsFromDecision,
  approvalExpiryMinutes, checkTarget, ACTIONS,
} from './pseudolock.service.js';

// ------------------------------------------------------------------ constants
export const RULE_PATTERNS = [
  ['brute_force', 'Password guessing (many failed logons)'],
  ['failed_logon', 'Failed logon'],
  ['account_lockout', 'Account locked out'],
  ['admin_group_add', 'User added to an admin group'],
  ['account_created', 'New user account created'],
  ['account_deleted', 'User account deleted'],
  ['explicit_credentials', "Logon with someone else's password (RunAs)"],
  ['log_cleared', 'Security log cleared'],
  ['audit_policy_changed', 'Audit policy changed'],
  ['service_installed', 'New service installed'],
  ['scheduled_task', 'Scheduled task created'],
  ['threat_intel_alert', 'Known-bad IP (threat intel)'],
  ['network_intrusion', 'Network intrusion'],
  ['malware', 'Malware'],
  ['memory_threat', 'Malicious code in memory'],
  ['behavioral_anomaly', 'Unusual behaviour'],
  ['anomalous_behavior', 'Unusual behaviour (other engine)'],
  ['geo_velocity', 'Login from an impossible location'],
  ['correlated_attack', 'Attack chain (several alerts linked)'],
  ['identity_mismatch', 'Identity problem'],
  ['insider_threat', 'Insider activity'],
  ['phishing', 'Phishing'],
].map(([id, label]) => ({ id, label }));
const PATTERN_IDS = new Set(RULE_PATTERNS.map((p) => p.id));
const VERDICTS = ['block', 'hold'];
const IMPORTANCE = ['low', 'normal', 'high', 'critical'];
const IP_KINDS = { any: 'Any (or no IP)', internet: 'Internet IP only', office: 'Office / private IP only', none: 'No IP (local, e.g. at the keyboard)' };
const HOURS = { any: 'Any time', office: 'Office hours only', off: 'Outside office hours only' };
const MODES = ['auto', 'ask', 'notify'];

const clip = (v, n = 300) => String(v ?? '').slice(0, n);
const nowIso = () => new Date().toISOString();
const newId = (p) => `${p}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;
const httpError = (status, message) => Object.assign(new Error(message), { status });
const intIn = (v, min, max, def) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.round(n))) : def;
};

/** OFFICE_HOURS=8-20 (start hour inclusive, end hour exclusive), same default as the agent's business_hours. */
export function officeHours() {
  const m = String(process.env.OFFICE_HOURS || '8-20').match(/^\s*(\d{1,2})\s*-\s*(\d{1,2})\s*$/);
  const a = m ? Math.min(23, Number(m[1])) : 8;
  const b = m ? Math.min(24, Number(m[2])) : 20;
  return a < b ? [a, b] : [8, 20];
}
const isOffice = (h) => { const [a, b] = officeHours(); return h >= a && h < b; };

/** 'public' | 'private' | 'local' | 'none' (same idea as the agent's ip_kind). */
export function ipKindOf(ip) {
  const v = String(ip || '').trim().split('%')[0];
  const fam = net.isIP(v);
  if (!fam) return 'none';
  if (fam === 4) {
    const [a, b] = v.split('.').map(Number);
    if (a === 127 || a === 0) return 'local';
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)) return 'private';
    return 'public';
  }
  const low = v.toLowerCase();
  if (low === '::1' || low === '::') return 'local';
  if (/^f[cd]/.test(low) || /^fe[89ab]/.test(low)) return 'private';
  return 'public';
}

export const rulesCatalog = () => ({
  patterns: RULE_PATTERNS, verdicts: VERDICTS, importance: IMPORTANCE,
  ipKinds: Object.entries(IP_KINDS).map(([id, label]) => ({ id, label })),
  hours: Object.entries(HOURS).map(([id, label]) => ({ id, label })),
  officeHours: officeHours(),
});

// ------------------------------------------------------------------ validation
export async function validateRule(body = {}) {
  const errors = [];
  const name = clip(body.name, 80).trim();
  if (!name) errors.push('Name is required');
  const mode = MODES.includes(body.mode) ? body.mode : null;
  if (!mode) errors.push('Choose what to do: Run automatically, Ask first or Notify only');
  const c = body.conditions || {};
  const patterns = [...new Set((Array.isArray(c.patterns) ? c.patterns : []).map(String))];
  const badPat = patterns.filter((p) => !PATTERN_IDS.has(p));
  if (badPat.length) errors.push(`Unknown attack type: ${badPat[0]}`);
  const verdicts = [...new Set((Array.isArray(c.verdicts) ? c.verdicts : ['block']).map((v) => String(v).toLowerCase()))].filter((v) => VERDICTS.includes(v));
  if (!verdicts.length) errors.push('Tick at least one TriGate verdict (BLOCK and/or HOLD)');
  const importance = [...new Set((Array.isArray(c.importance) ? c.importance : []).map(String))].filter((v) => IMPORTANCE.includes(v));
  const pcs = [...new Set((Array.isArray(c.pcs) ? c.pcs : String(c.pcs || '').split(','))
    .map((x) => clip(x, 120).trim()).filter(Boolean))].slice(0, 50);
  const conditions = {
    patterns: patterns.filter((p) => PATTERN_IDS.has(p)),
    minRisk: intIn(c.minRisk, 0, 100, 55),
    verdicts,
    pcs,
    importance,
    ipKind: IP_KINDS[c.ipKind] ? c.ipKind : 'any',
    hours: HOURS[c.hours] ? c.hours : 'any',
  };
  let playbookId = clip(body.playbookId, 80).trim() || null;
  let playbookName = null;
  if (mode && mode !== 'notify') {
    const pb = playbookId ? await getPlaybook(playbookId) : null;
    if (!pb) errors.push('Choose the playbook to run');
    else if (pb.enabled === false) errors.push(`Playbook "${pb.name}" is switched off - switch it on first`);
    else playbookName = pb.name;
  } else if (mode === 'notify') { playbookId = null; }
  const rule = {
    name,
    description: clip(body.description, 300).trim(),
    enabled: body.enabled !== false,
    testMode: Boolean(body.testMode),
    mode: mode || 'notify',
    playbookId, playbookName,
    notifyLevel: ['info', 'warning', 'critical'].includes(body.notifyLevel) ? body.notifyLevel : 'warning',
    conditions,
    cooldownMinutes: intIn(body.cooldownMinutes, 0, 1440, 30),
    maxPerHour: intIn(body.maxPerHour, 1, 100, 10),
  };
  return { rule, errors };
}

// ------------------------------------------------------------------ CRUD
const lastFired = new Map(); // `${ruleId}|${pc}|${ip}|${user}` -> ms (cooldown timers, memory only)
/** Saving / switching a rule starts its cooldowns fresh (e.g. after leaving test mode). */
const resetCooldowns = (ruleId) => { for (const k of [...lastFired.keys()]) if (k.startsWith(`${ruleId}|`)) lastFired.delete(k); };

const sortRules = (list) => list.sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0) || new Date(a.createdAt) - new Date(b.createdAt));

export async function listRules() {
  return sortRules((await store().rules.list({ limit: 500 })).filter((r) => r.status !== 'deleted'));
}
export async function getRule(id) {
  const r = await store().rules.get(id);
  return r && r.status !== 'deleted' ? r : null;
}
export async function saveRule(id, body, user) {
  const { rule, errors } = await validateRule(body);
  if (errors.length) throw Object.assign(httpError(400, errors[0]), { errors });
  let doc;
  if (id) {
    const old = await getRule(id);
    if (!old) throw httpError(404, 'Rule not found');
    doc = { ...old, ...rule, updatedBy: whoIs(user), version: (old.version || 1) + 1 };
  } else {
    const all = await listRules();
    doc = {
      id: newId('rule'), ...rule, status: 'active', priority: all.length ? Math.max(...all.map((r) => r.priority ?? 0)) + 1 : 0,
      createdBy: whoIs(user), version: 1, stats: { triggered: 0, lastTriggeredAt: null, lastOutcome: null },
    };
  }
  const saved = await store().rules.save(doc);
  resetCooldowns(saved.id);
  emit('rule:updated', { id: saved.id });
  logger.info(`Response rule "${saved.name}" saved by ${whoIs(user)} (${saved.enabled ? 'on' : 'off'}${saved.testMode ? ', test mode' : ''})`);
  return saved;
}
export async function setRuleEnabled(id, enabled, user) {
  const old = await getRule(id);
  if (!old) throw httpError(404, 'Rule not found');
  const saved = await store().rules.save({ ...old, enabled: Boolean(enabled), updatedBy: whoIs(user) });
  resetCooldowns(id);
  emit('rule:updated', { id });
  return saved;
}
export async function deleteRule(id) {
  if (!(await getRule(id))) throw httpError(404, 'Rule not found');
  await store().rules.remove(id);
  emit('rule:updated', { id, deleted: true });
}
/** ids = full new order (first = checked first). */
export async function reorderRules(ids) {
  const all = await listRules();
  const order = Array.isArray(ids) ? ids.map(String) : [];
  let i = 0;
  for (const id of order) {
    const r = all.find((x) => x.id === id);
    if (r) await store().rules.save({ ...r, priority: i++ });
  }
  for (const r of all.filter((x) => !order.includes(x.id))) await store().rules.save({ ...r, priority: i++ });
  emit('rule:updated', { reordered: true });
  return listRules();
}

// ------------------------------------------------------------------ matching
/** The facts a rule looks at, from a live TriGate decision. */
export function factsFromDecision(d, agentStatus) {
  const tri = d?.metadata?.trigate || {};
  const ctx = tri.context || {};
  const ip = String(ctx.src_ip || '').trim();
  const kind = ctx.ip_kind || ipKindOf(ip);
  const user = String(ctx.subject || ctx.entity || tri.subject || tri.entity || '').trim();
  return {
    pattern: String(tri.pattern || ctx.pattern || ''),
    patternLabel: ctx.pattern_label || tri.pattern || '',
    risk: Number(tri.risk?.score ?? 0),
    level: tri.risk?.level || '',
    verdict: String(d?.verdict || '').toLowerCase(),
    pc: String(d?.source || d?.endpoint || ''),
    importance: tri.impact?.importance || agentStatus?.importance || null,
    ipKind: kind,
    hour: Number.isInteger(ctx.local_hour) ? ctx.local_hour : new Date(d?.timestamp || Date.now()).getHours(),
    vars: {
      ...(kind === 'public' || kind === 'private' ? { ip } : {}),
      ...(user && user !== 'unknown' && user !== '-' ? { user } : {}),
      ...(String(ctx.pid ?? '').match(/^\d+$/) ? { pid: String(ctx.pid) } : {}),
    },
    alertId: d?.event_id ? `tg_${d.event_id}` : null,
    eventId: d?.event_id || null,
    description: ctx.description || d?.reason || '',
  };
}

/** Same facts from a stored alert (for "test against old alerts"). */
function factsFromAlert(a) {
  const kind = a.data?.ip_kind || ipKindOf(a.srcIp);
  const tz = process.env.REPORT_TZ || undefined;
  let hour = a.data?.local_hour;
  if (!Number.isInteger(hour)) {
    try { hour = Number(new Intl.DateTimeFormat('en-GB', { hour: 'numeric', hour12: false, timeZone: tz }).format(new Date(a.firstSeen))) % 24; } catch { hour = new Date(a.firstSeen).getHours(); }
  }
  return {
    pattern: a.pattern || '', risk: Number(a.riskScore || 0), verdict: String(a.verdict || '').toLowerCase(),
    pc: a.source || '', importance: a.data?.importance || null, ipKind: kind, hour,
  };
}

/** Returns null when it matches, otherwise the reason it does not. */
export function whyNot(cond, f) {
  if (cond.patterns?.length && !cond.patterns.includes(f.pattern)) return 'other attack type';
  if (f.risk < (cond.minRisk ?? 0)) return `risk ${f.risk} < ${cond.minRisk}`;
  if (!(cond.verdicts || ['block']).includes(f.verdict)) return `verdict ${f.verdict || '?'}`;
  if (cond.pcs?.length && !cond.pcs.some((p) => p.toLowerCase() === String(f.pc).toLowerCase())) return 'other PC';
  if (cond.importance?.length && !cond.importance.includes(f.importance)) return f.importance ? `PC importance ${f.importance}` : 'PC importance unknown';
  if (cond.ipKind === 'internet' && f.ipKind !== 'public') return 'not an internet IP';
  if (cond.ipKind === 'office' && f.ipKind !== 'private') return 'not an office IP';
  if (cond.ipKind === 'none' && !['none', 'local'].includes(f.ipKind)) return 'has an IP';
  if (cond.hours === 'office' && !isOffice(f.hour)) return 'outside office hours';
  if (cond.hours === 'off' && isOffice(f.hour)) return 'during office hours';
  return null;
}

// ------------------------------------------------------------------ live handling

async function logEvent(rule, facts, outcome, extra = {}) {
  const ev = {
    id: newId('rev'), status: outcome, ruleId: rule.id, ruleName: rule.name, mode: rule.mode, testMode: Boolean(rule.testMode),
    outcome, at: nowIso(), endpoint: facts.pc, pattern: facts.pattern, risk: facts.risk, verdict: facts.verdict,
    vars: facts.vars || {}, alertId: facts.alertId, eventId: facts.eventId,
    playbookId: rule.playbookId || null, playbookName: rule.playbookName || null,
    runId: null, approvalId: null, message: '', ...extra,
  };
  const saved = await store().ruleEvents.save(ev);
  emit('rule:event', saved);
  // stats on the rule itself
  const r = await getRule(rule.id);
  if (r && !['cooldown'].includes(outcome)) {
    r.stats = { triggered: (r.stats?.triggered || 0) + 1, lastTriggeredAt: ev.at, lastOutcome: outcome };
    await store().rules.save(r);
  }
  return saved;
}

async function runsLastHour(ruleId) {
  const since = Date.now() - 3600e3;
  return (await store().ruleEvents.list({ status: 'ran', limit: 500 }))
    .filter((e) => e.ruleId === ruleId && new Date(e.at).getTime() >= since).length;
}

/**
 * Handles one matched rule. Returns true when the rule "took over" (a playbook
 * was started / asked for, or it is in cooldown) - then the default TriGate
 * approvals are NOT created, so the same thing is not asked twice.
 */
async function apply(rule, facts) {
  const key = `${rule.id}|${facts.pc}|${facts.vars.ip || ''}|${facts.vars.user || ''}`;
  const cool = (rule.cooldownMinutes ?? 30) * 60000;
  const last = lastFired.get(key);
  if (cool > 0 && last && Date.now() - last < cool) {
    await logEvent(rule, facts, 'cooldown', { message: `Already handled ${Math.round((Date.now() - last) / 60000)} min ago (cooldown ${rule.cooldownMinutes} min)` });
    return !rule.testMode && rule.mode !== 'notify';
  }
  lastFired.set(key, Date.now());

  const what = `${facts.patternLabel || facts.pattern} on ${facts.pc || '?'} (risk ${facts.risk}${facts.vars.ip ? `, IP ${facts.vars.ip}` : ''}${facts.vars.user ? `, user ${facts.vars.user}` : ''})`;
  if (rule.testMode) {
    const would = rule.mode === 'notify' ? 'send a notification' : rule.mode === 'ask' ? `ask to run "${rule.playbookName}"` : `run "${rule.playbookName}"`;
    await logEvent(rule, facts, 'test', { message: `TEST MODE - would have: ${would}. Matched: ${what}` });
    return false;
  }
  if (rule.mode === 'notify') {
    emit('pseudolock:notify', { level: rule.notifyLevel, title: `Rule: ${rule.name}`, message: what, endpoint: facts.pc });
    await logEvent(rule, facts, 'notified', { message: `Notification sent: ${what}` });
    return false;
  }

  const pb = await getPlaybook(rule.playbookId);
  if (!pb || pb.enabled === false) {
    await logEvent(rule, facts, 'skipped', { message: `Playbook ${pb ? `"${pb.name}" is switched off` : 'was deleted'} - rule did nothing` });
    emit('pseudolock:notify', { level: 'warning', title: `Rule: ${rule.name}`, message: 'Its playbook is missing or switched off - nothing was done' });
    return false;
  }
  const vars = { ...facts.vars };
  const missing = pb.variables.filter((v) => !['pc', 'alert'].includes(v) && !vars[v]);
  if (missing.length) {
    await logEvent(rule, facts, 'skipped', { message: `This event has no ${missing.join(', ')} - playbook "${pb.name}" needs it, rule skipped. Matched: ${what}` });
    return false;
  }
  for (const s of pb.steps.filter((x) => x.type === 'action')) { // e.g. user name with characters the agent refuses
    const target = String(s.target || '').replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? (k === 'pc' ? facts.pc : ''));
    const kind = ACTIONS[s.action]?.target;
    if (kind && target && checkTarget(kind, target)) {
      await logEvent(rule, facts, 'skipped', { message: `Not run: ${checkTarget(kind, target)}` });
      return false;
    }
  }

  let mode = rule.mode;
  let limitNote = '';
  if (mode === 'auto' && (await runsLastHour(rule.id)) >= (rule.maxPerHour ?? 10)) {
    mode = 'ask';
    limitNote = `Limit of ${rule.maxPerHour} automatic runs per hour reached - asking instead. `;
    emit('pseudolock:notify', { level: 'warning', title: `Rule: ${rule.name}`, message: `${limitNote}Check Response → Approvals.` });
  }
  const reason = `${limitNote}Rule "${rule.name}" matched: ${what}${facts.description ? ` - ${facts.description}` : ''}`;
  if (mode === 'ask') {
    const r = await createPlaybookStartApproval({
      rule, playbook: pb, endpoint: facts.pc, vars, alertId: facts.alertId, eventId: facts.eventId,
      reason, risk: facts.risk, level: facts.level, verdict: facts.verdict, pattern: facts.pattern,
    });
    await logEvent(rule, facts, 'asked', { approvalId: r.approval.id, message: `${limitNote}Approval requested: ${r.approval.title}` });
    return true;
  }
  try {
    const run = await startRun(pb.id, { endpoint: facts.pc, vars, alertId: facts.alertId, ruleId: rule.id, ruleName: rule.name }, null, `Rule "${rule.name}"`);
    await logEvent(rule, facts, 'ran', { runId: run.id, message: `Started "${pb.name}" automatically. Matched: ${what}` });
    logger.warn(`Response rule "${rule.name}" started playbook "${pb.name}" on ${facts.pc} (${run.id})`);
  } catch (err) {
    await logEvent(rule, facts, 'failed', { message: `Could not start "${pb.name}": ${err.message}` });
    emit('pseudolock:notify', { level: 'warning', title: `Rule: ${rule.name}`, message: `Could not start "${pb.name}": ${err.message}` });
  }
  return true;
}

/**
 * Called for every TriGate decision the agent sends (routes/agent.routes.js).
 * First matching enabled rule wins; otherwise the default approvals apply.
 */
export async function onTriGateDecision(decision, agentStatus) {
  if (!decision) return { rule: null };
  const verdict = String(decision.verdict || '').toLowerCase();
  const ts = new Date(decision.timestamp || Date.now()).getTime();
  const fresh = !Number.isFinite(ts) || Date.now() - ts <= approvalExpiryMinutes() * 60000; // not a replay of old queued events
  let matched = null;
  let tookOver = false;
  if (fresh && VERDICTS.includes(verdict)) {
    const facts = factsFromDecision(decision, agentStatus);
    for (const rule of (await listRules()).filter((r) => r.enabled)) {
      if (whyNot(rule.conditions || {}, facts) === null) {
        matched = rule;
        try { tookOver = await apply(rule, facts); } catch (err) { logger.error(`Rule "${rule.name}" failed: ${err.message}`); }
        break;
      }
    }
  }
  const approvals = tookOver ? [] : await approvalsFromDecision(decision, agentStatus);
  return { rule: matched, tookOver, approvals };
}

// ------------------------------------------------------------------ preview + activity
/** "Test against old alerts": which TriGate alerts of the last N days this rule would have matched. */
export async function previewRule(body, days = 30) {
  const { rule } = await validateRule({ name: 'preview', mode: 'notify', ...body });
  const d = intIn(days, 1, 365, 30);
  const alerts = (await alertsSince(new Date(Date.now() - d * 86400e3))).filter((a) => a.kind === 'trigate');
  const hits = [];
  let unknownImportance = 0;
  const notReasons = {};
  for (const a of alerts) {
    const f = factsFromAlert(a);
    const why = whyNot(rule.conditions, f);
    if (why === null) hits.push(a);
    else {
      notReasons[why.replace(/\d+/g, 'N')] = (notReasons[why.replace(/\d+/g, 'N')] || 0) + 1;
      if (why === 'PC importance unknown') unknownImportance += 1;
    }
  }
  hits.sort((a, b) => new Date(b.firstSeen) - new Date(a.firstSeen));
  return {
    days: d, checked: alerts.length, matched: hits.length, unknownImportance,
    perDay: Math.round((hits.length / d) * 10) / 10,
    samples: hits.slice(0, 15).map((a) => ({
      alertId: a.alertId, title: a.title, source: a.source, risk: a.riskScore, verdict: a.verdict, srcIp: a.srcIp,
      user: a.subject || a.entity, when: a.firstSeen, occurrences: a.occurrences,
    })),
    notMatchedBecause: Object.entries(notReasons).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([reason, count]) => ({ reason, count })),
  };
}

export async function ruleActivity({ limit = 100, ruleId } = {}) {
  const list = await store().ruleEvents.list({ limit: Math.min(1000, intIn(limit, 1, 1000, 100) * (ruleId ? 5 : 1)) });
  return (ruleId ? list.filter((e) => e.ruleId === ruleId) : list).slice(0, intIn(limit, 1, 1000, 100));
}

/** Tests only. */
export const __resetRuleCooldowns = () => lastFired.clear();

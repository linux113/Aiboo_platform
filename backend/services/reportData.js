// backend/services/reportData.js
// One place that calculates every number used by the Executive dashboard,
// the charts / trends, and the Risk / Compliance / Executive reports
// (JSON, CSV and PDF all use exactly the same figures).
import { alertsSince, complianceSince, latestCompliance } from './alertStore.js';
import { getAgentStore } from '../routes/agent.routes.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const OPEN_WEIGHT = { critical: 15, high: 8, medium: 3, low: 1 };
const DAY = 86400000;

export const clampDays = (d, def = 30) => Math.min(365, Math.max(1, Number(d) || def));

export const safeTz = (tz) => {
  const want = String(tz || process.env.REPORT_TZ || 'UTC');
  try {
    new Intl.DateTimeFormat('en-CA', { timeZone: want });
    return want;
  } catch {
    return 'UTC';
  }
};

const dayKey = (date, tz) => new Intl.DateTimeFormat('en-CA', {
  timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
}).format(new Date(date)); // YYYY-MM-DD

const countBy = (rows, fn) => {
  const out = {};
  rows.forEach((r) => {
    const k = fn(r);
    if (k === undefined || k === null || k === '') return;
    out[k] = (out[k] || 0) + 1;
  });
  return out;
};

const top = (obj, n = 8) => Object.entries(obj)
  .sort((a, b) => b[1] - a[1])
  .slice(0, n)
  .map(([name, count]) => ({ name, count }));

const avgMinutes = (rows, field) => {
  const vals = rows
    .filter((a) => a[field] && a.firstSeen)
    .map((a) => (new Date(a[field]) - new Date(a.firstSeen)) / 60000)
    .filter((m) => Number.isFinite(m) && m >= 0);
  if (!vals.length) return null;
  return Math.round((vals.reduce((s, v) => s + v, 0) / vals.length) * 10) / 10;
};

// Daily counts per severity, every day present (empty days = 0)
export const buildTrend = (alerts, days, tz) => {
  const map = {};
  for (let i = days - 1; i >= 0; i -= 1) {
    const k = dayKey(Date.now() - i * DAY, tz);
    map[k] = { date: k, critical: 0, high: 0, medium: 0, low: 0, total: 0, closed: 0 };
  }
  alerts.forEach((a) => {
    const k = dayKey(a.firstSeen || a.lastSeen, tz);
    if (!map[k]) return;
    const s = SEVERITIES.includes(a.severity) ? a.severity : 'medium';
    map[k][s] += 1;
    map[k].total += 1;
  });
  alerts.forEach((a) => {
    if (!a.closedAt) return;
    const k = dayKey(a.closedAt, tz);
    if (map[k]) map[k].closed += 1;
  });
  return Object.values(map);
};

const complianceTrend = (reports, days, tz) => {
  const map = {};
  for (let i = days - 1; i >= 0; i -= 1) {
    const k = dayKey(Date.now() - i * DAY, tz);
    map[k] = { date: k, sum: 0, n: 0 };
  }
  reports.forEach((r) => {
    if (r.score === null || r.score === undefined) return;
    const k = dayKey(r.checkedAt, tz);
    if (!map[k]) return;
    map[k].sum += Number(r.score);
    map[k].n += 1;
  });
  return Object.values(map).map((d) => ({ date: d.date, score: d.n ? Math.round(d.sum / d.n) : null }));
};

// Security posture 0-100 (higher = safer)
export const postureScore = (openAlerts, avgCompliance) => {
  const penalty = Math.min(60, openAlerts.reduce((s, a) => s + (OPEN_WEIGHT[a.severity] || 1), 0));
  const compPenalty = avgCompliance === null ? 0 : 0.4 * (100 - avgCompliance);
  const score = Math.max(0, Math.min(100, Math.round(100 - penalty - compPenalty)));
  const level = score >= 80 ? 'good' : score >= 60 ? 'fair' : score >= 40 ? 'poor' : 'critical';
  return { score, level, alertPenalty: penalty, compliancePenalty: Math.round(compPenalty) };
};

// Everything the dashboards and reports need, for the last `days` days.
export const buildAnalytics = async ({ days = 30, tz } = {}) => {
  const d = clampDays(days);
  const zone = safeTz(tz);
  const since = new Date(Date.now() - d * DAY);
  const prevSince = new Date(Date.now() - 2 * d * DAY);

  const [all, compRows, latest] = await Promise.all([
    alertsSince(prevSince), complianceSince(since), latestCompliance(),
  ]);
  const inWindow = all.filter((a) => new Date(a.firstSeen || a.lastSeen) >= since);
  const previous = all.filter((a) => {
    const t = new Date(a.firstSeen || a.lastSeen);
    return t >= prevSince && t < since;
  });
  // open alerts count regardless of age (an old unhandled alert is still a risk)
  const openAll = (await alertsSince(new Date(Date.now() - 365 * DAY))).filter((a) => a.status !== 'closed');

  const store = getAgentStore();
  // prefer the live copy (full detail), fall back to stored history
  const latestByEp = {};
  latest.forEach((r) => { latestByEp[r.endpoint] = r; });
  Object.values(store.compliance || {}).forEach((r) => {
    latestByEp[r.endpoint] = { ...r, checkedAt: r.checked_at || r.received_at };
  });
  const latestList = Object.values(latestByEp);
  const scored = latestList.filter((r) => r.score !== null && r.score !== undefined);
  const avgCompliance = scored.length
    ? Math.round(scored.reduce((s, r) => s + Number(r.score), 0) / scored.length)
    : null;

  // most common failing compliance checks across all PCs
  const failing = {};
  latestList.forEach((r) => (r.checks || []).forEach((c) => {
    if (c.status !== 'fail' && c.status !== 'warn') return;
    const k = c.id || c.title;
    if (!failing[k]) failing[k] = { id: c.id, title: c.title || c.id, status: c.status, endpoints: [], fix: c.fix || '', iso: c.iso27001 || [], nist: c.nist_csf || [] };
    failing[k].endpoints.push(r.endpoint);
    if (c.status === 'fail') failing[k].status = 'fail';
  }));

  const closed = inWindow.filter((a) => a.status === 'closed');
  const fp = closed.filter((a) => a.closeReason === 'false_positive').length;
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, inWindow.filter((a) => a.severity === s).length]));
  const openBySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, openAll.filter((a) => a.severity === s).length]));

  const endpoints = Object.values(store.endpoints || {});
  const online = endpoints.filter((e) => e.lastSeen && Date.now() - new Date(e.lastSeen) < 2 * 60 * 1000).length;
  const gate = store.gateDecisions || [];
  const verdicts = countBy(gate, (g) => String(g.verdict || '').toLowerCase());

  const statusList = Object.values(store.agentStatus || {});
  const intel = statusList.reduce((acc, s) => {
    const ti = s.threat_intel || {};
    acc.feedEntries = Math.max(acc.feedEntries, Number(ti.feed_entries || 0));
    acc.matches += Number(ti.matches || 0);
    acc.scans += Number(ti.scans || 0);
    acc.behaviourAlerts += Number(s.behaviour?.alerts || 0);
    acc.incidents += Number(s.correlation?.emitted || 0);
    acc.restrictions += (s.access_control?.restrictions || []).length;
    acc.throttles += (s.access_control?.throttles || []).length;
    return acc;
  }, { feedEntries: 0, matches: 0, scans: 0, behaviourAlerts: 0, incidents: 0, restrictions: 0, throttles: 0 });

  const posture = postureScore(openAll, avgCompliance);
  const pct = (cur, prev) => (prev ? Math.round(((cur - prev) / prev) * 100) : null);

  return {
    generatedAt: new Date().toISOString(),
    days: d,
    tz: zone,
    kpis: {
      totalAlerts: inWindow.length,
      previousAlerts: previous.length,
      changePct: pct(inWindow.length, previous.length),
      open: openAll.filter((a) => a.status === 'open').length,
      acknowledged: openAll.filter((a) => a.status === 'acknowledged').length,
      openCritical: openBySeverity.critical,
      openHigh: openBySeverity.high,
      closed: closed.length,
      unassigned: openAll.filter((a) => !a.assignee).length,
      mttaMinutes: avgMinutes(inWindow, 'acknowledgedAt'),
      mttrMinutes: avgMinutes(inWindow, 'closedAt'),
      falsePositiveRate: closed.length ? Math.round((fp / closed.length) * 100) : null,
      incidents: inWindow.filter((a) => a.kind === 'incident').length,
      blocked: inWindow.filter((a) => a.verdict === 'block').length,
      held: inWindow.filter((a) => a.verdict === 'hold').length,
      endpoints: endpoints.length,
      endpointsOnline: online,
      avgCompliance,
    },
    posture,
    bySeverity,
    openBySeverity,
    byStatus: countBy(inWindow, (a) => a.status),
    byKind: countBy(inWindow, (a) => a.kind),
    byCloseReason: countBy(closed, (a) => a.closeReason || 'resolved'),
    topPatterns: top(countBy(inWindow, (a) => a.pattern)),
    topEntities: top(countBy(inWindow, (a) => a.entity || a.subject)),
    topSources: top(countBy(inWindow, (a) => a.source)),
    topIps: top(countBy(inWindow, (a) => a.srcIp)),
    trend: buildTrend(inWindow, d, zone),
    gateVerdicts: verdicts,
    intel,
    compliance: {
      average: avgCompliance,
      endpoints: latestList.map((r) => ({
        endpoint: r.endpoint, score: r.score, counts: r.counts || {}, checkedAt: r.checkedAt || r.checked_at,
        frameworks: r.frameworks || {},
      })),
      failing: Object.values(failing).sort((a, b) => b.endpoints.length - a.endpoints.length),
      trend: complianceTrend(compRows, d, zone),
      checks: latestList.length === 1 ? (latestList[0].checks || []) : [],
      byEndpoint: Object.fromEntries(latestList.map((r) => [r.endpoint, { endpoint: r.endpoint, checks: r.checks || [] }])),
    },
    recentCritical: inWindow
      .filter((a) => ['critical', 'high'].includes(a.severity))
      .sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen))
      .slice(0, 10)
      .map((a) => ({
        alertId: a.alertId, title: a.title, severity: a.severity, status: a.status, riskScore: a.riskScore,
        source: a.source, entity: a.entity, firstSeen: a.firstSeen, assignee: a.assignee,
      })),
    alerts: inWindow,
  };
};

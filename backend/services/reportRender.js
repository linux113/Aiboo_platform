// backend/services/reportRender.js
// Turns the analytics data into downloadable reports:
//   CSV (opens in Excel) and PDF (KPI boxes, tables and a trend bar chart).
// Report types: risk | compliance | executive
import PDFDocument from 'pdfkit';

export const REPORT_TYPES = {
  risk: 'Risk Report',
  compliance: 'Compliance Report',
  executive: 'Executive Security Summary',
};

const SEV_COLOR = { critical: '#b91c1c', high: '#ea580c', medium: '#ca8a04', low: '#2563eb' };
const STATUS_COLOR = { pass: '#15803d', warn: '#ca8a04', fail: '#b91c1c', unknown: '#6b7280' };

// ------------------------------------------------------------------ helpers
const fmtMin = (m) => {
  if (m === null || m === undefined) return 'n/a';
  if (m < 60) return `${m} min`;
  if (m < 1440) return `${Math.round((m / 60) * 10) / 10} h`;
  return `${Math.round((m / 1440) * 10) / 10} days`;
};

const fmtDate = (d, tz) => {
  if (!d) return '';
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: tz, year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
    }).format(new Date(d));
  } catch {
    return String(d);
  }
};

// Standard PDF fonts only know Latin-1: replace anything else safely
const txt = (v) => String(v ?? '')
  .replace(/[\u2013\u2014]/g, '-')
  .replace(/[\u2018\u2019]/g, "'")
  .replace(/[\u201c\u201d]/g, '"')
  .replace(/\u2265/g, '>=')
  .replace(/\u2264/g, '<=')
  .replace(/\u2026/g, '...')
  .replace(/[^\x09\x0a\x0d\x20-\x7e\xa0-\xff]/g, '?');

// ---------------------------------------------------------------------- CSV
const csvCell = (v) => {
  let s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join('; ') : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // stop Excel formula injection
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const csvRows = (rows) => rows.map((r) => r.map(csvCell).join(',')).join('\r\n');

const kpiRows = (a) => [
  ['Period (days)', a.days],
  ['Time zone', a.tz],
  ['Security posture score (0-100, higher = safer)', a.posture.score],
  ['Posture level', a.posture.level],
  ['Alerts in period', a.kpis.totalAlerts],
  ['Alerts in previous period', a.kpis.previousAlerts],
  ['Change vs previous period (%)', a.kpis.changePct ?? 'n/a'],
  ['Open alerts', a.kpis.open],
  ['Acknowledged (being handled)', a.kpis.acknowledged],
  ['Open critical', a.kpis.openCritical],
  ['Open high', a.kpis.openHigh],
  ['Closed in period', a.kpis.closed],
  ['Unassigned open alerts', a.kpis.unassigned],
  ['Mean time to acknowledge', fmtMin(a.kpis.mttaMinutes)],
  ['Mean time to resolve', fmtMin(a.kpis.mttrMinutes)],
  ['False positive rate (%)', a.kpis.falsePositiveRate ?? 'n/a'],
  ['Correlated incidents', a.kpis.incidents],
  ['TriGate BLOCK decisions', a.kpis.blocked],
  ['TriGate HOLD decisions', a.kpis.held],
  ['Endpoints (online / known)', `${a.kpis.endpointsOnline} / ${a.kpis.endpoints}`],
  ['Average compliance score', a.kpis.avgCompliance ?? 'n/a'],
];

const alertHeader = ['Alert ID', 'First seen', 'Last seen', 'Severity', 'Risk', 'Type', 'Status', 'Title',
  'User / entity', 'Source IP', 'Endpoint', 'Pattern', 'Assignee', 'Close reason', 'Occurrences'];
const alertRow = (x, tz) => [x.alertId, fmtDate(x.firstSeen, tz), fmtDate(x.lastSeen, tz), x.severity, x.riskScore,
  x.kind, x.status, x.title, x.entity || x.subject, x.srcIp, x.source, x.pattern, x.assignee, x.closeReason,
  x.occurrences];

const complianceRows = (a) => {
  const rows = [['Endpoint', 'Score', 'Check', 'Status', 'ISO 27001:2022', 'NIST CSF 2.0', 'Detail', 'How to fix']];
  a.compliance.endpoints.forEach((ep) => {
    const full = a.compliance.byEndpoint?.[ep.endpoint]?.checks || [];
    if (!full.length) rows.push([ep.endpoint, ep.score ?? 'n/a', '(no check detail stored)', '', '', '', '', '']);
    full.forEach((c) => rows.push([ep.endpoint, ep.score ?? 'n/a', c.title, c.status,
      c.iso27001 || [], c.nist_csf || [], c.detail, c.fix]));
  });
  return rows;
};

export const toCsv = (type, a) => {
  const parts = [];
  parts.push(csvRows([[`AiBoO ${REPORT_TYPES[type]}`], ['Generated', fmtDate(a.generatedAt, a.tz)]]));
  if (type === 'executive' || type === 'risk') {
    parts.push(csvRows([['Key figures'], ['Metric', 'Value'], ...kpiRows(a)]));
  }
  if (type === 'executive') {
    parts.push(csvRows([['Daily trend'], ['Date', 'Critical', 'High', 'Medium', 'Low', 'Total', 'Closed'],
      ...a.trend.map((d) => [d.date, d.critical, d.high, d.medium, d.low, d.total, d.closed])]));
    parts.push(csvRows([['Top attack patterns'], ['Pattern', 'Alerts'], ...a.topPatterns.map((t) => [t.name, t.count])]));
    parts.push(csvRows([['Most targeted users'], ['User', 'Alerts'], ...a.topEntities.map((t) => [t.name, t.count])]));
  }
  if (type === 'risk') {
    parts.push(csvRows([['Alerts'], alertHeader, ...a.alerts
      .slice().sort((x, y) => (y.riskScore || 0) - (x.riskScore || 0))
      .map((x) => alertRow(x, a.tz))]));
  }
  if (type === 'compliance' || type === 'executive') {
    parts.push(csvRows([['Compliance'], ['Average score', a.compliance.average ?? 'n/a']]));
    parts.push(csvRows(complianceRows(a)));
  }
  return `\ufeff${parts.join('\r\n\r\n')}\r\n`; // BOM so Excel reads UTF-8
};

// ---------------------------------------------------------------------- PDF
const M = 40; // margin

const header = (doc, title, a) => {
  doc.rect(0, 0, doc.page.width, 70).fill('#0f172a');
  doc.fill('#ffffff').font('Helvetica-Bold').fontSize(18).text(txt(`AiBoO  |  ${title}`), M, 18);
  doc.font('Helvetica').fontSize(9).fill('#cbd5e1')
    .text(txt(`Last ${a.days} days  -  generated ${fmtDate(a.generatedAt, a.tz)} (${a.tz})`), M, 44);
  doc.fill('#111827');
  doc.y = 88;
};

const ensure = (doc, h) => {
  if (doc.y + h > doc.page.height - 50) {
    doc.addPage();
    doc.y = M;
  }
};

const section = (doc, title) => {
  ensure(doc, 40);
  doc.moveDown(0.6);
  doc.font('Helvetica-Bold').fontSize(13).fill('#0f172a').text(txt(title), M, doc.y);
  doc.moveTo(M, doc.y + 2).lineTo(doc.page.width - M, doc.y + 2).lineWidth(0.7).stroke('#cbd5e1');
  doc.moveDown(0.5);
  doc.font('Helvetica').fontSize(9).fill('#111827');
};

const para = (doc, s) => {
  ensure(doc, 30);
  doc.font('Helvetica').fontSize(9.5).fill('#374151').text(txt(s), M, doc.y, { width: doc.page.width - 2 * M });
  doc.moveDown(0.4);
};

const kpiBoxes = (doc, items) => {
  const cols = 4;
  const gap = 8;
  const w = (doc.page.width - 2 * M - gap * (cols - 1)) / cols;
  const h = 46;
  for (let i = 0; i < items.length; i += cols) {
    ensure(doc, h + gap);
    const y = doc.y;
    items.slice(i, i + cols).forEach((it, j) => {
      const x = M + j * (w + gap);
      doc.roundedRect(x, y, w, h, 4).fill('#f1f5f9');
      doc.fill(it.color || '#0f172a').font('Helvetica-Bold').fontSize(15).text(txt(it.value), x + 8, y + 7, { width: w - 16 });
      doc.fill('#475569').font('Helvetica').fontSize(7.5).text(txt(it.label), x + 8, y + 29, { width: w - 16 });
    });
    doc.y = y + h + gap;
  }
  doc.fill('#111827');
};

// simple table with page breaks; cols = [{ label, width, get, color? }]
const table = (doc, cols, rows, { empty = 'No data' } = {}) => {
  const total = cols.reduce((s, c) => s + c.width, 0);
  const scale = (doc.page.width - 2 * M) / total;
  const ws = cols.map((c) => c.width * scale);
  const drawHead = () => {
    ensure(doc, 22);
    const y = doc.y;
    doc.rect(M, y, doc.page.width - 2 * M, 16).fill('#e2e8f0');
    let x = M;
    doc.font('Helvetica-Bold').fontSize(8).fill('#0f172a');
    cols.forEach((c, i) => { doc.text(txt(c.label), x + 3, y + 4, { width: ws[i] - 6, lineBreak: false, ellipsis: true }); x += ws[i]; });
    doc.y = y + 18;
  };
  drawHead();
  if (!rows.length) {
    doc.font('Helvetica-Oblique').fontSize(8.5).fill('#6b7280').text(txt(empty), M + 3, doc.y);
    doc.moveDown(0.5);
    return;
  }
  rows.forEach((r, idx) => {
    doc.font('Helvetica').fontSize(8);
    const cells = cols.map((c) => txt(c.get(r)));
    const h = Math.max(14, ...cells.map((s, i) => doc.heightOfString(s, { width: ws[i] - 6 }) + 5));
    if (doc.y + h > doc.page.height - 50) { doc.addPage(); doc.y = M; drawHead(); }
    const y = doc.y;
    if (idx % 2) doc.rect(M, y, doc.page.width - 2 * M, h).fill('#f8fafc');
    let x = M;
    cols.forEach((c, i) => {
      doc.font('Helvetica').fontSize(8).fill(c.color ? c.color(r) || '#111827' : '#111827')
        .text(cells[i], x + 3, y + 3, { width: ws[i] - 6 });
      x += ws[i];
    });
    doc.y = y + h;
  });
  doc.fill('#111827');
  doc.moveDown(0.4);
};

// stacked bar chart of the daily trend, drawn with rectangles
const trendChart = (doc, trend) => {
  const h = 150;
  ensure(doc, h + 40);
  const x0 = M + 24;
  const y0 = doc.y + 6;
  const w = doc.page.width - 2 * M - 24;
  const max = Math.max(1, ...trend.map((d) => d.total));
  doc.lineWidth(0.5).strokeColor('#cbd5e1');
  [0, 0.5, 1].forEach((f) => {
    const y = y0 + h - f * h;
    doc.moveTo(x0, y).lineTo(x0 + w, y).stroke();
    doc.font('Helvetica').fontSize(7).fill('#64748b').text(String(Math.round(max * f)), M, y - 3, { width: 20, align: 'right' });
  });
  const bw = w / trend.length;
  trend.forEach((d, i) => {
    let y = y0 + h;
    ['low', 'medium', 'high', 'critical'].forEach((s) => {
      if (!d[s]) return;
      const bh = (d[s] / max) * h;
      y -= bh;
      doc.rect(x0 + i * bw + bw * 0.15, y, Math.max(1, bw * 0.7), bh).fill(SEV_COLOR[s]);
    });
    const every = Math.ceil(trend.length / 10);
    if (i % every === 0) {
      doc.font('Helvetica').fontSize(6.5).fill('#64748b')
        .text(d.date.slice(5), x0 + i * bw - 6, y0 + h + 3, { width: bw + 12, align: 'center', lineBreak: false });
    }
  });
  let lx = x0;
  const ly = y0 + h + 16;
  ['critical', 'high', 'medium', 'low'].forEach((s) => {
    doc.rect(lx, ly, 8, 8).fill(SEV_COLOR[s]);
    doc.fill('#334155').fontSize(7.5).text(s, lx + 11, ly, { lineBreak: false });
    lx += 60;
  });
  doc.fill('#111827');
  doc.y = ly + 18;
};

// horizontal bars for a "top N" list
const hbars = (doc, items, color = '#2563eb') => {
  if (!items.length) { para(doc, 'No data in this period.'); return; }
  const max = Math.max(1, ...items.map((i) => i.count));
  const labelW = 170;
  const barW = doc.page.width - 2 * M - labelW - 40;
  items.forEach((it) => {
    ensure(doc, 16);
    const y = doc.y;
    doc.font('Helvetica').fontSize(8).fill('#111827').text(txt(it.name), M, y + 2, { width: labelW - 6, lineBreak: false, ellipsis: true });
    doc.rect(M + labelW, y + 2, Math.max(2, (it.count / max) * barW), 9).fill(color);
    doc.fill('#334155').text(String(it.count), M + labelW + (it.count / max) * barW + 4, y + 2, { lineBreak: false });
    doc.y = y + 14;
  });
  doc.fill('#111827');
  doc.moveDown(0.3);
};

const executiveSummaryText = (a) => {
  const k = a.kpis;
  const lines = [];
  lines.push(`Security posture is ${a.posture.level.toUpperCase()} (${a.posture.score}/100). `
    + `${k.totalAlerts} alerts were raised in the last ${a.days} days`
    + (k.changePct === null ? '.' : ` (${k.changePct >= 0 ? '+' : ''}${k.changePct}% compared with the previous ${a.days} days).`));
  lines.push(`${k.open + k.acknowledged} alerts are still not closed: ${k.openCritical} critical and ${k.openHigh} high. `
    + `${k.unassigned} of them have nobody assigned.`);
  if (k.mttaMinutes !== null || k.mttrMinutes !== null) {
    lines.push(`On average an alert was acknowledged in ${fmtMin(k.mttaMinutes)} and resolved in ${fmtMin(k.mttrMinutes)}.`);
  }
  if (a.compliance.average !== null) {
    lines.push(`Average device compliance (ISO 27001 / NIST CSF checks) is ${a.compliance.average}%. `
      + (a.compliance.failing.length ? `Most common gap: ${a.compliance.failing[0].title}.` : 'No failing checks.'));
  }
  if (a.topPatterns.length) lines.push(`Most frequent attack pattern: ${a.topPatterns[0].name} (${a.topPatterns[0].count} alerts).`);
  return lines.join(' ');
};

const kpiItems = (a) => [
  { label: 'Security posture (0-100)', value: a.posture.score, color: a.posture.score >= 80 ? '#15803d' : a.posture.score >= 60 ? '#ca8a04' : '#b91c1c' },
  { label: `Alerts (last ${a.days} days)`, value: a.kpis.totalAlerts },
  { label: 'Open critical / high', value: `${a.kpis.openCritical} / ${a.kpis.openHigh}`, color: a.kpis.openCritical ? '#b91c1c' : '#0f172a' },
  { label: 'Not closed (open + acknowledged)', value: a.kpis.open + a.kpis.acknowledged },
  { label: 'Mean time to acknowledge', value: fmtMin(a.kpis.mttaMinutes) },
  { label: 'Mean time to resolve', value: fmtMin(a.kpis.mttrMinutes) },
  { label: 'False positive rate', value: a.kpis.falsePositiveRate === null ? 'n/a' : `${a.kpis.falsePositiveRate}%` },
  { label: 'Average compliance', value: a.kpis.avgCompliance === null ? 'n/a' : `${a.kpis.avgCompliance}%` },
];

const alertCols = (tz) => [
  { label: 'Severity', width: 55, get: (r) => r.severity, color: (r) => SEV_COLOR[r.severity] },
  { label: 'Risk', width: 30, get: (r) => r.riskScore },
  { label: 'Alert', width: 190, get: (r) => r.title },
  { label: 'User / IP', width: 95, get: (r) => [r.entity, r.srcIp].filter(Boolean).join(' / ') },
  { label: 'Endpoint', width: 65, get: (r) => r.source },
  { label: 'Status', width: 70, get: (r) => (r.status === 'closed' ? `closed (${r.closeReason || 'resolved'})` : r.status) },
  { label: 'First seen', width: 75, get: (r) => fmtDate(r.firstSeen, tz) },
];

const complianceSection = (doc, a) => {
  section(doc, 'Compliance by device');
  table(doc, [
    { label: 'Endpoint', width: 120, get: (r) => r.endpoint },
    { label: 'Score', width: 50, get: (r) => (r.score ?? 'n/a') },
    { label: 'Pass', width: 40, get: (r) => r.counts.pass ?? 0 },
    { label: 'Warn', width: 40, get: (r) => r.counts.warn ?? 0 },
    { label: 'Fail', width: 40, get: (r) => r.counts.fail ?? 0, color: (r) => (r.counts.fail ? '#b91c1c' : null) },
    { label: 'Unknown', width: 50, get: (r) => r.counts.unknown ?? 0 },
    { label: 'ISO 27001 met', width: 80, get: (r) => { const f = r.frameworks['ISO 27001:2022']; return f ? `${f.met}/${f.controls}` : 'n/a'; } },
    { label: 'NIST CSF met', width: 80, get: (r) => { const f = r.frameworks['NIST CSF 2.0']; return f ? `${f.met}/${f.controls}` : 'n/a'; } },
    { label: 'Last check', width: 90, get: (r) => fmtDate(r.checkedAt, a.tz) },
  ], a.compliance.endpoints, { empty: 'No compliance report received yet (the agent sends one after each device check).' });

  section(doc, 'Gaps to fix (most common first)');
  table(doc, [
    { label: 'Check', width: 160, get: (r) => r.title },
    { label: 'Status', width: 40, get: (r) => r.status, color: (r) => STATUS_COLOR[r.status] },
    { label: 'Devices', width: 80, get: (r) => r.endpoints.join(', ') },
    { label: 'ISO 27001 / NIST CSF', width: 110, get: (r) => [...r.iso.map((x) => x.split(' ')[0]), ...r.nist].join(', ') },
    { label: 'How to fix', width: 190, get: (r) => r.fix },
  ], a.compliance.failing, { empty: 'No failing or warning checks.' });
};

export const toPdf = (type, a, stream) => {
  const doc = new PDFDocument({ size: 'A4', margin: M, bufferPages: true, info: { Title: `AiBoO ${REPORT_TYPES[type]}`, Author: 'AiBoO' } });
  doc.pipe(stream);
  header(doc, REPORT_TYPES[type], a);

  if (type === 'executive') {
    section(doc, 'Summary');
    para(doc, executiveSummaryText(a));
    kpiBoxes(doc, kpiItems(a));
    section(doc, `Alerts per day (last ${a.days} days)`);
    trendChart(doc, a.trend);
    section(doc, 'Top attack patterns');
    hbars(doc, a.topPatterns, '#7c3aed');
    section(doc, 'Most targeted users');
    hbars(doc, a.topEntities, '#0891b2');
    section(doc, 'Latest high and critical alerts');
    table(doc, alertCols(a.tz), a.recentCritical, { empty: 'No high or critical alerts in this period.' });
    complianceSection(doc, a);
  } else if (type === 'risk') {
    section(doc, 'Risk overview');
    para(doc, `Posture score ${a.posture.score}/100 (${a.posture.level}). Open alerts take away ${a.posture.alertPenalty} points `
      + `(critical 15, high 8, medium 3, low 1 each, at most 60) and compliance gaps take away ${a.posture.compliancePenalty}.`);
    kpiBoxes(doc, kpiItems(a));
    section(doc, 'Alerts by severity');
    hbars(doc, ['critical', 'high', 'medium', 'low'].map((s) => ({ name: s, count: a.bySeverity[s] || 0 })), '#ea580c');
    section(doc, `Alerts per day (last ${a.days} days)`);
    trendChart(doc, a.trend);
    section(doc, 'Top risky source IPs');
    hbars(doc, a.topIps, '#b91c1c');
    section(doc, 'Endpoints with most alerts');
    hbars(doc, a.topSources, '#2563eb');
    section(doc, 'All alerts (highest risk first, max 200)');
    table(doc, alertCols(a.tz), a.alerts.slice().sort((x, y) => (y.riskScore || 0) - (x.riskScore || 0)).slice(0, 200),
      { empty: 'No alerts in this period.' });
  } else {
    section(doc, 'Compliance overview');
    para(doc, a.compliance.average === null
      ? 'No compliance data yet. Each agent checks its PC (antivirus, firewall, updates, encryption, audit policy, ...) and sends the result here.'
      : `Average compliance score across devices: ${a.compliance.average}%. Checks are mapped to ISO/IEC 27001:2022 Annex A and NIST CSF 2.0 controls. `
        + 'Pass = 1 point, warning = half, fail = 0; checks that could not be read are left out.');
    complianceSection(doc, a);
    const checks = a.compliance.byEndpoint ? Object.values(a.compliance.byEndpoint) : [];
    checks.forEach((ep) => {
      section(doc, `All checks - ${ep.endpoint}`);
      table(doc, [
        { label: 'Check', width: 170, get: (r) => r.title },
        { label: 'Status', width: 45, get: (r) => r.status, color: (r) => STATUS_COLOR[r.status] },
        { label: 'ISO 27001:2022', width: 120, get: (r) => (r.iso27001 || []).join(', ') },
        { label: 'NIST CSF 2.0', width: 70, get: (r) => (r.nist_csf || []).join(', ') },
        { label: 'Detail', width: 130, get: (r) => r.detail },
      ], ep.checks || []);
    });
    section(doc, 'Compliance score per day');
    const pts = a.compliance.trend.filter((d) => d.score !== null);
    if (pts.length) hbars(doc, pts.map((d) => ({ name: d.date, count: d.score })), '#15803d');
    else para(doc, 'No history yet.');
  }

  // footer with page numbers
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i += 1) {
    doc.switchToPage(i);
    doc.page.margins.bottom = 0; // footer sits below the normal margin: don't start a new page
    doc.font('Helvetica').fontSize(7.5).fill('#94a3b8')
      .text(txt(`AiBoO ${REPORT_TYPES[type]}  -  page ${i + 1} of ${range.count}  -  confidential`),
        M, doc.page.height - 30, { width: doc.page.width - 2 * M, align: 'center', lineBreak: false });
  }
  doc.end();
};

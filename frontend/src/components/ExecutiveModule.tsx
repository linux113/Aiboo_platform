// Executive dashboard: posture score, KPIs, security trends, threat statistics,
// compliance and protection status - as widgets the user can show / hide,
// reorder and resize (saved in this browser).
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, Legend, CartesianGrid,
  PieChart, Pie, Cell, BarChart, Bar, LineChart, Line, RadialBarChart, RadialBar, PolarAngleAxis,
} from "recharts";
import api, { apiErrorMessage } from "../utils/api";
import { cn } from "../utils/cn";
import { sevCls } from "../utils/helpers";
import { browserTz, downloadReport, fmtMinutes, timeAgo, SEV_HEX, PATTERN_LABEL, type ReportType } from "../utils/reports";
import type { Analytics, AgentStatusReport, NavId } from "../types";

type WidgetId =
  | "kpis" | "posture" | "trend" | "severity" | "status" | "patterns"
  | "users" | "ips" | "compliance" | "protection" | "critical";

const WIDGETS: Record<WidgetId, { title: string; hint: string; wide: boolean }> = {
  kpis: { title: "Key figures", hint: "Alert counts and response times", wide: true },
  posture: { title: "Security posture", hint: "One score for the whole company", wide: false },
  trend: { title: "Security trend", hint: "Alerts per day by severity", wide: true },
  severity: { title: "Alerts by severity", hint: "Share of critical / high / medium / low", wide: false },
  status: { title: "Alert handling", hint: "Open, acknowledged, closed and why", wide: false },
  patterns: { title: "Top attack types", hint: "Most frequent TriGate patterns", wide: false },
  users: { title: "Most targeted users", hint: "Accounts that appear in most alerts", wide: false },
  ips: { title: "Top attacking IPs", hint: "Source IPs in most alerts", wide: false },
  compliance: { title: "Compliance", hint: "ISO 27001 / NIST CSF device checks", wide: true },
  protection: { title: "Protection status", hint: "Threat feeds, behaviour learning, live restrictions", wide: false },
  critical: { title: "Latest serious alerts", hint: "High and critical, newest first", wide: true },
};
const DEFAULT_ORDER: WidgetId[] = ["kpis", "posture", "trend", "severity", "status", "patterns", "users", "compliance", "protection", "ips", "critical"];
const STORE_KEY = "aiboo_exec_layout_v1";

type Layout = { order: WidgetId[]; hidden: WidgetId[]; wide: Partial<Record<WidgetId, boolean>> };

const loadLayout = (): Layout => {
  try {
    const raw = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
    if (raw && Array.isArray(raw.order)) {
      const known = raw.order.filter((w: WidgetId) => w in WIDGETS);
      const missing = DEFAULT_ORDER.filter((w) => !known.includes(w));
      return { order: [...known, ...missing], hidden: (raw.hidden || []).filter((w: WidgetId) => w in WIDGETS), wide: raw.wide || {} };
    }
  } catch { /* ignore */ }
  return { order: DEFAULT_ORDER, hidden: [], wide: {} };
};

const TIP = { contentStyle: { background: "#020617", border: "1px solid #334155", fontSize: 11 }, labelStyle: { color: "#94a3b8" } };
const AXIS = { stroke: "#475569", fontSize: 10, tickLine: false };

export default function ExecutiveModule({
  refreshTick,
  onNavigate,
  onNotify,
}: {
  refreshTick: number;
  onNavigate: (id: NavId) => void;
  onNotify?: (type: "critical" | "warning" | "info", title: string, body: string) => void;
}) {
  const [days, setDays] = useState(30);
  const [data, setData] = useState<Analytics | null>(null);
  const [status, setStatus] = useState<AgentStatusReport[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [layout, setLayout] = useState<Layout>(loadLayout);
  const [editing, setEditing] = useState(false);
  const [downloading, setDownloading] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [a, s] = await Promise.all([
        api.get("/analytics/overview", { params: { days, tz: browserTz() } }),
        api.get("/agent/agent-status").catch(() => ({ data: [] })),
      ]);
      setData(a.data);
      setStatus(Array.isArray(s.data) ? s.data : []);
      setError("");
    } catch (e) {
      setError(apiErrorMessage(e, "Could not load the executive dashboard"));
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => { load(); }, [load, refreshTick]);
  useEffect(() => {
    const iv = setInterval(load, 60000);
    return () => clearInterval(iv);
  }, [load]);
  useEffect(() => { localStorage.setItem(STORE_KEY, JSON.stringify(layout)); }, [layout]);

  const move = (id: WidgetId, dir: -1 | 1) => setLayout((l) => {
    const order = [...l.order];
    const i = order.indexOf(id);
    const j = i + dir;
    if (j < 0 || j >= order.length) return l;
    [order[i], order[j]] = [order[j], order[i]];
    return { ...l, order };
  });
  const toggleHidden = (id: WidgetId) => setLayout((l) => ({
    ...l, hidden: l.hidden.includes(id) ? l.hidden.filter((w) => w !== id) : [...l.hidden, id],
  }));
  const toggleWide = (id: WidgetId) => setLayout((l) => ({
    ...l, wide: { ...l.wide, [id]: !(l.wide[id] ?? WIDGETS[id].wide) },
  }));

  const report = async (type: ReportType, format: "pdf" | "csv") => {
    setDownloading(`${type}-${format}`);
    try {
      await downloadReport(type, format, days);
    } catch (e: any) {
      onNotify?.("warning", "Report failed", e.message);
    } finally {
      setDownloading("");
    }
  };

  const visible = layout.order.filter((w) => !layout.hidden.includes(w));

  return (
    <div className="flex flex-col gap-4">
      {/* toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-800/80 bg-slate-950/80 px-3 py-2">
        <div>
          <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">Executive Dashboard</div>
          <div className="text-[11px] text-slate-500">
            {data ? `Last ${data.days} days · updated ${timeAgo(data.generatedAt)} · time zone ${data.tz}` : "Loading…"}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <div className="flex overflow-hidden rounded border border-slate-700">
            {[7, 30, 90].map((d) => (
              <button key={d} onClick={() => setDays(d)}
                className={cn("px-2.5 py-1", days === d ? "bg-cyan-500/20 text-cyan-200" : "text-slate-400 hover:text-slate-200")}>{d} days</button>
            ))}
          </div>
          <button disabled={!!downloading} onClick={() => report("executive", "pdf")}
            className="rounded bg-cyan-500/80 px-2.5 py-1 font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50">
            {downloading === "executive-pdf" ? "Preparing…" : "⬇ Executive PDF"}
          </button>
          <button disabled={!!downloading} onClick={() => report("executive", "csv")}
            className="rounded border border-slate-700 px-2.5 py-1 text-slate-300 hover:text-cyan-200 disabled:opacity-50">CSV</button>
          <button onClick={() => setEditing((e) => !e)}
            className={cn("rounded border px-2.5 py-1", editing ? "border-cyan-400 text-cyan-200" : "border-slate-700 text-slate-300")}>
            ⚙ {editing ? "Done" : "Customise"}
          </button>
          <button onClick={load} className="rounded border border-slate-700 px-2 py-1 text-slate-300">{loading ? "…" : "↻"}</button>
        </div>
      </div>

      {editing && (
        <div className="rounded-xl border border-cyan-500/30 bg-slate-950/90 p-3 text-[11px]">
          <div className="mb-2 text-slate-300">Choose the widgets you want, their order (▲ ▼) and size. Saved in this browser.</div>
          <div className="grid grid-cols-1 gap-1.5 md:grid-cols-2">
            {layout.order.map((id, i) => {
              const wide = layout.wide[id] ?? WIDGETS[id].wide;
              return (
                <div key={id} className="flex items-center gap-2 rounded border border-slate-800 px-2 py-1">
                  <input type="checkbox" checked={!layout.hidden.includes(id)} onChange={() => toggleHidden(id)} />
                  <div className="min-w-0 flex-1">
                    <div className="text-slate-200">{WIDGETS[id].title}</div>
                    <div className="truncate text-[10px] text-slate-500">{WIDGETS[id].hint}</div>
                  </div>
                  <button onClick={() => toggleWide(id)} className="rounded border border-slate-700 px-1.5 text-slate-400">{wide ? "wide" : "half"}</button>
                  <button disabled={i === 0} onClick={() => move(id, -1)} className="px-1 text-slate-400 disabled:opacity-30">▲</button>
                  <button disabled={i === layout.order.length - 1} onClick={() => move(id, 1)} className="px-1 text-slate-400 disabled:opacity-30">▼</button>
                </div>
              );
            })}
          </div>
          <button onClick={() => setLayout({ order: DEFAULT_ORDER, hidden: [], wide: {} })} className="mt-2 text-slate-400 hover:text-slate-200">Reset to default</button>
        </div>
      )}

      {error && <div className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-[12px] text-red-200">{error}</div>}

      {data && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {visible.map((id) => (
            <div key={id} className={cn("flex flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3",
              (layout.wide[id] ?? WIDGETS[id].wide) && "lg:col-span-2")}>
              <div className="mb-2 flex items-baseline justify-between">
                <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-400">{WIDGETS[id].title}</div>
                <div className="text-[10px] text-slate-600">{WIDGETS[id].hint}</div>
              </div>
              <Widget id={id} a={data} status={status} onNavigate={onNavigate} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div className="flex h-32 items-center justify-center text-center text-[11px] text-slate-600">{text}</div>;
}

function Stat({ label, value, sub, tone }: { label: string; value: string | number; sub?: string; tone?: "red" | "amber" | "green" | "cyan" }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2">
      <div className="text-[9px] uppercase tracking-[0.15em] text-slate-500">{label}</div>
      <div className={cn("text-xl font-semibold",
        tone === "red" ? "text-red-300" : tone === "amber" ? "text-amber-300" : tone === "green" ? "text-emerald-300" : tone === "cyan" ? "text-cyan-300" : "text-slate-50")}>{value}</div>
      {sub && <div className="text-[10px] text-slate-500">{sub}</div>}
    </div>
  );
}

function TopBars({ items, color, label }: { items: { name: string; count: number }[]; color: string; label?: (s: string) => string }) {
  if (!items.length) return <Empty text="No data in this period yet." />;
  const rows = items.map((i) => ({ name: label ? label(i.name) : i.name, count: i.count }));
  return (
    <ResponsiveContainer width="100%" height={Math.max(120, rows.length * 26 + 20)}>
      <BarChart data={rows} layout="vertical" margin={{ left: 10, right: 20 }}>
        <XAxis type="number" allowDecimals={false} {...AXIS} />
        <YAxis type="category" dataKey="name" width={130} {...AXIS} tick={{ fill: "#cbd5e1", fontSize: 10 }} />
        <Tooltip {...TIP} cursor={{ fill: "#0f172a" }} />
        <Bar dataKey="count" name="Alerts" fill={color} radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

function Widget({ id, a, status, onNavigate }: { id: WidgetId; a: Analytics; status: AgentStatusReport[]; onNavigate: (id: NavId) => void }) {
  const k = a.kpis;
  const sevData = useMemo(() => (["critical", "high", "medium", "low"] as const)
    .map((s) => ({ name: s, value: a.bySeverity[s] || 0 })).filter((d) => d.value > 0), [a]);

  switch (id) {
    case "kpis":
      return (
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          <Stat label={`Alerts (${a.days} days)`} value={k.totalAlerts}
            sub={k.changePct === null ? "no earlier data" : `${k.changePct >= 0 ? "▲" : "▼"} ${Math.abs(k.changePct)}% vs previous ${a.days} days`}
            tone={k.changePct !== null && k.changePct > 0 ? "amber" : undefined} />
          <Stat label="Open critical / high" value={`${k.openCritical} / ${k.openHigh}`} tone={k.openCritical ? "red" : k.openHigh ? "amber" : "green"} sub="not yet closed" />
          <Stat label="Needs action" value={k.open + k.acknowledged} sub={`${k.open} open · ${k.acknowledged} acknowledged · ${k.unassigned} unassigned`} tone={k.open ? "amber" : "green"} />
          <Stat label="Closed" value={k.closed} sub={k.falsePositiveRate === null ? "" : `${k.falsePositiveRate}% were false alarms`} tone="green" />
          <Stat label="Mean time to acknowledge" value={fmtMinutes(k.mttaMinutes)} sub="alert raised → someone looked" tone="cyan" />
          <Stat label="Mean time to resolve" value={fmtMinutes(k.mttrMinutes)} sub="alert raised → closed" tone="cyan" />
          <Stat label="TriGate BLOCK / HOLD" value={`${k.blocked} / ${k.held}`} sub={`${k.incidents} attack-chain incidents`} />
          <Stat label="Endpoints online" value={`${k.endpointsOnline} / ${k.endpoints}`} sub="PCs with a running agent" tone={k.endpointsOnline ? "green" : "red"} />
        </div>
      );

    case "posture": {
      const color = a.posture.score >= 80 ? "#10b981" : a.posture.score >= 60 ? "#eab308" : a.posture.score >= 40 ? "#f97316" : "#ef4444";
      return (
        <div className="flex items-center gap-3">
          <div className="relative h-40 w-40 flex-shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart innerRadius="72%" outerRadius="100%" data={[{ v: a.posture.score }]} startAngle={210} endAngle={-30}>
                <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                <RadialBar dataKey="v" cornerRadius={8} fill={color} background={{ fill: "#1e293b" }} />
              </RadialBarChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <div className="text-3xl font-bold" style={{ color }}>{a.posture.score}</div>
              <div className="text-[10px] uppercase tracking-wider text-slate-400">{a.posture.level}</div>
            </div>
          </div>
          <div className="space-y-1 text-[11px] text-slate-400">
            <div>Starts at <b className="text-slate-200">100</b> (safest).</div>
            <div>− <b className="text-slate-200">{a.posture.alertPenalty}</b> for open alerts (critical 15, high 8, medium 3, low 1 each; max 60).</div>
            <div>− <b className="text-slate-200">{a.posture.compliancePenalty}</b> for compliance gaps{a.compliance.average === null ? " (no compliance data yet)" : ` (avg ${a.compliance.average}%)`}.</div>
            <div className="text-slate-500">Close alerts and fix failing checks to raise it.</div>
          </div>
        </div>
      );
    }

    case "trend":
      if (!a.trend.some((d) => d.total || d.closed)) return <Empty text="No alerts in this period. The chart fills in as the agents report." />;
      return (
        <ResponsiveContainer width="100%" height={240}>
          <AreaChart data={a.trend} margin={{ left: -15, right: 10 }}>
            <CartesianGrid stroke="#1e293b" vertical={false} />
            <XAxis dataKey="date" tickFormatter={(d: string) => d.slice(5)} {...AXIS} />
            <YAxis allowDecimals={false} {...AXIS} />
            <Tooltip {...TIP} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            {(["low", "medium", "high", "critical"] as const).map((s) => (
              <Area key={s} type="monotone" dataKey={s} stackId="1" stroke={SEV_HEX[s]} fill={SEV_HEX[s]} fillOpacity={0.35} />
            ))}
            <Area type="monotone" dataKey="closed" name="closed (handled)" stroke="#10b981" fill="none" strokeDasharray="4 3" />
          </AreaChart>
        </ResponsiveContainer>
      );

    case "severity":
      if (!sevData.length) return <Empty text="No alerts in this period." />;
      return (
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}
              label={({ name, value }: { name?: string; value?: number }) => `${name} ${value}`}>
              {sevData.map((d) => <Cell key={d.name} fill={SEV_HEX[d.name]} />)}
            </Pie>
            <Tooltip {...TIP} />
          </PieChart>
        </ResponsiveContainer>
      );

    case "status": {
      const rows = [
        { name: "Open", value: a.byStatus.open || 0, fill: "#ef4444" },
        { name: "Acknowledged", value: a.byStatus.acknowledged || 0, fill: "#eab308" },
        { name: "Closed", value: a.byStatus.closed || 0, fill: "#10b981" },
      ];
      const reasons = Object.entries(a.byCloseReason);
      return (
        <div>
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={rows} margin={{ left: -15 }}>
              <XAxis dataKey="name" {...AXIS} />
              <YAxis allowDecimals={false} {...AXIS} />
              <Tooltip {...TIP} cursor={{ fill: "#0f172a" }} />
              <Bar dataKey="value" name="Alerts" radius={[4, 4, 0, 0]}>
                {rows.map((r) => <Cell key={r.name} fill={r.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="mt-1 flex flex-wrap gap-1.5 text-[10px]">
            {reasons.length === 0 ? <span className="text-slate-600">Nothing closed yet.</span> : reasons.map(([r, n]) => (
              <span key={r} className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">{PATTERN_LABEL(r)}: {n}</span>
            ))}
            <button onClick={() => onNavigate("alerts")} className="ml-auto text-cyan-300 hover:underline">Open Alert Management →</button>
          </div>
        </div>
      );
    }

    case "patterns":
      return <TopBars items={a.topPatterns} color="#8b5cf6" label={PATTERN_LABEL} />;
    case "users":
      return <TopBars items={a.topEntities} color="#06b6d4" />;
    case "ips":
      return <TopBars items={a.topIps} color="#ef4444" />;

    case "compliance": {
      const c = a.compliance;
      if (!c.endpoints.length) return <Empty text="No compliance report yet. Each agent checks its PC (antivirus, firewall, updates, BitLocker, audit policy…) every 15 minutes and sends the result here." />;
      const hasTrend = c.trend.some((d) => d.score !== null);
      return (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-[180px_1fr_1fr]">
          <div className="space-y-2">
            <Stat label="Average compliance" value={c.average === null ? "n/a" : `${c.average}%`}
              tone={c.average === null ? undefined : c.average >= 80 ? "green" : c.average >= 60 ? "amber" : "red"} />
            {c.endpoints.map((e) => (
              <div key={e.endpoint} className="flex justify-between text-[11px]">
                <span className="truncate text-slate-300">{e.endpoint}</span>
                <span className="text-slate-400">{e.score ?? "n/a"}% · {e.counts.fail || 0} fail</span>
              </div>
            ))}
          </div>
          <div>
            <div className="mb-1 text-[10px] text-slate-500">Score per day</div>
            {hasTrend ? (
              <ResponsiveContainer width="100%" height={150}>
                <LineChart data={c.trend} margin={{ left: -20, right: 10 }}>
                  <CartesianGrid stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="date" tickFormatter={(d: string) => d.slice(5)} {...AXIS} />
                  <YAxis domain={[0, 100]} {...AXIS} />
                  <Tooltip {...TIP} />
                  <Line type="monotone" dataKey="score" stroke="#10b981" strokeWidth={2} connectNulls dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : <Empty text="History builds up day by day." />}
          </div>
          <div>
            <div className="mb-1 text-[10px] text-slate-500">Gaps to fix</div>
            {c.failing.length === 0 ? <div className="text-[11px] text-emerald-300">No failing checks 🎉</div> : (
              <div className="space-y-1 text-[11px]">
                {c.failing.slice(0, 6).map((f) => (
                  <div key={f.id} className="rounded border border-slate-800 px-2 py-1">
                    <div className="flex justify-between gap-2">
                      <span className="text-slate-200">{f.title}</span>
                      <span className={f.status === "fail" ? "text-red-300" : "text-amber-300"}>{f.status}</span>
                    </div>
                    <div className="text-[10px] text-slate-500">{f.endpoints.join(", ")}</div>
                  </div>
                ))}
                <button onClick={() => onNavigate("reports")} className="text-cyan-300 hover:underline">All checks and fixes →</button>
              </div>
            )}
          </div>
        </div>
      );
    }

    case "protection": {
      if (!status.length) return <Empty text="No agent has reported its status yet (sent every 5 minutes after start)." />;
      return (
        <div className="space-y-2 text-[11px]">
          <div className="grid grid-cols-2 gap-2">
            <Stat label="Threat-feed IPs" value={a.intel.feedEntries.toLocaleString()} sub={`${a.intel.matches} live matches`} tone={a.intel.matches ? "red" : "cyan"} />
            <Stat label="Behaviour alerts" value={a.intel.behaviourAlerts} sub="unusual logins (UEBA)" />
            <Stat label="Accounts restricted" value={a.intel.restrictions} sub="auto re-enabled later" tone={a.intel.restrictions ? "amber" : undefined} />
            <Stat label="IPs throttled" value={a.intel.throttles} sub="bandwidth limited" tone={a.intel.throttles ? "amber" : undefined} />
          </div>
          {status.map((s) => (
            <div key={s.endpoint} className="rounded border border-slate-800 px-2 py-1.5">
              <div className="flex justify-between">
                <span className="font-medium text-slate-200">{s.endpoint}</span>
                <span className="text-slate-500">{timeAgo(s.received_at)}</span>
              </div>
              <div className="mt-0.5 flex flex-wrap gap-1 text-[10px]">
                <Badge on={!!s.threat_intel?.connection_scan} text="Connection scan" />
                {(s.threat_intel?.feeds || []).map((f) => <Badge key={f.key} on={f.entries > 0 && !f.error} text={`${f.name} (${f.entries})`} title={f.error || f.updated} />)}
                <Badge on={s.behaviour?.enabled !== false} text={`Behaviour: ${s.behaviour?.learned ?? 0}/${s.behaviour?.users ?? 0} users learned`} />
                <Badge on={!!s.auto_response} text={s.auto_response ? "Auto-response ON" : "Auto-response off"} warn={!s.auto_response} />
              </div>
              {(s.access_control?.restrictions || []).map((r) => (
                <div key={r.user} className="mt-0.5 text-[10px] text-amber-300">🔒 {r.user} disabled · {r.minutes_left} min left</div>
              ))}
              {(s.access_control?.throttles || []).map((t) => (
                <div key={t.segment} className="mt-0.5 text-[10px] text-amber-300">🐢 {t.segment} limited to {t.kbps} kbps · {t.minutes_left} min left</div>
              ))}
            </div>
          ))}
        </div>
      );
    }

    case "critical":
      if (!a.recentCritical.length) return <Empty text="No high or critical alerts in this period." />;
      return (
        <div className="space-y-1">
          {a.recentCritical.map((r) => (
            <button key={r.alertId} onClick={() => onNavigate("alerts")}
              className="flex w-full items-center gap-2 rounded border border-slate-800 px-2 py-1.5 text-left text-[11px] hover:border-cyan-500/40">
              <span className={cn("rounded-full px-2 py-0.5 text-[9px] ring-1", sevCls(r.severity))}>{r.severity}</span>
              <span className="min-w-0 flex-1 truncate text-slate-200">{r.title}</span>
              <span className="hidden text-slate-500 md:inline">{r.source}</span>
              <span className={cn("rounded px-1.5 text-[10px]", r.status === "closed" ? "text-emerald-300" : r.status === "acknowledged" ? "text-amber-300" : "text-red-300")}>{r.status}</span>
              <span className="w-20 text-right text-slate-500">{timeAgo(r.firstSeen)}</span>
            </button>
          ))}
        </div>
      );
    default:
      return null;
  }
}

function Badge({ on, text, warn, title }: { on: boolean; text: string; warn?: boolean; title?: string }) {
  return (
    <span title={title} className={cn("rounded px-1.5 py-0.5",
      warn ? "bg-slate-800 text-slate-400" : on ? "bg-emerald-500/15 text-emerald-300" : "bg-red-500/10 text-red-300")}>{text}</span>
  );
}

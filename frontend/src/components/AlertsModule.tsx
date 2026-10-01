// Alert Management: every TriGate HOLD/BLOCK, high/critical finding and
// correlated incident becomes an alert that a person must handle:
// acknowledge -> assign -> (notes) -> close with a reason (or reopen).
import { useCallback, useEffect, useMemo, useState } from "react";
import api, { apiErrorMessage } from "../utils/api";
import { cn } from "../utils/cn";
import { sevCls } from "../utils/helpers";
import { downloadReport, timeAgo, PATTERN_LABEL } from "../utils/reports";
import type { AlertList, SecurityAlert, AlertStatus, CloseReason } from "../types";

const CLOSE_REASONS: { id: CloseReason; label: string; hint: string }[] = [
  { id: "resolved", label: "Resolved", hint: "Real problem, now fixed" },
  { id: "false_positive", label: "False alarm", hint: "Not an attack (normal activity)" },
  { id: "duplicate", label: "Duplicate", hint: "Same as another alert" },
  { id: "accepted_risk", label: "Accepted risk", hint: "Known and allowed on purpose" },
];
const REASON_LABEL: Record<string, string> = Object.fromEntries(CLOSE_REASONS.map((r) => [r.id, r.label]));
const KIND_LABEL: Record<string, string> = { trigate: "TriGate", finding: "Detection", incident: "Incident" };
const STATUS_CLS: Record<AlertStatus, string> = {
  open: "bg-red-500/15 text-red-300",
  acknowledged: "bg-amber-500/15 text-amber-300",
  closed: "bg-emerald-500/15 text-emerald-300",
};
const ACTION_ICON: Record<string, string> = {
  created: "🆕", acknowledged: "👀", assigned: "👤", closed: "✅", reopened: "↩️", note: "📝", seen_again: "🔁",
};

type Tab = AlertStatus | "active" | "all";

export default function AlertsModule({
  canEdit,
  userName,
  refreshTick,
  onNotify,
}: {
  canEdit: boolean;
  userName: string;
  refreshTick: number;
  onNotify?: (type: "critical" | "warning" | "info", title: string, body: string) => void;
}) {
  const [tab, setTab] = useState<Tab>("active");
  const [severity, setSeverity] = useState("");
  const [kind, setKind] = useState("");
  const [assignee, setAssignee] = useState("");
  const [q, setQ] = useState("");
  const [days, setDays] = useState(30);
  const [sort, setSort] = useState("newest");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<AlertList | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [openId, setOpenId] = useState<string | null>(null);
  const [detail, setDetail] = useState<SecurityAlert | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [assignTo, setAssignTo] = useState("");
  const [closeReason, setCloseReason] = useState<CloseReason>("resolved");
  const [bulkReason, setBulkReason] = useState<CloseReason>("resolved");

  const statusParam = tab === "active" ? "open,acknowledged" : tab === "all" ? "" : tab;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get("/alerts", {
        params: { status: statusParam, severity, kind, q, days, sort, page, limit: 50,
          assignee: assignee === "me" ? userName : assignee },
      });
      setData(res.data);
      setError("");
    } catch (e) {
      setError(apiErrorMessage(e, "Could not load alerts"));
    } finally {
      setLoading(false);
    }
  }, [statusParam, severity, kind, q, days, sort, page, assignee, userName]);

  const loadDetail = useCallback(async (id: string) => {
    try {
      const res = await api.get(`/alerts/${encodeURIComponent(id)}`);
      setDetail(res.data);
      setAssignTo(res.data.assignee || "");
    } catch (e) {
      setDetail(null);
      setError(apiErrorMessage(e, "Could not load alert"));
    }
  }, []);

  // reload on filter change, on live socket updates and every 30 s
  useEffect(() => { load(); }, [load, refreshTick]);
  useEffect(() => {
    const iv = setInterval(load, 60000);
    return () => clearInterval(iv);
  }, [load]);
  useEffect(() => { if (openId) loadDetail(openId); }, [openId, loadDetail, refreshTick]);
  useEffect(() => { setPage(1); }, [statusParam, severity, kind, q, days, sort, assignee]);

  const act = async (path: string, body: Record<string, unknown>, okText: string) => {
    if (!openId) return;
    setBusy(true);
    try {
      const res = await api.post(`/alerts/${encodeURIComponent(openId)}/${path}`, body);
      setDetail(res.data);
      setNote("");
      onNotify?.("info", okText, res.data.title);
      load();
    } catch (e) {
      onNotify?.("warning", "Alert update failed", apiErrorMessage(e, "Failed"));
    } finally {
      setBusy(false);
    }
  };

  const bulk = async (action: "acknowledge" | "close" | "assign") => {
    if (!selected.size) return;
    setBusy(true);
    try {
      const res = await api.post("/alerts/bulk", {
        ids: [...selected], action, reason: bulkReason, assignee: userName,
      });
      onNotify?.("info", "Alerts updated", `${res.data.updated} of ${selected.size} alerts`);
      setSelected(new Set());
      load();
      if (openId) loadDetail(openId);
    } catch (e) {
      onNotify?.("warning", "Bulk update failed", apiErrorMessage(e, "Failed"));
    } finally {
      setBusy(false);
    }
  };

  const alerts = data?.alerts || [];
  const allChecked = alerts.length > 0 && alerts.every((a) => selected.has(a.alertId));
  const pages = data ? Math.max(1, Math.ceil(data.total / data.limit)) : 1;
  const counts = data?.counts || { open: 0, acknowledged: 0, closed: 0 };

  const tabs: { id: Tab; label: string }[] = useMemo(() => [
    { id: "active", label: "Needs action" },
    { id: "open", label: "Open" },
    { id: "acknowledged", label: "Acknowledged" },
    { id: "closed", label: "Closed" },
    { id: "all", label: "All" },
  ], []);

  const toggle = (id: string) => setSelected((s) => {
    const n = new Set(s);
    if (n.has(id)) n.delete(id); else n.add(id);
    return n;
  });

  return (
    <div className="grid h-full grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)]">
      {/* ------------------------------------------------ list */}
      <div className="flex min-h-0 flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">Alert Management</div>
            <div className="text-[11px] text-slate-500">
              TriGate HOLD/BLOCK, serious detections and attack chains.{" "}
              {data?.storage === "memory" && <span className="text-amber-400">Database offline - alerts kept in memory until restart.</span>}
            </div>
          </div>
          <div className="flex items-center gap-2 text-[11px]">
            <button
              onClick={() => downloadReport("risk", "csv", days).catch((e) => onNotify?.("warning", "Export failed", e.message))}
              className="rounded border border-slate-700 px-2 py-1 text-slate-300 hover:border-cyan-500/60 hover:text-cyan-200"
            >⬇ Export CSV</button>
            <button onClick={load} className="rounded border border-slate-700 px-2 py-1 text-slate-300 hover:text-cyan-200">
              {loading ? "…" : "↻ Refresh"}
            </button>
          </div>
        </div>

        {/* status tabs */}
        <div className="mb-2 flex flex-wrap gap-1.5 text-[11px]">
          {tabs.map((t) => {
            const n = t.id === "active" ? counts.open + counts.acknowledged
              : t.id === "all" ? counts.open + counts.acknowledged + counts.closed
              : counts[t.id as AlertStatus];
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={cn("rounded-full border px-3 py-1",
                  tab === t.id ? "border-cyan-400/70 bg-cyan-500/10 text-cyan-200" : "border-slate-700 text-slate-400 hover:text-slate-200")}
              >
                {t.label} ({n})
              </button>
            );
          })}
        </div>

        {/* filters */}
        <div className="mb-2 grid grid-cols-2 gap-2 text-[11px] md:grid-cols-6">
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search user, IP, PC, text…"
            className="col-span-2 rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-100 placeholder:text-slate-600 focus:outline-none" />
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-200">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={kind} onChange={(e) => setKind(e.target.value)} className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-200">
            <option value="">All types</option>
            <option value="trigate">TriGate</option>
            <option value="incident">Incidents</option>
            <option value="finding">Detections</option>
          </select>
          <select value={assignee} onChange={(e) => setAssignee(e.target.value)} className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-200">
            <option value="">Anyone</option>
            <option value="me">Assigned to me</option>
            <option value="unassigned">Unassigned</option>
          </select>
          <div className="flex gap-2">
            <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="flex-1 rounded border border-slate-700 bg-slate-950 px-1 py-1.5 text-slate-200">
              <option value={1}>24 h</option>
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
              <option value={90}>90 days</option>
            </select>
            <select value={sort} onChange={(e) => setSort(e.target.value)} className="flex-1 rounded border border-slate-700 bg-slate-950 px-1 py-1.5 text-slate-200">
              <option value="newest">Newest</option>
              <option value="severity">Severity</option>
              <option value="risk">Risk</option>
              <option value="oldest">Oldest</option>
            </select>
          </div>
        </div>

        {/* bulk bar */}
        {canEdit && selected.size > 0 && (
          <div className="mb-2 flex flex-wrap items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/5 px-2 py-1.5 text-[11px]">
            <span className="text-cyan-200">{selected.size} selected</span>
            <button disabled={busy} onClick={() => bulk("acknowledge")} className="rounded bg-amber-500/80 px-2 py-0.5 font-semibold text-slate-950 disabled:opacity-50">Acknowledge</button>
            <button disabled={busy} onClick={() => bulk("assign")} className="rounded bg-slate-700 px-2 py-0.5 text-slate-100 disabled:opacity-50">Assign to me</button>
            <select value={bulkReason} onChange={(e) => setBulkReason(e.target.value as CloseReason)} className="rounded border border-slate-700 bg-slate-950 px-1 py-0.5 text-slate-200">
              {CLOSE_REASONS.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
            </select>
            <button disabled={busy} onClick={() => bulk("close")} className="rounded bg-emerald-500/80 px-2 py-0.5 font-semibold text-slate-950 disabled:opacity-50">Close</button>
            <button onClick={() => setSelected(new Set())} className="ml-auto text-slate-400 hover:text-slate-200">Clear</button>
          </div>
        )}

        {error && <div className="mb-2 rounded border border-red-500/40 bg-red-500/10 px-2 py-1 text-[11px] text-red-200">{error}</div>}

        {/* table */}
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="sticky top-0 bg-slate-950 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                {canEdit && (
                  <th className="w-6 py-1.5">
                    <input type="checkbox" checked={allChecked}
                      onChange={() => setSelected(allChecked ? new Set() : new Set(alerts.map((a) => a.alertId)))} />
                  </th>
                )}
                <th className="py-1.5">Severity</th>
                <th>Alert</th>
                <th className="hidden md:table-cell">User / IP</th>
                <th>Status</th>
                <th className="hidden lg:table-cell">Assignee</th>
                <th className="text-right">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-600">
                    {loading ? "Loading…" : "No alerts here. New TriGate HOLD/BLOCK decisions and attack chains appear automatically."}
                  </td>
                </tr>
              )}
              {alerts.map((a) => (
                <tr key={a.alertId} onClick={() => setOpenId(a.alertId)}
                  className={cn("cursor-pointer border-t border-slate-800/70 hover:bg-slate-900/70", openId === a.alertId && "bg-cyan-500/5")}>
                  {canEdit && (
                    <td className="py-1.5" onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={selected.has(a.alertId)} onChange={() => toggle(a.alertId)} />
                    </td>
                  )}
                  <td className="py-1.5">
                    <span className={cn("rounded-full px-2 py-0.5 text-[9px] font-medium ring-1", sevCls(a.severity))}>{a.severity}</span>
                    <div className="mt-0.5 text-[9px] text-slate-500">risk {a.riskScore}</div>
                  </td>
                  <td className="max-w-[260px] pr-2">
                    <div className="truncate font-medium text-slate-100">{a.title}</div>
                    <div className="truncate text-[10px] text-slate-500">
                      {KIND_LABEL[a.kind]}{a.verdict ? ` · ${a.verdict.toUpperCase()}` : ""} · {a.source}
                      {a.occurrences > 1 ? ` · ×${a.occurrences}` : ""}
                    </div>
                  </td>
                  <td className="hidden max-w-[140px] truncate pr-2 text-slate-300 md:table-cell">
                    {[a.entity || a.subject, a.srcIp].filter(Boolean).join(" · ") || "—"}
                  </td>
                  <td>
                    <span className={cn("rounded px-1.5 py-0.5 text-[10px]", STATUS_CLS[a.status])}>{a.status}</span>
                    {a.status === "closed" && a.closeReason && <div className="text-[9px] text-slate-500">{REASON_LABEL[a.closeReason]}</div>}
                  </td>
                  <td className="hidden truncate text-slate-300 lg:table-cell">{a.assignee || <span className="text-slate-600">—</span>}</td>
                  <td className="text-right text-slate-400">{timeAgo(a.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {pages > 1 && (
          <div className="mt-2 flex items-center justify-end gap-2 text-[11px] text-slate-400">
            <button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-slate-700 px-2 disabled:opacity-40">‹</button>
            page {page} / {pages}
            <button disabled={page >= pages} onClick={() => setPage(page + 1)} className="rounded border border-slate-700 px-2 disabled:opacity-40">›</button>
          </div>
        )}
      </div>

      {/* ------------------------------------------------ detail */}
      <div className="flex min-h-0 flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
        {!detail ? (
          <div className="m-auto max-w-xs text-center text-[12px] text-slate-500">
            Click an alert to see the details and handle it.
            <div className="mt-3 space-y-1 text-left text-[11px] text-slate-600">
              <div>1. <b className="text-slate-400">Acknowledge</b> = "I am looking at it" (starts the response clock).</div>
              <div>2. <b className="text-slate-400">Assign</b> = who is responsible.</div>
              <div>3. <b className="text-slate-400">Close</b> with a reason: resolved, false alarm, duplicate or accepted risk.</div>
            </div>
          </div>
        ) : (
          <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-auto text-[11px]">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className={cn("rounded-full px-2 py-0.5 text-[9px] font-medium ring-1", sevCls(detail.severity))}>{detail.severity}</span>
                  <span className={cn("rounded px-1.5 py-0.5 text-[10px]", STATUS_CLS[detail.status])}>{detail.status}</span>
                  <span className="text-[10px] text-slate-500">{KIND_LABEL[detail.kind]} · risk {detail.riskScore}{detail.verdict ? ` · ${detail.verdict.toUpperCase()}` : ""}</span>
                </div>
                <div className="mt-1 text-[14px] font-semibold text-slate-100">{detail.title}</div>
              </div>
              <button onClick={() => { setOpenId(null); setDetail(null); }} className="text-slate-500 hover:text-slate-300">✕</button>
            </div>

            {detail.description && <p className="text-slate-300">{detail.description}</p>}

            <div className="grid grid-cols-2 gap-x-3 gap-y-1 rounded-lg border border-slate-800 bg-slate-900/50 p-2">
              <Field k="PC (endpoint)" v={detail.source} />
              <Field k="User" v={detail.entity || detail.subject} />
              <Field k="Source IP" v={detail.srcIp} />
              <Field k="Pattern" v={PATTERN_LABEL(detail.pattern)} />
              <Field k="First seen" v={new Date(detail.firstSeen).toLocaleString()} />
              <Field k="Last seen" v={`${new Date(detail.lastSeen).toLocaleString()}${detail.occurrences > 1 ? ` (×${detail.occurrences})` : ""}`} />
              {detail.data?.mitre && <Field k="MITRE ATT&CK" v={detail.data.mitre} />}
              {detail.data?.trust !== undefined && <Field k="Trust / Intent / Impact" v={`${detail.data.trust} / ${detail.data.intent} / ${detail.data.impact}`} />}
              {Array.isArray(detail.data?.stages) && detail.data!.stages.length > 0 && (
                <div className="col-span-2"><Field k="Attack stages" v={detail.data!.stages.join(" → ")} /></div>
              )}
              <Field k="Assignee" v={detail.assignee || "nobody"} />
              {detail.acknowledgedAt && <Field k="Acknowledged" v={`${detail.acknowledgedBy || ""} · ${timeAgo(detail.acknowledgedAt)}`} />}
              {detail.closedAt && <Field k="Closed" v={`${detail.closedBy || ""} · ${REASON_LABEL[detail.closeReason] || ""}`} />}
            </div>

            {Array.isArray(detail.data?.recommended) && detail.data!.recommended.length > 0 && (
              <div className="rounded-lg border border-slate-800 p-2">
                <div className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">TriGate recommended</div>
                {detail.data!.recommended.map((r: any, i: number) => (
                  <div key={i} className="text-slate-300">• {r.text || `${PATTERN_LABEL(r.action)}${r.target ? ` → ${r.target}` : ""}`}</div>
                ))}
                <div className="mt-1 text-[10px] text-slate-500">Run these from Agent Console → TriGate.</div>
              </div>
            )}

            {canEdit ? (
              <div className="space-y-2 rounded-lg border border-slate-800 p-2">
                <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} placeholder="Note (optional for actions, required for 'Add note')"
                  className="w-full rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-100 placeholder:text-slate-600 focus:outline-none" />
                <div className="flex flex-wrap gap-1.5">
                  {detail.status === "open" && (
                    <button disabled={busy} onClick={() => act("acknowledge", { note }, "Alert acknowledged")}
                      className="rounded bg-amber-500/85 px-2.5 py-1 font-semibold text-slate-950 disabled:opacity-50">👀 Acknowledge</button>
                  )}
                  <button disabled={busy || !note.trim()} onClick={() => act("notes", { text: note }, "Note added")}
                    className="rounded border border-slate-600 px-2.5 py-1 text-slate-200 disabled:opacity-40">📝 Add note</button>
                  {detail.status === "closed" && (
                    <button disabled={busy} onClick={() => act("reopen", { note }, "Alert reopened")}
                      className="rounded border border-red-500/60 px-2.5 py-1 text-red-200 disabled:opacity-50">↩ Reopen</button>
                  )}
                </div>
                <div className="flex gap-1.5">
                  <input value={assignTo} onChange={(e) => setAssignTo(e.target.value)} placeholder="Assign to (name or team)"
                    className="flex-1 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-100 placeholder:text-slate-600 focus:outline-none" />
                  <button disabled={busy} onClick={() => setAssignTo(userName)} className="rounded border border-slate-700 px-2 text-slate-300">Me</button>
                  <button disabled={busy || assignTo === (detail.assignee || "")} onClick={() => act("assign", { assignee: assignTo }, "Alert assigned")}
                    className="rounded bg-slate-700 px-2.5 py-1 text-slate-100 disabled:opacity-40">👤 Assign</button>
                </div>
                {detail.status !== "closed" && (
                  <div className="flex gap-1.5">
                    <select value={closeReason} onChange={(e) => setCloseReason(e.target.value as CloseReason)}
                      className="flex-1 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200">
                      {CLOSE_REASONS.map((r) => <option key={r.id} value={r.id}>{r.label} - {r.hint}</option>)}
                    </select>
                    <button disabled={busy} onClick={() => act("close", { reason: closeReason, note }, "Alert closed")}
                      className="rounded bg-emerald-500/85 px-2.5 py-1 font-semibold text-slate-950 disabled:opacity-50">✅ Close</button>
                  </div>
                )}
              </div>
            ) : (
              <div className="rounded border border-slate-800 px-2 py-1.5 text-slate-500">You have view-only access (viewer role).</div>
            )}

            {(detail.notes || []).length > 0 && (
              <div>
                <div className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">Notes</div>
                {detail.notes.map((n, i) => (
                  <div key={i} className="mb-1 rounded border border-slate-800 bg-slate-900/60 px-2 py-1">
                    <div className="text-[10px] text-slate-500">{n.by} · {new Date(n.at).toLocaleString()}</div>
                    <div className="whitespace-pre-wrap text-slate-200">{n.text}</div>
                  </div>
                ))}
              </div>
            )}

            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">History</div>
              {(detail.history || []).slice().reverse().map((h, i) => (
                <div key={i} className="flex gap-2 border-l border-slate-700 py-0.5 pl-2">
                  <span>{ACTION_ICON[h.action] || "•"}</span>
                  <div>
                    <span className="text-slate-200">{h.action}</span>
                    {h.action === "assigned" && <span className="text-slate-400"> → {h.to || "nobody"}</span>}
                    <span className="text-slate-500"> · {h.by} · {new Date(h.at).toLocaleString()}</span>
                    {h.text && h.action !== "note" && <div className="text-[10px] text-slate-500">{h.text}</div>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Field({ k, v }: { k: string; v?: string | number | null }) {
  return (
    <div className="min-w-0">
      <div className="text-[9px] uppercase tracking-wider text-slate-500">{k}</div>
      <div className="truncate text-slate-200" title={String(v ?? "")}>{v === undefined || v === null || v === "" ? "—" : v}</div>
    </div>
  );
}

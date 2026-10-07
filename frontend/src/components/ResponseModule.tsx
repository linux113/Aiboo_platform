// PseudoLock Response screen (backend: routes/pseudolock.routes.js)
//   Approvals - actions waiting for a person: Approve / Reject, who decided, expiry countdown
//   Playbooks - built-in + your own multi-step playbooks, with a simple editor
//   Runs      - every playbook run with the status of each step
//   Rules     - WHEN this happens -> THEN run this playbook (ResponseRules.tsx)
import { useCallback, useEffect, useMemo, useState } from "react";
import RulesTab from "./ResponseRules";
import api, { apiErrorMessage } from "../utils/api";
import { cn } from "../utils/cn";

// ------------------------------------------------------------------ types
export interface Approval {
  id: string;
  status: "pending" | "approved" | "rejected" | "expired" | "running" | "done" | "failed" | "cancelled";
  kind: "action" | "playbook_step" | "playbook_start";
  title: string;
  action: string | null;
  actionLabel: string;
  target: string;
  params: Record<string, number>;
  endpoint: string;
  reason: string;
  risk: number | null;
  level: string;
  origin: "trigate" | "playbook" | "manual" | "rule";
  ruleName?: string | null;
  startedRunId?: string | null;
  alertId: string | null;
  runId: string | null;
  playbookName: string | null;
  requestedBy: string;
  requestedAt: string;
  expiresAt: string;
  expiresMinutes: number;
  decidedBy: string | null;
  decidedAt: string | null;
  note: string;
  result: string | null;
  error: string | null;
  finishedAt: string | null;
  occurrences: number;
  history: { at: string; by: string; what: string }[];
}
export type StepType = "action" | "approval" | "notify" | "wait";
export interface PlaybookStep {
  type: StepType;
  action?: string;
  target?: string;
  params?: Record<string, number>;
  onFailure?: "stop" | "continue";
  message?: string;
  expiresMinutes?: number;
  level?: "info" | "warning" | "critical";
  seconds?: number;
}
export interface Playbook {
  id: string;
  name: string;
  description: string;
  builtIn: boolean;
  enabled: boolean;
  steps: PlaybookStep[];
  variables: string[];
  needsPc: boolean;
  createdBy?: string;
  updatedBy?: string;
  version?: number;
}
interface RunStep { label: string; status: "pending" | "running" | "waiting" | "done" | "failed" | "skipped"; message: string; error: string | null; approvalId: string | null; startedAt: string | null; finishedAt: string | null }
export interface PlaybookRun {
  id: string;
  playbookId: string;
  playbookName: string;
  endpoint: string;
  vars: Record<string, string>;
  alertId: string | null;
  status: "running" | "waiting_approval" | "done" | "failed" | "stopped" | "cancelled";
  current: number;
  steps: RunStep[];
  startedBy: string;
  trigger?: "manual" | "rule";
  ruleName?: string | null;
  startedAt: string;
  finishedAt: string | null;
  message: string;
}
interface CatalogAction { id: string; label: string; help: string; target: string; targetHint: string; targetOptional: boolean; params: { key: string; label: string; def: number; min: number; max: number }[]; runsOn: "pc" | "backend" }
interface Catalog { actions: CatalogAction[]; variables: { id: string; label: string; example: string; auto?: boolean }[]; approvalExpiryMinutes: number; fourEyes: boolean; maxSteps: number }
export interface RunPrefill { endpoint?: string; vars?: Record<string, string>; alertId?: string; pattern?: string; title?: string }
type Notify = (type: "critical" | "warning" | "info", title: string, body: string) => void;

// ------------------------------------------------------------------ helpers
const P = `/pseudolock`;
const STATUS_CLS: Record<string, string> = {
  pending: "bg-amber-500/15 text-amber-300 ring-amber-500/40",
  waiting: "bg-amber-500/15 text-amber-300 ring-amber-500/40",
  waiting_approval: "bg-amber-500/15 text-amber-300 ring-amber-500/40",
  running: "bg-cyan-500/15 text-cyan-300 ring-cyan-500/40",
  approved: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
  done: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
  rejected: "bg-slate-500/20 text-slate-300 ring-slate-500/40",
  cancelled: "bg-slate-500/20 text-slate-300 ring-slate-500/40",
  skipped: "bg-slate-800 text-slate-500 ring-slate-700",
  expired: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  stopped: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  failed: "bg-red-500/15 text-red-300 ring-red-500/40",
};
const STATUS_TEXT: Record<string, string> = {
  pending: "Pending", waiting: "Waiting", waiting_approval: "Waiting for approval", running: "Running",
  approved: "Approved", done: "Done", rejected: "Rejected", cancelled: "Cancelled", skipped: "Skipped",
  expired: "Expired", stopped: "Stopped", failed: "Failed",
};
const STEP_ICON: Record<string, string> = { pending: "○", running: "◔", waiting: "⏳", done: "✅", failed: "❌", skipped: "–" };
const TYPE_LABEL: Record<StepType, string> = { action: "⚡ Action on the PC", approval: "✋ Wait for approval", notify: "📣 Notify dashboards", wait: "⏱ Wait" };
const ORIGIN_LABEL: Record<string, string> = { trigate: "TriGate BLOCK", playbook: "Playbook step", manual: "Requested by hand", rule: "Response rule" };
const fmt = (d?: string | null) => (d ? new Date(d).toLocaleString() : "—");
const Badge = ({ s }: { s: string }) => (
  <span className={cn("rounded-full px-2 py-0.5 text-[10px] font-medium ring-1", STATUS_CLS[s] || STATUS_CLS.pending)}>{STATUS_TEXT[s] || s}</span>
);
function countdown(expiresAt: string, now: number) {
  const s = Math.max(0, Math.round((new Date(expiresAt).getTime() - now) / 1000));
  if (s <= 0) return "expiring…";
  const m = Math.floor(s / 60);
  return m >= 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m}:${String(s % 60).padStart(2, "0")}`;
}
/** Best built-in playbook for an alert pattern (used by "Run playbook" on an alert). */
export function suggestPlaybook(pattern?: string, hasPid?: boolean): string {
  const p = String(pattern || "");
  if (["brute_force", "failed_logon", "account_lockout"].includes(p)) return "builtin_password_guessing";
  if (["admin_group_add", "account_created"].includes(p)) return "builtin_new_admin";
  if (p === "threat_intel_alert") return hasPid ? "builtin_stop_program" : "builtin_bad_ip";
  if (["log_cleared", "audit_policy_changed", "service_installed", "scheduled_task", "malware", "network_intrusion"].includes(p)) return "builtin_compromised_pc";
  return "builtin_safe_test";
}
const inputCls = "w-full rounded border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/60 focus:outline-none";

function useCatalog() {
  const [cat, setCat] = useState<Catalog | null>(null);
  useEffect(() => { api.get(`${P}/catalog`).then((r) => setCat(r.data)).catch(() => setCat(null)); }, []);
  return cat;
}
function useOnlinePcs(open = true) {
  const [pcs, setPcs] = useState<string[]>([]);
  useEffect(() => {
    if (!open) return;
    api.get(`/agent/agents-online`, { timeout: 5000 })
      .then((r) => setPcs((Array.isArray(r.data?.agents) ? r.data.agents : []).map((a: { endpointId?: string }) => a.endpointId || "").filter(Boolean)))
      .catch(() => setPcs([]));
  }, [open]);
  return pcs;
}

// ================================================================== main
export default function ResponseModule({
  canEdit, refreshTick, onNotify, prefill, onPrefillUsed, initialTab = "approvals",
}: {
  initialTab?: "approvals" | "playbooks" | "runs" | "rules";
  canEdit: boolean;
  refreshTick: number;
  onNotify?: Notify;
  prefill?: RunPrefill | null;
  onPrefillUsed?: () => void;
}) {
  const [tab, setTab] = useState<"approvals" | "playbooks" | "runs" | "rules">(initialTab);
  const [pendingCount, setPendingCount] = useState(0);
  return (
    <div className="flex h-full min-h-0 flex-col gap-3 text-[11px]">
      <div className="flex flex-wrap items-center gap-2">
        <div className="text-[15px] font-semibold text-slate-100">🛡 PseudoLock Response</div>
        <div className="ml-2 flex gap-1 rounded-lg border border-slate-800 bg-slate-900/60 p-0.5">
          {(["approvals", "playbooks", "runs", "rules"] as const).map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={cn("rounded-md px-3 py-1 text-[11px] font-medium", tab === t ? "bg-cyan-500/15 text-cyan-200 ring-1 ring-cyan-500/40" : "text-slate-400 hover:text-slate-200")}>
              {t === "approvals" ? "✋ Approvals" : t === "playbooks" ? "📘 Playbooks" : t === "runs" ? "▶ Runs" : "⚙ Rules"}
              {t === "approvals" && pendingCount > 0 && <span className="ml-1 rounded-full bg-amber-500 px-1.5 text-[9px] font-bold text-slate-950">{pendingCount}</span>}
            </button>
          ))}
        </div>
        <span className="text-[10px] text-slate-500">Actions wait here for a person · playbooks run several steps one after the other · rules start playbooks by themselves</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {tab === "approvals" && <ApprovalsTab canEdit={canEdit} refreshTick={refreshTick} onNotify={onNotify} onCount={setPendingCount} />}
        {tab === "playbooks" && <PlaybooksTab canEdit={canEdit} refreshTick={refreshTick} onNotify={onNotify} prefill={prefill} onPrefillUsed={onPrefillUsed} onStarted={() => setTab("runs")} />}
        {tab === "runs" && <RunsTab canEdit={canEdit} refreshTick={refreshTick} onNotify={onNotify} />}
        {tab === "rules" && <RulesTab canEdit={canEdit} refreshTick={refreshTick} onNotify={onNotify} onOpenTab={setTab} />}
      </div>
      {/* keep the badge right even when another tab is open */}
      {tab !== "approvals" && <ApprovalCounter refreshTick={refreshTick} onCount={setPendingCount} />}
    </div>
  );
}

function ApprovalCounter({ refreshTick, onCount }: { refreshTick: number; onCount: (n: number) => void }) {
  useEffect(() => { api.get(`${P}/approvals/count`).then((r) => onCount(Number(r.data?.pending) || 0)).catch(() => {}); }, [refreshTick, onCount]);
  return null;
}

// ================================================================== approvals
function ApprovalsTab({ canEdit, refreshTick, onNotify, onCount }: { canEdit: boolean; refreshTick: number; onNotify?: Notify; onCount: (n: number) => void }) {
  const [rows, setRows] = useState<Approval[]>([]);
  const [show, setShow] = useState<"pending" | "history">("pending");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [now, setNow] = useState(Date.now());

  const load = useCallback(async () => {
    try {
      const r = await api.get(`${P}/approvals`, { params: { status: "all", limit: 300 } });
      const list: Approval[] = Array.isArray(r.data) ? r.data : [];
      setRows(list);
      onCount(list.filter((a) => a.status === "pending").length);
      setError("");
    } catch (e) { setError(apiErrorMessage(e, "Could not load approvals")); }
  }, [onCount]);
  useEffect(() => { load(); }, [load, refreshTick]);
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  // a pending row whose timer ran out: ask the server (it marks it expired)
  useEffect(() => {
    if (rows.some((a) => a.status === "pending" && new Date(a.expiresAt).getTime() < now - 1500)) load();
  }, [now, rows, load]);

  const decide = async (a: Approval, what: "approve" | "reject") => {
    setBusy(a.id);
    try {
      await api.post(`${P}/approvals/${a.id}/${what}`, { note: notes[a.id] || "" });
      onNotify?.("info", what === "approve" ? "Approved" : "Rejected", `${a.title}${what === "approve" && a.action ? " - sending to the PC…" : ""}`);
      setNotes((n) => ({ ...n, [a.id]: "" }));
      await load();
    } catch (e) {
      onNotify?.("warning", `Could not ${what}`, apiErrorMessage(e, "Request failed"));
      await load();
    } finally { setBusy(null); }
  };

  const pending = rows.filter((a) => a.status === "pending");
  const history = rows.filter((a) => a.status !== "pending");
  const list = show === "pending" ? pending : history;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={() => setShow("pending")} className={cn("rounded border px-2.5 py-1", show === "pending" ? "border-amber-500/60 bg-amber-500/10 text-amber-200" : "border-slate-700 text-slate-400")}>Pending ({pending.length})</button>
        <button onClick={() => setShow("history")} className={cn("rounded border px-2.5 py-1", show === "history" ? "border-cyan-500/60 bg-cyan-500/10 text-cyan-200" : "border-slate-700 text-slate-400")}>History ({history.length})</button>
        <button onClick={load} className="rounded border border-slate-700 px-2 py-1 text-slate-300 hover:text-cyan-200">↻ Refresh</button>
        {!canEdit && <span className="text-slate-500">You have view-only access (viewer role) - only admin / analyst can approve.</span>}
      </div>
      {error && <div className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-red-200">{error}</div>}
      {list.length === 0 && !error && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 text-center text-slate-500">
          {show === "pending" ? (
            <>
              <div className="text-[13px] text-slate-300">Nothing waits for approval ✔</div>
              <div className="mt-1">Requests appear here when TriGate says <b className="text-slate-300">BLOCK</b> on a PC whose agent has <code>auto_response = false</code>,
                when a playbook reaches a “Wait for approval” step, or when a response rule set to “Ask first” matches.</div>
            </>
          ) : "No decided approvals yet."}
        </div>
      )}
      {list.map((a) => {
        const left = new Date(a.expiresAt).getTime() - now;
        const urgent = a.status === "pending" && left < 5 * 60000;
        return (
          <div key={a.id} className={cn("rounded-xl border bg-slate-900/50 p-3", a.status === "pending" ? (urgent ? "border-orange-500/50" : "border-amber-500/30") : "border-slate-800")}>
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge s={a.status} />
                  <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">{ORIGIN_LABEL[a.origin] || a.origin}</span>
                  {a.risk != null && <span className="text-[10px] text-slate-400">risk {a.risk}{a.level ? ` (${a.level})` : ""}</span>}
                  {a.occurrences > 1 && <span className="text-[10px] text-amber-300">seen ×{a.occurrences}</span>}
                </div>
                <div className="mt-1 text-[13px] font-semibold text-slate-100">{a.title}</div>
                <div className="mt-0.5 text-slate-400">
                  {a.kind === "playbook_start" ? <>Starts playbook <b className="text-slate-200">{a.playbookName}</b> when approved</>
                    : a.action ? <>Action: <b className="text-slate-200">{a.actionLabel}</b>{a.target && <> → <code className="text-cyan-200">{a.target}</code></>}{a.params?.minutes ? ` · ${a.params.minutes} min` : ""}{a.params?.kbps ? ` · ${a.params.kbps} kbit/s` : ""}</>
                    : <>Playbook <b className="text-slate-200">{a.playbookName}</b> continues after approval</>}
                  {a.endpoint && <> · PC <b className="text-slate-200">{a.endpoint}</b></>}
                </div>
                {a.reason && <div className="mt-0.5 text-[10px] text-slate-500">{a.reason}</div>}
              </div>
              <div className="text-right text-[10px] text-slate-400">
                {a.status === "pending" ? (
                  <>
                    <div>expires in</div>
                    <div className={cn("text-[16px] font-bold tabular-nums", urgent ? "text-orange-300" : "text-amber-200")}>{countdown(a.expiresAt, now)}</div>
                    <div>at {new Date(a.expiresAt).toLocaleTimeString()}</div>
                  </>
                ) : (
                  <>
                    {a.decidedBy && <div>{a.status === "rejected" ? "Rejected" : "Approved"} by <b className="text-slate-200">{a.decidedBy}</b></div>}
                    {a.decidedAt && <div>{fmt(a.decidedAt)}</div>}
                    {a.status === "expired" && <div>Nobody decided within {a.expiresMinutes} min</div>}
                  </>
                )}
              </div>
            </div>
            <div className="mt-1 text-[10px] text-slate-500">Requested by {a.requestedBy} · {fmt(a.requestedAt)}{a.alertId ? ` · alert ${a.alertId}` : ""}</div>
            {a.note && <div className="mt-1 text-[10px] text-slate-300">📝 {a.note}</div>}
            {a.status === "done" && <div className="mt-1 rounded bg-emerald-500/10 px-2 py-1 text-emerald-200">✅ {a.kind === "playbook_start" ? (a.result || "Playbook started") : <>Done on the PC{a.result ? `: ${a.result}` : ""}</>}</div>}
            {a.status === "failed" && <div className="mt-1 rounded bg-red-500/10 px-2 py-1 text-red-200">❌ Failed: {a.error}</div>}
            {a.status === "running" && <div className="mt-1 rounded bg-cyan-500/10 px-2 py-1 text-cyan-200">◔ Sent to {a.endpoint} - waiting for the agent's answer…</div>}
            {a.status === "pending" && canEdit && (
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <input value={notes[a.id] || ""} onChange={(e) => setNotes((n) => ({ ...n, [a.id]: e.target.value }))} placeholder="Note (optional) - why you approve / reject"
                  className={cn(inputCls, "min-w-[200px] flex-1")} />
                <button disabled={busy === a.id} onClick={() => decide(a, "approve")}
                  className="rounded bg-emerald-500/85 px-3 py-1 font-semibold text-slate-950 disabled:opacity-50">{a.kind === "playbook_start" ? "✔ Approve & start" : "✔ Approve"}</button>
                <button disabled={busy === a.id} onClick={() => decide(a, "reject")}
                  className="rounded border border-red-500/60 px-3 py-1 font-semibold text-red-200 disabled:opacity-50">✖ Reject</button>
              </div>
            )}
            {a.history?.length > 1 && (
              <details className="mt-1 text-[10px] text-slate-500">
                <summary className="cursor-pointer">History ({a.history.length})</summary>
                {a.history.slice().reverse().map((h, i) => <div key={i} className="pl-2">• {fmt(h.at)} · {h.by} · {h.what}</div>)}
              </details>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ================================================================== playbooks
function stepSummary(s: PlaybookStep, cat: Catalog | null) {
  if (s.type === "action") {
    const a = cat?.actions.find((x) => x.id === s.action);
    const extra = [s.params?.minutes ? `${s.params.minutes} min` : "", s.params?.kbps ? `${s.params.kbps} kbit/s` : ""].filter(Boolean).join(", ");
    return `${a?.label || s.action}${s.target ? ` → ${s.target}` : ""}${extra ? ` (${extra})` : ""}${s.onFailure === "continue" ? " · if it fails: continue" : ""}`;
  }
  if (s.type === "approval") return `Wait for approval: “${s.message}” (expires ${s.expiresMinutes} min)`;
  if (s.type === "notify") return `Notify (${s.level}): “${s.message}”`;
  return `Wait ${s.seconds} seconds`;
}

function PlaybooksTab({ canEdit, refreshTick, onNotify, prefill, onPrefillUsed, onStarted }: {
  canEdit: boolean; refreshTick: number; onNotify?: Notify; prefill?: RunPrefill | null; onPrefillUsed?: () => void; onStarted: () => void;
}) {
  const cat = useCatalog();
  const [list, setList] = useState<Playbook[]>([]);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<Partial<Playbook> | null>(null);
  const [running, setRunning] = useState<Playbook | null>(null);
  const [runPrefill, setRunPrefill] = useState<RunPrefill | null>(null);

  const load = useCallback(async () => {
    try { const r = await api.get(`${P}/playbooks`); setList(Array.isArray(r.data) ? r.data : []); setError(""); }
    catch (e) { setError(apiErrorMessage(e, "Could not load playbooks")); }
  }, []);
  useEffect(() => { load(); }, [load, refreshTick]);

  // opened from an alert: pre-select the suggested playbook
  useEffect(() => {
    if (!prefill || !list.length) return;
    const id = suggestPlaybook(prefill.pattern, Boolean(prefill.vars?.pid));
    const pb = list.find((p) => p.id === id) || list[0];
    setRunPrefill(prefill);
    setRunning(pb);
    onPrefillUsed?.();
  }, [prefill, list, onPrefillUsed]);

  const remove = async (p: Playbook) => {
    if (!window.confirm(`Delete playbook "${p.name}"?`)) return;
    try { await api.delete(`${P}/playbooks/${p.id}`); onNotify?.("info", "Playbook deleted", p.name); load(); }
    catch (e) { onNotify?.("warning", "Delete failed", apiErrorMessage(e, "Request failed")); }
  };

  if (editing) {
    return <PlaybookEditor cat={cat} initial={editing} onCancel={() => setEditing(null)}
      onSaved={(p) => { setEditing(null); load(); onNotify?.("info", "Playbook saved", p.name); }} />;
  }
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        {canEdit && <button onClick={() => setEditing({ name: "", description: "", enabled: true, steps: [{ type: "action", action: "block_access", target: "{ip}", onFailure: "stop" }] })}
          className="rounded bg-cyan-500/85 px-3 py-1 font-semibold text-slate-950">＋ New playbook</button>}
        <button onClick={load} className="rounded border border-slate-700 px-2 py-1 text-slate-300 hover:text-cyan-200">↻ Refresh</button>
        <span className="text-slate-500">Built-in playbooks are read-only - press <b>Copy &amp; edit</b> to make your own version.</span>
      </div>
      {error && <div className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-red-200">{error}</div>}
      <div className="grid gap-2 lg:grid-cols-2">
        {list.map((p) => (
          <div key={p.id} className={cn("rounded-xl border bg-slate-900/50 p-3", p.enabled ? "border-slate-800" : "border-slate-800 opacity-60")}>
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[13px] font-semibold text-slate-100">{p.name}</span>
                  {p.builtIn ? <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[9px] text-slate-400">BUILT-IN</span>
                    : <span className="rounded bg-cyan-500/10 px-1.5 py-0.5 text-[9px] text-cyan-300">CUSTOM v{p.version || 1}</span>}
                  {!p.enabled && <span className="rounded bg-slate-700 px-1.5 py-0.5 text-[9px] text-slate-300">OFF</span>}
                </div>
                {p.description && <div className="mt-0.5 text-slate-400">{p.description}</div>}
              </div>
            </div>
            <ol className="mt-2 space-y-0.5">
              {p.steps.map((s, i) => (
                <li key={i} className="flex gap-1.5 text-slate-300"><span className="w-4 text-right text-slate-500">{i + 1}.</span><span>{stepSummary(s, cat)}</span></li>
              ))}
            </ol>
            <div className="mt-2 text-[10px] text-slate-500">
              Needs: {[p.needsPc ? "PC" : "", ...p.variables.filter((v) => v !== "pc" && v !== "alert").map((v) => cat?.variables.find((x) => x.id === v)?.label || v)].filter(Boolean).join(", ") || "nothing"}
              {!p.builtIn && p.createdBy ? ` · by ${p.updatedBy || p.createdBy}` : ""}
            </div>
            {canEdit && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                <button disabled={!p.enabled} onClick={() => { setRunPrefill(null); setRunning(p); }} className="rounded bg-emerald-500/85 px-2.5 py-1 font-semibold text-slate-950 disabled:opacity-40">▶ Run</button>
                <button onClick={() => setEditing({ ...p, id: undefined, builtIn: false, name: `${p.name} (copy)` })} className="rounded border border-slate-600 px-2.5 py-1 text-slate-200">⧉ Copy &amp; edit</button>
                {!p.builtIn && <button onClick={() => setEditing(p)} className="rounded border border-slate-600 px-2.5 py-1 text-slate-200">✎ Edit</button>}
                {!p.builtIn && <button onClick={() => remove(p)} className="rounded border border-red-500/50 px-2.5 py-1 text-red-200">🗑 Delete</button>}
              </div>
            )}
          </div>
        ))}
      </div>
      {running && (
        <RunPlaybookDialog playbooks={list} initialId={running.id} prefill={runPrefill} onClose={() => setRunning(null)} onNotify={onNotify}
          onStarted={() => { setRunning(null); onStarted(); }} />
      )}
    </div>
  );
}

// ------------------------------------------------------------------ editor
function PlaybookEditor({ cat, initial, onCancel, onSaved }: { cat: Catalog | null; initial: Partial<Playbook>; onCancel: () => void; onSaved: (p: Playbook) => void }) {
  const [name, setName] = useState(initial.name || "");
  const [description, setDescription] = useState(initial.description || "");
  const [enabled, setEnabled] = useState(initial.enabled !== false);
  const [steps, setSteps] = useState<PlaybookStep[]>(() => JSON.parse(JSON.stringify(initial.steps || [])));
  const [errors, setErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const maxSteps = cat?.maxSteps || 15;

  const upd = (i: number, patch: Partial<PlaybookStep>) => setSteps((s) => s.map((x, j) => (j === i ? { ...x, ...patch } : x)));
  const move = (i: number, d: number) => setSteps((s) => { const n = [...s]; const j = i + d; if (j < 0 || j >= n.length) return s; [n[i], n[j]] = [n[j], n[i]]; return n; });
  const blank = (type: StepType): PlaybookStep =>
    type === "action" ? { type, action: "block_access", target: "{ip}", onFailure: "stop" }
      : type === "approval" ? { type, message: "Continue on {pc}?", expiresMinutes: cat?.approvalExpiryMinutes || 30 }
        : type === "notify" ? { type, message: "Playbook step done on {pc}", level: "info" }
          : { type, seconds: 30 };
  const setAction = (i: number, id: string) => {
    const a = cat?.actions.find((x) => x.id === id);
    const params: Record<string, number> = {};
    for (const p of a?.params || []) params[p.key] = p.def;
    const guess = a?.target === "user" ? "{user}" : a?.target === "process" ? "{pid}" : a?.target === "badge" ? "{badge}" : a?.target === "label" ? "{pc}" : "{ip}";
    upd(i, { action: id, params, target: guess });
  };

  const save = async () => {
    setSaving(true);
    setErrors([]);
    const body = { name, description, enabled, steps };
    try {
      const r = initial.id ? await api.put(`${P}/playbooks/${initial.id}`, body) : await api.post(`${P}/playbooks`, body);
      onSaved(r.data);
    } catch (e: any) {
      const errs: string[] = e?.response?.data?.errors || [apiErrorMessage(e, "Save failed")];
      setErrors(errs);
    } finally { setSaving(false); }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-3 rounded-xl border border-cyan-500/30 bg-slate-900/60 p-4">
      <div className="flex items-center justify-between">
        <div className="text-[14px] font-semibold text-slate-100">{initial.id ? "✎ Edit playbook" : "＋ New playbook"}</div>
        <button onClick={onCancel} className="text-slate-500 hover:text-slate-300">✕</button>
      </div>
      <div className="grid gap-2 md:grid-cols-[2fr_3fr]">
        <label className="space-y-0.5"><span className="text-[10px] uppercase tracking-wider text-slate-500">Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Block attacker and lock account" className={inputCls} maxLength={80} /></label>
        <label className="space-y-0.5"><span className="text-[10px] uppercase tracking-wider text-slate-500">Description (when to use it)</span>
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g. For password guessing from the internet" className={inputCls} maxLength={400} /></label>
      </div>
      <label className="flex items-center gap-2 text-slate-300"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled (can be run)</label>
      <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2 text-[10px] text-slate-400">
        💡 In targets and messages you can use <b>variables</b> - they are filled in when you press Run:{" "}
        {(cat?.variables || []).map((v) => <code key={v.id} className="mr-1.5 text-cyan-300" title={`${v.label}, e.g. ${v.example}`}>{`{${v.id}}`}</code>)}
        <span>({(cat?.variables || []).map((v) => `{${v.id}} = ${v.label}`).join(", ")})</span>
      </div>

      <div className="space-y-2">
        {steps.map((s, i) => {
          const a = cat?.actions.find((x) => x.id === s.action);
          return (
            <div key={i} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="w-14 text-[11px] font-semibold text-slate-400">Step {i + 1}</span>
                <select value={s.type} onChange={(e) => setSteps((st) => st.map((x, j) => (j === i ? blank(e.target.value as StepType) : x)))} className={cn(inputCls, "w-auto")}>
                  {(Object.keys(TYPE_LABEL) as StepType[]).map((t) => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}
                </select>
                <div className="ml-auto flex gap-1">
                  <button title="Move up" disabled={i === 0} onClick={() => move(i, -1)} className="rounded border border-slate-700 px-1.5 text-slate-300 disabled:opacity-30">↑</button>
                  <button title="Move down" disabled={i === steps.length - 1} onClick={() => move(i, 1)} className="rounded border border-slate-700 px-1.5 text-slate-300 disabled:opacity-30">↓</button>
                  <button title="Remove step" onClick={() => setSteps((st) => st.filter((_, j) => j !== i))} className="rounded border border-red-500/50 px-1.5 text-red-300">✕</button>
                </div>
              </div>
              {s.type === "action" && (
                <div className="mt-1.5 grid gap-1.5 md:grid-cols-2">
                  <label className="space-y-0.5"><span className="text-[10px] text-slate-500">Action</span>
                    <select value={s.action} onChange={(e) => setAction(i, e.target.value)} className={inputCls}>
                      {(cat?.actions || []).map((x) => <option key={x.id} value={x.id}>{x.label}{x.runsOn === "backend" ? " (badge system)" : ""}</option>)}
                    </select></label>
                  <label className="space-y-0.5"><span className="text-[10px] text-slate-500">Target - {a?.targetHint || ""}</span>
                    <input value={s.target || ""} onChange={(e) => upd(i, { target: e.target.value })} placeholder={a?.targetOptional ? "(optional)" : "{ip}"} className={inputCls} /></label>
                  {(a?.params || []).map((p) => (
                    <label key={p.key} className="space-y-0.5"><span className="text-[10px] text-slate-500">{p.label} ({p.min}-{p.max})</span>
                      <input type="number" min={p.min} max={p.max} value={s.params?.[p.key] ?? p.def}
                        onChange={(e) => upd(i, { params: { ...(s.params || {}), [p.key]: Number(e.target.value) } })} className={inputCls} /></label>
                  ))}
                  <label className="space-y-0.5"><span className="text-[10px] text-slate-500">If this step fails</span>
                    <select value={s.onFailure || "stop"} onChange={(e) => upd(i, { onFailure: e.target.value as "stop" | "continue" })} className={inputCls}>
                      <option value="stop">Stop the playbook</option>
                      <option value="continue">Continue with the next step</option>
                    </select></label>
                  {a?.help && <div className="text-[10px] text-slate-500 md:col-span-2">{a.help}</div>}
                </div>
              )}
              {s.type === "approval" && (
                <div className="mt-1.5 grid gap-1.5 md:grid-cols-[3fr_1fr]">
                  <label className="space-y-0.5"><span className="text-[10px] text-slate-500">Question shown in Pending approvals</span>
                    <input value={s.message || ""} onChange={(e) => upd(i, { message: e.target.value })} className={inputCls} /></label>
                  <label className="space-y-0.5"><span className="text-[10px] text-slate-500">Expires after (minutes)</span>
                    <input type="number" min={1} max={1440} value={s.expiresMinutes ?? 30} onChange={(e) => upd(i, { expiresMinutes: Number(e.target.value) })} className={inputCls} /></label>
                  <div className="text-[10px] text-slate-500 md:col-span-2">The playbook stops here until someone presses Approve. Reject or no answer in time = the playbook stops.</div>
                </div>
              )}
              {s.type === "notify" && (
                <div className="mt-1.5 grid gap-1.5 md:grid-cols-[3fr_1fr]">
                  <label className="space-y-0.5"><span className="text-[10px] text-slate-500">Message (bell on every open dashboard)</span>
                    <input value={s.message || ""} onChange={(e) => upd(i, { message: e.target.value })} className={inputCls} /></label>
                  <label className="space-y-0.5"><span className="text-[10px] text-slate-500">Level</span>
                    <select value={s.level || "info"} onChange={(e) => upd(i, { level: e.target.value as PlaybookStep["level"] })} className={inputCls}>
                      <option value="info">Info</option><option value="warning">Warning</option><option value="critical">Critical</option>
                    </select></label>
                </div>
              )}
              {s.type === "wait" && (
                <label className="mt-1.5 block w-48 space-y-0.5"><span className="text-[10px] text-slate-500">Seconds (1-3600)</span>
                  <input type="number" min={1} max={3600} value={s.seconds ?? 30} onChange={(e) => upd(i, { seconds: Number(e.target.value) })} className={inputCls} /></label>
              )}
            </div>
          );
        })}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-slate-500">Add step:</span>
          {(Object.keys(TYPE_LABEL) as StepType[]).map((t) => (
            <button key={t} disabled={steps.length >= maxSteps} onClick={() => setSteps((s) => [...s, blank(t)])}
              className="rounded border border-slate-600 px-2 py-0.5 text-slate-200 disabled:opacity-40">＋ {TYPE_LABEL[t]}</button>
          ))}
          <span className="text-[10px] text-slate-500">({steps.length}/{maxSteps})</span>
        </div>
      </div>
      {errors.length > 0 && (
        <div className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-red-200">
          {errors.map((e, i) => <div key={i}>• {e}</div>)}
        </div>
      )}
      <div className="flex gap-2">
        <button disabled={saving} onClick={save} className="rounded bg-cyan-500/85 px-4 py-1.5 font-semibold text-slate-950 disabled:opacity-50">{saving ? "Saving…" : "💾 Save playbook"}</button>
        <button onClick={onCancel} className="rounded border border-slate-600 px-4 py-1.5 text-slate-300">Cancel</button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ run dialog (also used by Alerts)
export function RunPlaybookDialog({ playbooks, initialId, prefill, onClose, onStarted, onNotify }: {
  playbooks?: Playbook[]; initialId?: string; prefill?: RunPrefill | null; onClose: () => void; onStarted?: (run: PlaybookRun) => void; onNotify?: Notify;
}) {
  const cat = useCatalog();
  const pcs = useOnlinePcs(true);
  const [list, setList] = useState<Playbook[]>(playbooks || []);
  const [pbId, setPbId] = useState(initialId || "");
  const [endpoint, setEndpoint] = useState(prefill?.endpoint || "");
  const [vars, setVars] = useState<Record<string, string>>({ ...(prefill?.vars || {}) });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (playbooks?.length) return;
    api.get(`${P}/playbooks`).then((r) => {
      const l: Playbook[] = Array.isArray(r.data) ? r.data : [];
      setList(l);
      if (!initialId) setPbId(suggestPlaybook(prefill?.pattern, Boolean(prefill?.vars?.pid)));
    }).catch((e) => setError(apiErrorMessage(e, "Could not load playbooks")));
  }, [playbooks, initialId, prefill]);
  useEffect(() => { if (!endpoint && pcs.length === 1) setEndpoint(pcs[0]); }, [pcs, endpoint]);

  const pb = useMemo(() => list.find((p) => p.id === pbId) || null, [list, pbId]);
  const needVars = (pb?.variables || []).filter((v) => v !== "pc" && v !== "alert");

  const start = async () => {
    if (!pb) return;
    setBusy(true);
    setError("");
    try {
      const r = await api.post(`${P}/playbooks/${pb.id}/run`, { endpoint, vars, alertId: prefill?.alertId });
      onNotify?.("info", "Playbook started", `${pb.name}${endpoint ? ` on ${endpoint}` : ""} - see Response → Runs`);
      onStarted?.(r.data);
    } catch (e) { setError(apiErrorMessage(e, "Could not start the playbook")); }
    finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-lg space-y-2 rounded-xl border border-emerald-500/30 bg-slate-950 p-4 text-[11px] shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <div className="text-[14px] font-semibold text-slate-100">▶ Run playbook</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300">✕</button>
        </div>
        {prefill?.title && <div className="rounded bg-slate-900 px-2 py-1 text-slate-400">For alert: <span className="text-slate-200">{prefill.title}</span></div>}
        <label className="block space-y-0.5"><span className="text-[10px] uppercase tracking-wider text-slate-500">Playbook</span>
          <select value={pbId} onChange={(e) => setPbId(e.target.value)} className={inputCls}>
            <option value="">- choose -</option>
            {list.filter((p) => p.enabled).map((p) => <option key={p.id} value={p.id}>{p.name}{p.builtIn ? "" : " (custom)"}</option>)}
          </select></label>
        {pb && (
          <>
            <ol className="rounded border border-slate-800 bg-slate-900/50 p-2">
              {pb.steps.map((s, i) => <li key={i} className="text-slate-300">{i + 1}. {stepSummary(s, cat)}</li>)}
            </ol>
            {pb.needsPc && (
              <label className="block space-y-0.5"><span className="text-[10px] uppercase tracking-wider text-slate-500">PC (endpoint) - must be online</span>
                <input list="pl-pcs" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder={pcs[0] || "PC name"} className={inputCls} />
                <datalist id="pl-pcs">{pcs.map((p) => <option key={p} value={p} />)}</datalist>
                <span className="text-[10px] text-slate-500">Online now: {pcs.length ? pcs.join(", ") : "none - start the agent first"}</span>
              </label>
            )}
            {needVars.map((v) => {
              const info = cat?.variables.find((x) => x.id === v);
              return (
                <label key={v} className="block space-y-0.5"><span className="text-[10px] uppercase tracking-wider text-slate-500">{info?.label || v} <code className="normal-case text-cyan-300">{`{${v}}`}</code></span>
                  <input value={vars[v] || ""} onChange={(e) => setVars((x) => ({ ...x, [v]: e.target.value }))} placeholder={`e.g. ${info?.example || ""}`} className={inputCls} /></label>
              );
            })}
          </>
        )}
        {error && <div className="rounded border border-red-500/40 bg-red-500/10 px-2 py-1 text-red-200">{error}</div>}
        <div className="flex gap-2 pt-1">
          <button disabled={!pb || busy} onClick={start} className="rounded bg-emerald-500/85 px-4 py-1.5 font-semibold text-slate-950 disabled:opacity-40">{busy ? "Starting…" : "▶ Start"}</button>
          <button onClick={onClose} className="rounded border border-slate-600 px-4 py-1.5 text-slate-300">Cancel</button>
        </div>
      </div>
    </div>
  );
}

// ================================================================== runs
function RunsTab({ canEdit, refreshTick, onNotify }: { canEdit: boolean; refreshTick: number; onNotify?: Notify }) {
  const [runs, setRuns] = useState<PlaybookRun[]>([]);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try { const r = await api.get(`${P}/runs`, { params: { limit: 50 } }); setRuns(Array.isArray(r.data) ? r.data : []); setError(""); }
    catch (e) { setError(apiErrorMessage(e, "Could not load runs")); }
  }, []);
  useEffect(() => { load(); }, [load, refreshTick]);
  // while something is running, refresh every 3 s (in case the live socket is off)
  useEffect(() => {
    if (!runs.some((r) => r.status === "running" || r.status === "waiting_approval")) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [runs, load]);

  const cancel = async (r: PlaybookRun) => {
    if (!window.confirm(`Cancel "${r.playbookName}"? Steps already done are NOT undone.`)) return;
    try { await api.post(`${P}/runs/${r.id}/cancel`); onNotify?.("info", "Run cancelled", r.playbookName); load(); }
    catch (e) { onNotify?.("warning", "Cancel failed", apiErrorMessage(e, "Request failed")); }
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <button onClick={load} className="rounded border border-slate-700 px-2 py-1 text-slate-300 hover:text-cyan-200">↻ Refresh</button>
        <span className="text-slate-500">Last 50 playbook runs. Start one from the Playbooks tab or from an alert (Alerts → open an alert → ▶ Run playbook).</span>
      </div>
      {error && <div className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-red-200">{error}</div>}
      {!error && runs.length === 0 && <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 text-center text-slate-500">No playbook has been run yet.</div>}
      {runs.map((r) => (
        <div key={r.id} className="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge s={r.status} />
            <span className="text-[13px] font-semibold text-slate-100">{r.playbookName}</span>
            {r.endpoint && <span className="text-slate-400">on <b className="text-slate-200">{r.endpoint}</b></span>}
            {r.trigger === "rule" && <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-[10px] text-violet-200 ring-1 ring-violet-500/30">⚙ automatic (rule)</span>}
            <span className="text-[10px] text-slate-500">started by {r.startedBy} · {fmt(r.startedAt)}{r.finishedAt ? ` · finished ${new Date(r.finishedAt).toLocaleTimeString()}` : ""}</span>
            {canEdit && (r.status === "running" || r.status === "waiting_approval") && (
              <button onClick={() => cancel(r)} className="ml-auto rounded border border-red-500/50 px-2 py-0.5 text-red-200">■ Cancel</button>
            )}
          </div>
          {Object.keys(r.vars || {}).filter((k) => r.vars[k] && r.vars[k] !== "-" && k !== "pc").length > 0 && (
            <div className="mt-1 text-[10px] text-slate-500">{Object.entries(r.vars).filter(([k, v]) => v && v !== "-" && k !== "pc").map(([k, v]) => `${k} = ${v}`).join(" · ")}</div>
          )}
          <ol className="mt-2 space-y-1">
            {r.steps.map((s, i) => (
              <li key={i} className={cn("flex gap-2 rounded px-2 py-1", i === r.current && (r.status === "running" || r.status === "waiting_approval") ? "bg-cyan-500/5 ring-1 ring-cyan-500/30" : "")}>
                <span className="w-4 text-center">{STEP_ICON[s.status] || "•"}</span>
                <div className="min-w-0 flex-1">
                  <div className={cn(s.status === "skipped" ? "text-slate-500" : "text-slate-200")}>{i + 1}. {s.label}</div>
                  {(s.message || s.error) && <div className={cn("text-[10px]", s.error ? "text-red-300" : "text-slate-500")}>{s.error || s.message}</div>}
                  {s.status === "waiting" && <div className="text-[10px] text-amber-300">→ Open the Approvals tab and press Approve or Reject</div>}
                </div>
                <Badge s={s.status} />
              </li>
            ))}
          </ol>
          {r.message && r.status !== "running" && r.status !== "waiting_approval" && <div className="mt-1 text-[10px] text-slate-400">{r.message}</div>}
        </div>
      ))}
    </div>
  );
}

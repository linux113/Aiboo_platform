// PseudoLock Response -> "⚙ Rules" tab (backend: services/responseRules.service.js)
// WHEN a TriGate decision matches -> THEN run a playbook automatically, ask
// first, or only notify. Rules are checked from top to bottom; the first rule
// that matches is used. Safety: cooldown, max runs per hour, test mode and
// "Test against old alerts".
import { useCallback, useEffect, useMemo, useState } from "react";
import api, { apiErrorMessage } from "../utils/api";
import { cn } from "../utils/cn";
import type { Playbook } from "./ResponseModule";

type Notify = (type: "critical" | "warning" | "info", title: string, body: string) => void;
type Mode = "auto" | "ask" | "notify";
interface Conditions {
  patterns: string[]; minRisk: number; verdicts: string[]; pcs: string[]; importance: string[];
  ipKind: "any" | "internet" | "office" | "none"; hours: "any" | "office" | "off";
}
export interface ResponseRule {
  id: string; name: string; description: string; enabled: boolean; testMode: boolean; mode: Mode;
  playbookId: string | null; playbookName: string | null; notifyLevel: "info" | "warning" | "critical";
  conditions: Conditions; cooldownMinutes: number; maxPerHour: number; priority: number;
  createdBy?: string; updatedBy?: string; createdAt?: string; updatedAt?: string;
  stats?: { triggered: number; lastTriggeredAt: string | null; lastOutcome: string | null };
}
interface RuleEvent {
  id: string; ruleId: string; ruleName: string; outcome: string; at: string; endpoint: string; pattern: string; risk: number;
  verdict: string; vars: Record<string, string>; message: string; runId: string | null; approvalId: string | null; testMode: boolean;
}
interface Opt { id: string; label: string }
interface RulesCatalog { patterns: Opt[]; verdicts: string[]; importance: string[]; ipKinds: Opt[]; hours: Opt[]; officeHours: [number, number] }
interface Preview {
  days: number; checked: number; matched: number; perDay: number; unknownImportance: number;
  samples: { alertId: string; title: string; source: string; risk: number; verdict: string; srcIp?: string; user?: string; when: string; occurrences?: number }[];
  notMatchedBecause: { reason: string; count: number }[];
}

const P = `/pseudolock`;
const inputCls = "w-full rounded border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/60 focus:outline-none";
const fmt = (d?: string | null) => (d ? new Date(d).toLocaleString() : "—");
const MODE: Record<Mode, { label: string; help: string; cls: string }> = {
  auto: { label: "⚡ Run automatically", help: "Starts the playbook at once - nobody has to click.", cls: "bg-red-500/15 text-red-200 ring-red-500/40" },
  ask: { label: "✋ Ask first", help: "Puts it in Approvals - the playbook starts when someone clicks Approve.", cls: "bg-amber-500/15 text-amber-200 ring-amber-500/40" },
  notify: { label: "📣 Notify only", help: "Only shows a message on every open dashboard. Nothing is changed.", cls: "bg-sky-500/15 text-sky-200 ring-sky-500/40" },
};
const OUTCOME: Record<string, { label: string; cls: string }> = {
  ran: { label: "▶ Ran playbook", cls: "text-red-200" },
  asked: { label: "✋ Asked for approval", cls: "text-amber-200" },
  notified: { label: "📣 Notified", cls: "text-sky-200" },
  test: { label: "🧪 Test mode - nothing done", cls: "text-violet-200" },
  cooldown: { label: "⏸ Cooldown - already handled", cls: "text-slate-400" },
  skipped: { label: "– Skipped", cls: "text-slate-400" },
  failed: { label: "❌ Failed", cls: "text-red-300" },
};
const VAR_NAME: Record<string, string> = { ip: "attacker IP", user: "user name", pid: "process id", badge: "badge number" };
const EMPTY: Omit<ResponseRule, "id" | "priority"> = {
  name: "", description: "", enabled: true, testMode: true, mode: "ask", playbookId: "builtin_password_guessing", playbookName: null,
  notifyLevel: "warning", cooldownMinutes: 30, maxPerHour: 10,
  conditions: { patterns: ["brute_force"], minRisk: 55, verdicts: ["block"], pcs: [], importance: [], ipKind: "any", hours: "any" },
};
const EXAMPLES: { label: string; rule: Partial<ResponseRule> }[] = [
  { label: "Password guessing from the internet → block IP + disable user (ask first)", rule: {
    name: "Password guessing from the internet", mode: "ask", playbookId: "builtin_password_guessing",
    conditions: { ...EMPTY.conditions, patterns: ["brute_force", "account_lockout"], minRisk: 55, ipKind: "internet" } } },
  { label: "Known-bad IP → slow down + block (automatic)", rule: {
    name: "Known-bad IP", mode: "auto", playbookId: "builtin_bad_ip",
    conditions: { ...EMPTY.conditions, patterns: ["threat_intel_alert"], minRisk: 55, ipKind: "internet" } } },
  { label: "New admin outside office hours → disable account (ask first)", rule: {
    name: "New admin at night", mode: "ask", playbookId: "builtin_new_admin",
    conditions: { ...EMPTY.conditions, patterns: ["admin_group_add", "account_created"], minRisk: 35, verdicts: ["block", "hold"], hours: "off" } } },
  { label: "Security log cleared → tell everyone (notify only)", rule: {
    name: "Security log cleared", mode: "notify", playbookId: null, notifyLevel: "critical",
    conditions: { ...EMPTY.conditions, patterns: ["log_cleared", "audit_policy_changed"], minRisk: 35, verdicts: ["block", "hold"] } } },
];

function whenText(c: Conditions, cat: RulesCatalog | null) {
  const label = (id: string) => cat?.patterns.find((p) => p.id === id)?.label || id;
  const parts = [
    c.patterns.length ? c.patterns.map(label).join(" or ") : "any attack type",
    `risk ${c.minRisk} or more`,
    `TriGate ${c.verdicts.map((v) => v.toUpperCase()).join(" / ")}`,
    c.pcs.length ? `on ${c.pcs.join(", ")}` : "on any PC",
  ];
  if (c.importance.length) parts.push(`PC importance ${c.importance.join("/")}`);
  if (c.ipKind !== "any") parts.push(cat?.ipKinds.find((k) => k.id === c.ipKind)?.label.toLowerCase() || c.ipKind);
  if (c.hours !== "any") {
    const [a, b] = cat?.officeHours || [8, 20];
    parts.push(c.hours === "office" ? `office hours (${a}:00-${b}:00)` : `outside office hours (before ${a}:00 or after ${b}:00)`);
  }
  return parts.join(" · ");
}

// ================================================================== tab
export default function RulesTab({ canEdit, refreshTick, onNotify, onOpenTab }: {
  canEdit: boolean; refreshTick: number; onNotify?: Notify; onOpenTab?: (t: "approvals" | "playbooks" | "runs" | "rules") => void;
}) {
  const [rules, setRules] = useState<ResponseRule[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [cat, setCat] = useState<RulesCatalog | null>(null);
  const [activity, setActivity] = useState<RuleEvent[]>([]);
  const [editing, setEditing] = useState<Partial<ResponseRule> | null>(null);
  const [previews, setPreviews] = useState<Record<string, Preview | "loading">>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [r, a] = await Promise.all([api.get(`${P}/rules`), api.get(`${P}/rules/activity`, { params: { limit: 60 } })]);
      setRules(Array.isArray(r.data) ? r.data : []);
      setActivity(Array.isArray(a.data) ? a.data : []);
      setError("");
    } catch (e) { setError(apiErrorMessage(e, "Could not load rules")); }
  }, []);
  useEffect(() => { load(); }, [load, refreshTick]);
  useEffect(() => {
    api.get(`${P}/catalog`).then((r) => setCat(r.data?.rules || null)).catch(() => setCat(null));
    api.get(`${P}/playbooks`).then((r) => setPlaybooks(Array.isArray(r.data) ? r.data : [])).catch(() => setPlaybooks([]));
  }, [refreshTick]);

  const act = async (fn: () => Promise<unknown>, ok?: string) => {
    setBusy(true);
    try { await fn(); if (ok) onNotify?.("info", "Rules", ok); await load(); } catch (e) { onNotify?.("warning", "Rules", apiErrorMessage(e, "Request failed")); } finally { setBusy(false); }
  };
  const move = (i: number, d: -1 | 1) => {
    const ids = rules.map((r) => r.id);
    const j = i + d;
    if (j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    act(() => api.post(`${P}/rules/reorder`, { ids }));
  };
  const preview = async (key: string, body: Partial<ResponseRule>) => {
    setPreviews((p) => ({ ...p, [key]: "loading" }));
    try {
      const r = await api.post(`${P}/rules/preview`, { conditions: body.conditions, days: 30 });
      setPreviews((p) => ({ ...p, [key]: r.data }));
    } catch (e) {
      setPreviews((p) => { const n = { ...p }; delete n[key]; return n; });
      onNotify?.("warning", "Test against old alerts", apiErrorMessage(e, "Failed"));
    }
  };

  if (editing) {
    return (
      <RuleEditor cat={cat} playbooks={playbooks} initial={editing} onCancel={() => setEditing(null)}
        preview={previews.__editor} onPreview={(b) => preview("__editor", b)}
        onSaved={(r) => { setEditing(null); setPreviews((p) => { const n = { ...p }; delete n.__editor; return n; }); onNotify?.("info", "Rule saved", `${r.name} - ${r.enabled ? (r.testMode ? "ON in test mode" : "ON") : "OFF"}`); load(); }} />
    );
  }

  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-violet-500/30 bg-violet-500/5 p-3 text-slate-300">
        <div className="text-[12px] font-semibold text-violet-200">⚙ Response rules - "WHEN this happens → THEN do that"</div>
        <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[10px] text-slate-400">
          <li>Every time TriGate says <b>BLOCK</b> or <b>HOLD</b>, the rules below are checked <b>from top to bottom</b>. The <b>first rule that matches</b> is used - the others are ignored.</li>
          <li>If no rule matches, nothing changes: the TriGate suggestions wait in <b>✋ Approvals</b> as before.</li>
          <li>New rules start in <b>🧪 test mode</b>: they only write "would have run" in the Activity list below. Switch test mode off when you are happy.</li>
          <li>Safety: the same attack (same PC + IP + user) is handled only once per <b>cooldown</b>; above <b>max runs per hour</b> the rule asks instead of running.</li>
          <li>If an agent has <code>auto_response = true</code> in config.ini, that PC already acts by itself - a rule may then do the same thing a second time.</li>
        </ul>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {canEdit && <button data-testid="rule-new" onClick={() => setEditing({ ...EMPTY })} className="rounded bg-cyan-500/85 px-3 py-1 font-semibold text-slate-950">＋ New rule</button>}
        {canEdit && <select aria-label="Start from an example" value="" onChange={(e) => { const ex = EXAMPLES[Number(e.target.value)]; if (ex) setEditing({ ...EMPTY, ...ex.rule }); }} className={cn(inputCls, "w-auto")}>
          <option value="">…or start from an example</option>
          {EXAMPLES.map((ex, i) => <option key={ex.label} value={i}>{ex.label}</option>)}
        </select>}
        {!canEdit && <span className="text-slate-500">Only admin / analyst can change rules.</span>}
        <button onClick={load} className="ml-auto rounded border border-slate-700 px-2 py-0.5 text-slate-300">⟳ Refresh</button>
      </div>
      {error && <div className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-red-200">{error}</div>}
      {!error && rules.length === 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 text-center text-slate-500">
          No rules yet - everything waits in Approvals. Click <b>＋ New rule</b> or pick an example.
        </div>
      )}

      {rules.map((r, i) => {
        const pv = previews[r.id];
        return (
          <div key={r.id} data-testid="rule-card" className={cn("rounded-xl border bg-slate-900/50 p-3", r.enabled ? "border-slate-700" : "border-slate-800 opacity-60")}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-bold text-slate-300" title="Checked in this order">#{i + 1}</span>
              <span className="text-[13px] font-semibold text-slate-100">{r.name}</span>
              <span className={cn("rounded-full px-2 py-0.5 text-[10px] ring-1", MODE[r.mode].cls)}>{MODE[r.mode].label}</span>
              {r.testMode && <span className="rounded-full bg-violet-500/15 px-2 py-0.5 text-[10px] text-violet-200 ring-1 ring-violet-500/40">🧪 test mode</span>}
              <span className={cn("rounded-full px-2 py-0.5 text-[10px] font-semibold", r.enabled ? "bg-emerald-500/15 text-emerald-300" : "bg-slate-700 text-slate-400")}>{r.enabled ? "ON" : "OFF"}</span>
              {canEdit && (
                <div className="ml-auto flex flex-wrap gap-1">
                  <button disabled={busy || i === 0} onClick={() => move(i, -1)} title="Check earlier" className="rounded border border-slate-700 px-1.5 text-slate-300 disabled:opacity-30">↑</button>
                  <button disabled={busy || i === rules.length - 1} onClick={() => move(i, 1)} title="Check later" className="rounded border border-slate-700 px-1.5 text-slate-300 disabled:opacity-30">↓</button>
                  <button disabled={busy} onClick={() => act(() => api.post(`${P}/rules/${r.id}/enabled`, { enabled: !r.enabled }), `${r.name} switched ${r.enabled ? "OFF" : "ON"}`)}
                    className="rounded border border-slate-700 px-2 text-slate-200">{r.enabled ? "Switch off" : "Switch on"}</button>
                  <button onClick={() => setEditing(r)} className="rounded border border-slate-700 px-2 text-slate-200">✎ Edit</button>
                  <button disabled={busy} onClick={() => { if (window.confirm(`Delete rule "${r.name}"?`)) act(() => api.delete(`${P}/rules/${r.id}`), `${r.name} deleted`); }}
                    className="rounded border border-red-500/40 px-2 text-red-200">🗑</button>
                </div>
              )}
            </div>
            {r.description && <div className="mt-0.5 text-[10px] text-slate-500">{r.description}</div>}
            <div className="mt-1.5 grid gap-1 md:grid-cols-2">
              <div className="rounded bg-slate-950/60 px-2 py-1"><b className="text-cyan-300">WHEN</b> <span className="text-slate-300">{whenText(r.conditions, cat)}</span></div>
              <div className="rounded bg-slate-950/60 px-2 py-1"><b className="text-cyan-300">THEN</b> <span className="text-slate-300">
                {r.mode === "notify" ? `show a ${r.notifyLevel} message on the dashboards` : `${r.mode === "auto" ? "run" : "ask to run"} playbook "${r.playbookName || r.playbookId}" on that PC`}
              </span></div>
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-3 text-[10px] text-slate-500">
              <span>cooldown {r.cooldownMinutes} min</span>
              {r.mode === "auto" && <span>max {r.maxPerHour} runs / hour</span>}
              <span>matched {r.stats?.triggered || 0}×{r.stats?.lastTriggeredAt ? ` · last ${fmt(r.stats.lastTriggeredAt)}` : ""}</span>
              {r.createdBy && <span>made by {r.createdBy}</span>}
              <button onClick={() => preview(r.id, r)} className="rounded border border-slate-700 px-2 py-0.5 text-slate-300">🔍 Test against old alerts</button>
            </div>
            {pv && <PreviewBox p={pv} onClose={() => setPreviews((x) => { const n = { ...x }; delete n[r.id]; return n; })} />}
          </div>
        );
      })}

      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3">
        <div className="mb-1 flex items-center gap-2">
          <span className="text-[12px] font-semibold text-slate-200">📜 Activity - what the rules did</span>
          <span className="text-[10px] text-slate-500">newest first · kept 90 days</span>
        </div>
        {activity.length === 0 && <div className="text-slate-500">Nothing yet. When a rule matches an attack it is listed here.</div>}
        <div className="space-y-1">
          {activity.map((e) => (
            <div key={e.id} data-testid="rule-event" className="flex flex-wrap items-baseline gap-x-2 border-b border-slate-800/60 pb-1">
              <span className="text-[10px] tabular-nums text-slate-500">{fmt(e.at)}</span>
              <span className={cn("font-semibold", OUTCOME[e.outcome]?.cls)}>{OUTCOME[e.outcome]?.label || e.outcome}</span>
              <span className="text-slate-300">rule <b>{e.ruleName}</b></span>
              {e.endpoint && <span className="text-slate-400">PC {e.endpoint}</span>}
              <span className="min-w-[200px] flex-1 text-[10px] text-slate-400">{e.message}</span>
              {e.runId && <button onClick={() => onOpenTab?.("runs")} className="text-[10px] text-cyan-300 underline">see run</button>}
              {e.approvalId && <button onClick={() => onOpenTab?.("approvals")} className="text-[10px] text-amber-300 underline">see approval</button>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ================================================================== preview
function PreviewBox({ p, onClose }: { p: Preview | "loading"; onClose?: () => void }) {
  if (p === "loading") return <div className="mt-2 rounded border border-slate-700 bg-slate-950/60 px-2 py-1 text-slate-400">Checking old alerts…</div>;
  return (
    <div data-testid="rule-preview" className="mt-2 rounded border border-cyan-500/30 bg-cyan-500/5 p-2">
      <div className="flex items-center gap-2">
        <b className="text-cyan-200">Last {p.days} days: this rule would have matched {p.matched} of {p.checked} TriGate alerts</b>
        <span className="text-[10px] text-slate-400">(about {p.perDay} per day)</span>
        {onClose && <button onClick={onClose} className="ml-auto text-slate-400">✕</button>}
      </div>
      {p.matched > 0 && p.perDay > 20 && <div className="mt-0.5 text-amber-300">⚠ That is a lot - make the rule stricter (higher risk, fewer attack types) or use "Ask first".</div>}
      {p.unknownImportance > 0 && <div className="mt-0.5 text-[10px] text-slate-500">{p.unknownImportance} older alerts do not record the PC importance, so they were not counted.</div>}
      {p.samples.length > 0 && (
        <table className="mt-1 w-full text-[10px]">
          <thead><tr className="text-left text-slate-500"><th>When</th><th>PC</th><th>Alert</th><th>Risk</th><th>IP</th><th>User</th></tr></thead>
          <tbody>
            {p.samples.map((s) => (
              <tr key={s.alertId} className="border-t border-slate-800/60 text-slate-300">
                <td className="pr-2">{fmt(s.when)}</td><td className="pr-2">{s.source}</td>
                <td className="pr-2">{s.title}{s.occurrences && s.occurrences > 1 ? ` (×${s.occurrences})` : ""}</td>
                <td className="pr-2">{s.risk} {s.verdict?.toUpperCase()}</td><td className="pr-2">{s.srcIp || "—"}</td><td>{s.user || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {p.notMatchedBecause.length > 0 && (
        <div className="mt-1 text-[10px] text-slate-500">Not matched because: {p.notMatchedBecause.map((n) => `${n.reason} (${n.count})`).join(" · ")}</div>
      )}
    </div>
  );
}

// ================================================================== editor
function Check({ on, label, onChange, testId }: { on: boolean; label: string; onChange: (v: boolean) => void; testId?: string }) {
  return (
    <label className="flex cursor-pointer items-center gap-1.5 text-slate-300">
      <input type="checkbox" data-testid={testId} checked={on} onChange={(e) => onChange(e.target.checked)} /> {label}
    </label>
  );
}

function RuleEditor({ cat, playbooks, initial, onCancel, onSaved, preview, onPreview }: {
  cat: RulesCatalog | null; playbooks: Playbook[]; initial: Partial<ResponseRule>; onCancel: () => void; onSaved: (r: ResponseRule) => void;
  preview?: Preview | "loading"; onPreview: (r: Partial<ResponseRule>) => void;
}) {
  const [r, setR] = useState<Omit<ResponseRule, "id" | "priority"> & { id?: string }>({ ...EMPTY, ...initial, conditions: { ...EMPTY.conditions, ...(initial.conditions || {}) } });
  const [pcText, setPcText] = useState((initial.conditions?.pcs || []).join(", "));
  const [errors, setErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [onlinePcs, setOnlinePcs] = useState<string[]>([]);
  useEffect(() => {
    api.get(`/agent/agents-online`, { timeout: 5000 })
      .then((x) => setOnlinePcs((Array.isArray(x.data?.agents) ? x.data.agents : []).map((a: { endpointId?: string }) => a.endpointId || "").filter(Boolean)))
      .catch(() => setOnlinePcs([]));
  }, []);
  const c = r.conditions;
  const setC = (patch: Partial<Conditions>) => setR((x) => ({ ...x, conditions: { ...x.conditions, ...patch } }));
  const toggle = (list: string[], v: string, on: boolean) => (on ? [...new Set([...list, v])] : list.filter((x) => x !== v));
  const pcs = useMemo(() => pcText.split(",").map((x) => x.trim()).filter(Boolean), [pcText]);
  const body = () => ({ ...r, conditions: { ...c, pcs } });
  const pb = playbooks.find((p) => p.id === r.playbookId);
  const needs = (pb?.variables || []).filter((v) => v !== "pc" && v !== "alert");

  const save = async () => {
    setSaving(true);
    setErrors([]);
    try {
      const res = r.id ? await api.put(`${P}/rules/${r.id}`, body()) : await api.post(`${P}/rules`, body());
      onSaved(res.data);
    } catch (e) {
      const d = (e as { response?: { data?: { errors?: string[] } } }).response?.data;
      setErrors(d?.errors?.length ? d.errors : [apiErrorMessage(e, "Could not save")]);
    } finally { setSaving(false); }
  };

  const box = "rounded-xl border border-slate-800 bg-slate-900/50 p-3";
  return (
    <div className="space-y-3" data-testid="rule-editor">
      <div className="flex items-center gap-2">
        <div className="text-[13px] font-semibold text-slate-100">{r.id ? `Edit rule: ${initial.name}` : "New response rule"}</div>
        <button onClick={onCancel} className="ml-auto rounded border border-slate-700 px-2 py-0.5 text-slate-300">✕ Cancel</button>
      </div>

      <div className={cn(box, "grid gap-2 md:grid-cols-2")}>
        <label className="space-y-0.5"><span className="text-slate-400">Name</span>
          <input aria-label="Rule name" value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} placeholder="e.g. Password guessing from the internet" className={inputCls} /></label>
        <label className="space-y-0.5"><span className="text-slate-400">Description (optional)</span>
          <input value={r.description} onChange={(e) => setR({ ...r, description: e.target.value })} placeholder="Why this rule exists" className={inputCls} /></label>
        <div className="flex flex-wrap gap-4 md:col-span-2">
          <Check on={r.enabled} label="Rule is ON" onChange={(v) => setR({ ...r, enabled: v })} />
          <Check testId="rule-testmode" on={r.testMode} label="🧪 Test mode (only record what it would do - safe)" onChange={(v) => setR({ ...r, testMode: v })} />
        </div>
      </div>

      <div className={box}>
        <div className="mb-1 font-semibold text-cyan-300">WHEN - all of these must be true</div>
        <div className="text-slate-400">Attack type <span className="text-[10px] text-slate-500">(tick none = any type)</span></div>
        <div className="mt-1 grid gap-x-3 gap-y-0.5 sm:grid-cols-2 lg:grid-cols-3">
          {(cat?.patterns || []).map((p) => (
            <Check key={p.id} testId={`pat-${p.id}`} on={c.patterns.includes(p.id)} label={p.label} onChange={(v) => setC({ patterns: toggle(c.patterns, p.id, v) })} />
          ))}
        </div>
        <div className="mt-2 grid gap-2 md:grid-cols-3">
          <label className="space-y-0.5"><span className="text-slate-400">Risk at least (0-100)</span>
            <input aria-label="Minimum risk" type="number" min={0} max={100} value={c.minRisk} onChange={(e) => setC({ minRisk: Number(e.target.value) })} className={inputCls} />
            <span className="text-[10px] text-slate-500">55+ = high (BLOCK) · 75+ = critical · 35+ = medium (HOLD)</span></label>
          <div className="space-y-0.5"><span className="text-slate-400">TriGate verdict</span>
            <div className="flex gap-3">
              <Check on={c.verdicts.includes("block")} label="BLOCK" onChange={(v) => setC({ verdicts: toggle(c.verdicts, "block", v) })} />
              <Check on={c.verdicts.includes("hold")} label="HOLD" onChange={(v) => setC({ verdicts: toggle(c.verdicts, "hold", v) })} />
            </div></div>
          <div className="space-y-0.5"><span className="text-slate-400">PC importance <span className="text-[10px] text-slate-500">(none = any)</span></span>
            <div className="flex flex-wrap gap-3">
              {(cat?.importance || ["low", "normal", "high", "critical"]).map((v) => (
                <Check key={v} on={c.importance.includes(v)} label={v} onChange={(on) => setC({ importance: toggle(c.importance, v, on) })} />
              ))}
            </div></div>
          <label className="space-y-0.5 md:col-span-1"><span className="text-slate-400">Only these PCs <span className="text-[10px] text-slate-500">(empty = all PCs, comma separated)</span></span>
            <input aria-label="PCs" value={pcText} onChange={(e) => setPcText(e.target.value)} placeholder="all PCs" className={inputCls} />
            {onlinePcs.length > 0 && <div className="flex flex-wrap gap-1">{onlinePcs.filter((p) => !pcs.includes(p)).map((p) => (
              <button key={p} onClick={() => setPcText([...pcs, p].join(", "))} className="rounded bg-slate-800 px-1.5 text-[10px] text-slate-300">+ {p}</button>
            ))}</div>}</label>
          <label className="space-y-0.5"><span className="text-slate-400">Where the attack comes from</span>
            <select aria-label="IP type" value={c.ipKind} onChange={(e) => setC({ ipKind: e.target.value as Conditions["ipKind"] })} className={inputCls}>
              {(cat?.ipKinds || []).map((k) => <option key={k.id} value={k.id}>{k.label}</option>)}
            </select></label>
          <label className="space-y-0.5"><span className="text-slate-400">Time of day (PC's clock)</span>
            <select aria-label="Hours" value={c.hours} onChange={(e) => setC({ hours: e.target.value as Conditions["hours"] })} className={inputCls}>
              {(cat?.hours || []).map((k) => <option key={k.id} value={k.id}>{k.label}{k.id !== "any" && cat ? ` (office = ${cat.officeHours[0]}:00-${cat.officeHours[1]}:00)` : ""}</option>)}
            </select></label>
        </div>
      </div>

      <div className={box}>
        <div className="mb-1 font-semibold text-cyan-300">THEN</div>
        <div className="grid gap-1 md:grid-cols-3">
          {(Object.keys(MODE) as Mode[]).map((m) => (
            <label key={m} className={cn("cursor-pointer rounded-lg border p-2", r.mode === m ? "border-cyan-500/60 bg-cyan-500/5" : "border-slate-800")}>
              <div className="flex items-center gap-1.5"><input type="radio" name="rule-mode" data-testid={`mode-${m}`} checked={r.mode === m} onChange={() => setR({ ...r, mode: m })} />
                <b className="text-slate-100">{MODE[m].label}</b></div>
              <div className="mt-0.5 text-[10px] text-slate-400">{MODE[m].help}</div>
            </label>
          ))}
        </div>
        {r.mode !== "notify" ? (
          <div className="mt-2 space-y-1">
            <label className="block space-y-0.5"><span className="text-slate-400">Playbook to run (on the PC where the attack was seen)</span>
              <select aria-label="Playbook" value={r.playbookId || ""} onChange={(e) => setR({ ...r, playbookId: e.target.value })} className={inputCls}>
                <option value="">— choose —</option>
                {playbooks.map((p) => <option key={p.id} value={p.id} disabled={p.enabled === false}>{p.name}{p.builtIn ? " (built-in)" : ""}{p.enabled === false ? " - switched off" : ""}</option>)}
              </select></label>
            {pb && <div className="text-[10px] text-slate-400">Steps: {pb.steps.length} · {pb.description}</div>}
            {needs.length > 0 && (
              <div className="rounded bg-amber-500/10 px-2 py-1 text-[10px] text-amber-200">
                This playbook needs the <b>{needs.map((v) => VAR_NAME[v] || v).join(" and ")}</b>. AiBoO takes it from the attack. If an attack does not have it
                {needs.includes("ip") ? " (for example someone typing wrong passwords at the PC itself has no IP)" : ""}, the rule <b>skips</b> it and the normal approvals are used.
                {needs.includes("badge") ? " Attacks never contain a badge number - use this playbook by hand only." : ""}
              </div>
            )}
          </div>
        ) : (
          <label className="mt-2 block space-y-0.5"><span className="text-slate-400">Message type</span>
            <select value={r.notifyLevel} onChange={(e) => setR({ ...r, notifyLevel: e.target.value as ResponseRule["notifyLevel"] })} className={cn(inputCls, "w-auto")}>
              <option value="info">info</option><option value="warning">warning</option><option value="critical">critical</option>
            </select></label>
        )}
      </div>

      <div className={cn(box, "grid gap-2 md:grid-cols-2")}>
        <div className="font-semibold text-cyan-300 md:col-span-2">SAFETY</div>
        <label className="space-y-0.5"><span className="text-slate-400">Cooldown (minutes)</span>
          <input aria-label="Cooldown" type="number" min={0} max={1440} value={r.cooldownMinutes} onChange={(e) => setR({ ...r, cooldownMinutes: Number(e.target.value) })} className={inputCls} />
          <span className="text-[10px] text-slate-500">Same PC + IP + user is handled only once in this time (0 = every time).</span></label>
        <label className="space-y-0.5"><span className="text-slate-400">Max automatic runs per hour</span>
          <input aria-label="Max per hour" type="number" min={1} max={100} value={r.maxPerHour} onChange={(e) => setR({ ...r, maxPerHour: Number(e.target.value) })} className={inputCls} />
          <span className="text-[10px] text-slate-500">Above this the rule asks for approval instead (protects against a wrong rule).</span></label>
      </div>

      {errors.length > 0 && <div className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-red-200">{errors.map((e) => <div key={e}>• {e}</div>)}</div>}
      <div className="flex flex-wrap items-center gap-2">
        <button data-testid="rule-save" disabled={saving} onClick={save} className="rounded bg-cyan-500/85 px-4 py-1 font-semibold text-slate-950 disabled:opacity-50">💾 Save rule</button>
        <button data-testid="rule-preview-btn" onClick={() => onPreview(body())} className="rounded border border-slate-700 px-3 py-1 text-slate-200">🔍 Test against old alerts</button>
        {!r.testMode && r.mode === "auto" && r.enabled && <span className="text-[10px] text-amber-300">⚠ This rule will change PCs without asking anyone.</span>}
      </div>
      {preview && <PreviewBox p={preview} />}
    </div>
  );
}

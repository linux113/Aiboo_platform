import { useCallback, useEffect, useState } from "react";
import { cn } from "../utils/cn";
import api, { agentH, AGENT_URL } from "../utils/api";
import { sevCls, threatIcon, verdictCls } from "../utils/helpers";
import type {
  AgentFinding,
  CorrelatedAlert,
  GateDecision,
  PseudoLock,
} from "../types";

interface IsoSuggestion {
  id: string;
  event_id: string;
  agent: string;
  threat_type: string;
  severity: string;
  confidence: number;
  summary: string;
  target: string;
  recommended_actions: string[];
  advice: string;
  advice_source: string;
  status: "pending" | "executing" | "executed" | "dismissed" | "failed";
  executed_actions?: string[];
  notes?: string;
  auto?: boolean;
  timestamp: number;
}

const ISO_STATUS_CLS: Record<string, string> = {
  pending: "bg-amber-500/10 text-amber-300 ring-amber-400/40",
  executing: "bg-cyan-500/10 text-cyan-300 ring-cyan-400/40",
  executed: "bg-emerald-500/10 text-emerald-300 ring-emerald-400/40",
  dismissed: "bg-slate-500/10 text-slate-400 ring-slate-500/40",
  failed: "bg-red-500/10 text-red-400 ring-red-500/40",
};

export default function AgentConsole({
  findings,
  correlated,
  gateDecisions,
  pseudoLocks,
  onRestoreLock,
  onSendTestEvent,
}: {
  findings: AgentFinding[];
  correlated: CorrelatedAlert[];
  gateDecisions: GateDecision[];
  pseudoLocks: PseudoLock[];
  onRestoreLock: (id: string) => void;
  onSendTestEvent: (evt: unknown) => void;
}) {
  const [tab, setTab] = useState<
    "findings" | "correlated" | "gates" | "locks" | "isolation" | "send"
  >("findings");
  const [form, setForm] = useState({
    source: "test-sensor",
    event_type: "network_intrusion",
    message: "Test network intrusion from 10.0.0.1",
    severity: "high",
    src_ip: "10.0.0.1",
    dst_port: "443",
  });
  const [sending, setSending] = useState(false);
  const [sendResult, setSendResult] = useState("");

  // ---- Isolation tab state ----
  const [isoSuggestions, setIsoSuggestions] = useState<IsoSuggestion[]>([]);
  const [autoMode, setAutoMode] = useState(false);
  const [isoBusy, setIsoBusy] = useState<string | null>(null);

  const refreshIsolation = useCallback(async () => {
    try {
      const [sug, st] = await Promise.all([
        api.get(`${AGENT_URL}/isolation/suggestions`, agentH()),
        api.get(`${AGENT_URL}/isolation/stats`, agentH()),
      ]);
      setIsoSuggestions(Array.isArray(sug.data) ? sug.data : []);
      setAutoMode(!!st.data?.auto_mode);
    } catch {
      /* agent service offline — keep last known state */
    }
  }, []);

  useEffect(() => {
    refreshIsolation();
    const t = setInterval(refreshIsolation, 8000);
    return () => clearInterval(t);
  }, [refreshIsolation]);

  const executeIso = async (id: string) => {
    setIsoBusy(id);
    try {
      await api.post(`${AGENT_URL}/isolation/execute`, { id }, agentH());
      await refreshIsolation();
    } finally {
      setIsoBusy(null);
    }
  };

  const dismissIso = async (id: string) => {
    setIsoBusy(id);
    try {
      await api.post(`${AGENT_URL}/isolation/dismiss`, { id }, agentH());
      setIsoSuggestions((p) => p.filter((x) => x.id !== id));
    } finally {
      setIsoBusy(null);
    }
  };

  const toggleAuto = async () => {
    try {
      await api.post(`${AGENT_URL}/isolation/auto`, { enabled: !autoMode }, agentH());
      setAutoMode(!autoMode);
    } catch {
      /* best-effort */
    }
  };

  const sendEvent = async () => {
    setSending(true);
    setSendResult("");
    try {
      const res = await api.post(
        `${AGENT_URL}/events`,
        {
          timestamp: new Date().toISOString(),
          source: form.source,
          event_type: form.event_type,
          message: form.message,
          severity: form.severity,
          payload: {
            src_ip: form.src_ip,
            dst_port: parseInt(form.dst_port) || 443,
          },
        },
        agentH()
      );
      setSendResult(`✅ Event accepted — ID: ${res.data.event_id}`);
      onSendTestEvent(res.data);
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } }; message?: string };
      setSendResult(
        `❌ ${err.response?.data?.detail || err.message || "Failed — is agent service running on port 8001?"}`
      );
    } finally {
      setSending(false);
    }
  };

  const tabs = [
    { k: "findings" as const, label: `Findings (${findings.length})` },
    { k: "correlated" as const, label: `Correlated (${correlated.length})` },
    { k: "gates" as const, label: `Gates (${gateDecisions.length})` },
    {
      k: "locks" as const,
      label: `Locks (${pseudoLocks.filter((l) => l.active).length} active)`,
    },
    {
      k: "isolation" as const,
      label: `Isolation (${isoSuggestions.filter((x) => x.status === "pending").length})`,
    },
    { k: "send" as const, label: "Send Event" },
  ];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 overflow-hidden">
        <div className="flex border-b border-slate-800/80 overflow-x-auto">
          {tabs.map((t) => (
            <button
              key={t.k}
              onClick={() => setTab(t.k)}
              className={cn(
                "px-4 py-3 text-xs font-medium flex-shrink-0 transition border-b-2",
                tab === t.k
                  ? "border-cyan-500 text-cyan-200 bg-cyan-500/5"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div className="p-4 min-h-[400px]">
          {tab === "findings" && (
            <div className="space-y-2">
              {findings.length === 0 && (
                <div className="py-8 text-center">
                  <p className="text-slate-500 text-sm">
                    No agent findings yet
                  </p>
                  <p className="text-slate-600 text-xs mt-1">
                    Send a test event using the "Send Event" tab
                  </p>
                </div>
              )}
              {findings.map((f) => (
                <div
                  key={f.id}
                  className={cn(
                    "rounded-xl border p-3",
                    f.severity === "critical"
                      ? "border-red-500/40 bg-red-500/5"
                      : f.severity === "high"
                        ? "border-amber-500/30 bg-amber-500/5"
                        : "border-slate-800 bg-slate-900/40"
                  )}
                >
                  <div className="flex items-start gap-3">
                    <span className="text-xl mt-0.5 flex-shrink-0">
                      {threatIcon(f.threat_type)}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="text-sm font-semibold text-slate-100">
                          {f.agent_name}
                        </span>
                        <span
                          className={cn(
                            "rounded-full px-2 py-0.5 text-[9px] font-medium ring-1",
                            sevCls(f.severity)
                          )}
                        >
                          {f.severity.toUpperCase()}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {(f.confidence * 100) | 0}% confidence
                        </span>
                        <span className="text-[10px] text-slate-600 ml-auto">
                          {new Date(f.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 mb-2">
                        {f.summary}
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {f.actions.map((a) => (
                          <span
                            key={a}
                            className={cn(
                              "rounded-full border px-2 py-0.5 text-[9px] font-medium",
                              a.includes("lock") || a.includes("revoke")
                                ? "border-red-500/40 bg-red-500/10 text-red-300"
                                : a.includes("escalate")
                                  ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
                                  : "border-slate-700 bg-slate-900 text-slate-400"
                            )}
                          >
                            {a.replace(/_/g, " ")}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {tab === "correlated" && (
            <div className="space-y-3">
              {correlated.length === 0 && (
                <div className="py-8 text-center">
                  <p className="text-slate-500 text-sm">
                    No correlated alerts yet
                  </p>
                </div>
              )}
              {correlated.map((a) => (
                <div
                  key={a.alert_id}
                  className="rounded-xl border border-red-500/40 bg-red-500/5 p-4"
                >
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-xl">🔗</span>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-bold text-slate-100">
                          CORRELATED ALERT
                        </span>
                        <span
                          className={cn(
                            "rounded-full px-2 py-0.5 text-[9px] font-medium ring-1",
                            sevCls(a.severity)
                          )}
                        >
                          {a.severity.toUpperCase()}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {(a.confidence * 100) | 0}%
                        </span>
                        <span className="text-[10px] text-slate-600 ml-auto">
                          {new Date(a.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 mt-1">
                        {a.description.replace("[CORRELATED] ", "")}
                      </p>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    {a.findings.map((f) => (
                      <div
                        key={f.id}
                        className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-[11px] text-slate-300"
                      >
                        <span className="font-medium text-slate-200">
                          {f.agent_name}:
                        </span>{" "}
                        {f.summary}
                      </div>
                    ))}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {a.actions.map((ac) => (
                      <span
                        key={ac}
                        className="rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[9px] text-red-300"
                      >
                        {ac.replace(/_/g, " ")}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {tab === "gates" && (
            <div className="space-y-2">
              {gateDecisions.length === 0 && (
                <div className="py-8 text-center">
                  <p className="text-slate-500 text-sm">
                    No gate decisions yet
                  </p>
                </div>
              )}
              {gateDecisions.map((d, i) => (
                <div
                  key={i}
                  className="rounded-lg border border-slate-800 bg-slate-900/60 p-3"
                >
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-[10px] font-bold text-slate-400">
                      GATE {d.gate} — {d.gate_label.toUpperCase()}
                    </span>
                    <span
                      className={cn(
                        "rounded border px-2 py-0.5 text-[9px] font-bold uppercase",
                        verdictCls(d.verdict)
                      )}
                    >
                      {d.verdict}
                    </span>
                    <span
                      className={cn(
                        "rounded-full px-2 py-0.5 text-[9px] font-medium ring-1",
                        sevCls(d.severity)
                      )}
                    >
                      {d.severity}
                    </span>
                    <span className="text-[10px] text-slate-500">
                      {(d.confidence * 100) | 0}%
                    </span>
                    <span className="text-[10px] text-slate-600 ml-auto">
                      {new Date(d.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{d.reason}</p>
                  <div className="flex flex-wrap gap-1.5 mt-1.5">
                    {d.actions.map((a) => (
                      <span
                        key={a}
                        className="rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-[9px] text-slate-400"
                      >
                        {a.replace(/_/g, " ")}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {tab === "locks" && (
            <div className="space-y-3">
              {pseudoLocks.length === 0 && (
                <div className="py-8 text-center">
                  <p className="text-slate-500 text-sm">
                    No pseudo-locks recorded
                  </p>
                </div>
              )}
              {pseudoLocks.map((lock) => (
                <div
                  key={lock.lock_id}
                  className={cn(
                    "rounded-xl border p-4",
                    lock.active
                      ? "border-amber-500/40 bg-amber-500/5"
                      : "border-slate-700 bg-slate-900/40"
                  )}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <span className="text-base">🔒</span>
                        <span className="text-sm font-semibold text-slate-100">
                          {lock.lock_id}
                        </span>
                        <span
                          className={cn(
                            "rounded-full px-2 py-0.5 text-[9px] font-bold",
                            lock.active
                              ? "bg-amber-500/20 text-amber-300"
                              : "bg-emerald-500/10 text-emerald-400"
                          )}
                        >
                          {lock.active ? "ACTIVE" : "RESTORED"}
                        </span>
                        <span
                          className={cn(
                            "rounded-full px-2 py-0.5 text-[9px] font-medium ring-1",
                            sevCls(lock.severity)
                          )}
                        >
                          {lock.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 mb-1">
                        {lock.summary}
                      </p>
                      <div className="text-[10px] text-slate-500 space-y-0.5">
                        <div>Agent: {lock.agent}</div>
                        <div>
                          Locked: {new Date(lock.locked_at).toLocaleString()}
                        </div>
                        {lock.restored_at && (
                          <div>
                            Restored:{" "}
                            {new Date(lock.restored_at).toLocaleString()}
                          </div>
                        )}
                      </div>
                    </div>
                    {lock.active && (
                      <button
                        onClick={() => onRestoreLock(lock.lock_id)}
                        className="flex-shrink-0 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-500/20 transition font-medium"
                      >
                        Restore
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {tab === "isolation" && (
            <div className="space-y-3">
              {/* ---- Control strip ---- */}
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={toggleAuto}
                  className={cn(
                    "rounded-lg px-3 py-1.5 text-[11px] font-bold ring-1 transition",
                    autoMode
                      ? "bg-red-500/15 text-red-300 ring-red-500/50 hover:bg-red-500/25"
                      : "bg-slate-800/60 text-slate-300 ring-slate-600/50 hover:bg-slate-800"
                  )}
                >
                  {autoMode ? "AUTO-RESPOND: ON" : "AUTO-RESPOND: OFF"}
                </button>
                <button
                  onClick={refreshIsolation}
                  className="rounded-lg bg-slate-800/60 px-3 py-1.5 text-[11px] font-medium text-slate-300 ring-1 ring-slate-600/50 hover:bg-slate-800 transition"
                >
                  ⟳ Refresh
                </button>
                <span className="text-[10px] text-slate-500 ml-auto">
                  {isoSuggestions.filter((x) => x.status === "pending").length} pending ·{" "}
                  {isoSuggestions.filter((x) => x.status === "executed").length} executed
                </span>
              </div>

              {isoSuggestions.length === 0 && (
                <div className="py-10 text-center">
                  <p className="text-slate-500 text-sm">No isolation suggestions</p>
                  <p className="text-slate-600 text-xs mt-1">
                    High/critical findings with containment actions appear here for review.
                  </p>
                </div>
              )}

              {isoSuggestions.map((iso) => (
                <div
                  key={iso.id}
                  className={cn(
                    "rounded-xl border p-3",
                    iso.status === "executed"
                      ? "border-emerald-500/30 bg-emerald-500/5"
                      : iso.status === "failed"
                        ? "border-red-500/40 bg-red-500/5"
                        : iso.severity === "critical"
                          ? "border-red-500/40 bg-red-500/5"
                          : "border-amber-500/30 bg-amber-500/5"
                  )}
                >
                  {/* header row */}
                  <div className="flex items-center gap-2 flex-wrap mb-1.5">
                    <span className="text-sm font-semibold text-slate-100">
                      {threatIcon(iso.threat_type)} {iso.threat_type.replace(/_/g, " ")}
                    </span>
                    <span className={cn("rounded-full px-2 py-0.5 text-[9px] font-medium ring-1", sevCls(iso.severity))}>
                      {iso.severity.toUpperCase()}
                    </span>
                    <span className={cn("rounded-full px-2 py-0.5 text-[9px] font-medium ring-1", ISO_STATUS_CLS[iso.status] || ISO_STATUS_CLS.pending)}>
                      {iso.status.toUpperCase()}{iso.auto ? " · AUTO" : ""}
                    </span>
                    <span className="text-[10px] text-slate-600 ml-auto">
                      {new Date(iso.timestamp * 1000).toLocaleTimeString()} · {iso.agent}
                    </span>
                  </div>

                  <div className="text-xs text-slate-300 mb-1">
                    <span className="text-slate-500">Target:</span>{" "}
                    <span className="font-mono text-cyan-300">{iso.target}</span>
                    <span className="text-slate-600"> · {(iso.confidence * 100) | 0}% confidence</span>
                  </div>
                  <div className="text-xs text-slate-400 mb-2">{iso.summary}</div>

                  {/* AI advice */}
                  <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-2.5 mb-2">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[9px] font-bold uppercase tracking-wider text-cyan-300">
                        🤖 AI Suggestion
                      </span>
                      <span className="rounded-full bg-slate-800 px-1.5 py-0.5 text-[8px] text-slate-400 ring-1 ring-slate-600">
                        {iso.advice_source === "llm" ? "LLM" : "offline rules"}
                      </span>
                    </div>
                    <p className="text-[11px] text-cyan-100/90 leading-relaxed">{iso.advice}</p>
                  </div>

                  {/* recommended actions */}
                  <div className="flex items-center gap-1.5 flex-wrap mb-2.5">
                    {(iso.executed_actions?.length ? iso.executed_actions : iso.recommended_actions).map((a) => (
                      <span key={a} className="rounded-md bg-slate-800/80 px-2 py-0.5 text-[9px] font-medium text-slate-300 ring-1 ring-slate-600/60">
                        {a.replace(/_/g, " ")}
                      </span>
                    ))}
                  </div>
                  {iso.notes && (
                    <div className="text-[10px] text-slate-500 mb-2">ℹ️ {iso.notes}</div>
                  )}

                  {/* action buttons */}
                  {(iso.status === "pending" || iso.status === "failed") && (
                    <div className="flex gap-2">
                      <button
                        onClick={() => executeIso(iso.id)}
                        disabled={isoBusy === iso.id}
                        className="rounded-lg bg-gradient-to-r from-red-500 to-orange-500 px-4 py-1.5 text-[11px] font-bold text-white hover:from-red-400 hover:to-orange-400 transition disabled:opacity-50 shadow"
                      >
                        {isoBusy === iso.id ? "Executing..." : "⚡ Take Action"}
                      </button>
                      <button
                        onClick={() => dismissIso(iso.id)}
                        disabled={isoBusy === iso.id}
                        className="rounded-lg bg-slate-800/80 px-4 py-1.5 text-[11px] font-medium text-slate-300 ring-1 ring-slate-600/60 hover:bg-slate-800 transition disabled:opacity-50"
                      >
                        Dismiss
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {tab === "send" && (
            <div className="max-w-lg space-y-4">
              <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 text-[11px] text-cyan-300/80">
                Send a threat event directly to the AiBoO agent service. The
                tri-gate pipeline will process it and results appear in
                real-time.
              </div>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { l: "Source", k: "source" },
                  { l: "Source IP", k: "src_ip" },
                  { l: "Destination Port", k: "dst_port" },
                  { l: "Message", k: "message" },
                ].map((f) => (
                  <div key={f.k} className={f.k === "message" ? "col-span-2" : ""}>
                    <label className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400 mb-1.5">
                      {f.l}
                    </label>
                    <input
                      value={(form as Record<string, string>)[f.k]}
                      onChange={(e) =>
                        setForm((p) => ({ ...p, [f.k]: e.target.value }))
                      }
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                    />
                  </div>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400 mb-1.5">
                    Event Type
                  </label>
                  <select
                    value={form.event_type}
                    onChange={(e) =>
                      setForm((p) => ({ ...p, event_type: e.target.value }))
                    }
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:outline-none"
                  >
                    {[
                      "network_intrusion",
                      "identity_mismatch",
                      "physical_intrusion",
                      "insider_threat",
                      "anomalous_behavior",
                      "correlated_attack",
                    ].map((t) => (
                      <option key={t} value={t}>
                        {t.replace(/_/g, " ")}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400 mb-1.5">
                    Severity
                  </label>
                  <select
                    value={form.severity}
                    onChange={(e) =>
                      setForm((p) => ({ ...p, severity: e.target.value }))
                    }
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:outline-none"
                  >
                    {["low", "medium", "high", "critical"].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </div>
              </div>
              <button
                onClick={sendEvent}
                disabled={sending}
                className="w-full rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 py-2.5 text-sm font-bold text-slate-950 hover:from-cyan-400 hover:to-emerald-400 transition disabled:opacity-50 shadow-lg"
              >
                {sending ? "Sending..." : "Send Test Event"}
              </button>
              {sendResult && (
                <div className="rounded-lg border border-slate-700 bg-slate-900/60 px-4 py-3 text-xs text-slate-300">
                  {sendResult}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
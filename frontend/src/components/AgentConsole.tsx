import { useState, useMemo, useEffect } from "react";
import { cn } from "../utils/cn";
import api, { waitForCommand, apiErrorMessage } from "../utils/api";
import { sevCls, threatIcon, verdictCls } from "../utils/helpers";
import TriGateCard from "./TriGateCard";
import type {
  ActionRecord,
  AgentFinding,
  CorrelatedAlert,
  GateDecision,
  PseudoLock,
} from "../types";

// ---- Filter definitions for the Isolation & Termination tab ----
type ActionFilter =
  | "all"
  | "terminated"
  | "isolated"
  | "quarantined"
  | "pseudo-locked"
  | "failed";

const ACTION_FILTERS: {
  key: ActionFilter;
  label: string;
  actions: string[] | null;
}[] = [
  { key: "all", label: "All", actions: null },
  { key: "terminated", label: "Terminated", actions: ["terminate_process", "force_logout"] },
  { key: "isolated", label: "Isolated", actions: ["isolate_asset", "block_access", "lock_zone", "throttle_segment"] },
  { key: "quarantined", label: "Quarantined", actions: ["quarantine_device", "quarantine_file"] },
  { key: "pseudo-locked", label: "Pseudo-Locked", actions: ["pseudo_lock", "revoke_identity", "restrict_identity"] },
  { key: "failed", label: "Failed", actions: null }, // special-cased on status
];

// ---- Remote dispatch action catalogue ----
// Windows (the socket agent) and Linux (the REST Sentinel) do not support the
// same list, so each entry says which platform(s) it belongs to. A Linux server
// must never be offered "Lock screen" or be told a device will be quarantined.
type DispatchAction = {
  value: string;
  label: string;
  placeholder: string;
  linuxLabel?: string;
  linuxPlaceholder?: string;
  platforms: Array<"windows" | "linux">;
};

const DISPATCH_ACTIONS: DispatchAction[] = [
  { value: "terminate_process", label: "Terminate process", placeholder: "PID or process name (e.g. 1234 or notepad.exe)",
    linuxLabel: "Stop a process", linuxPlaceholder: "PID or process name (e.g. 9881 or python3)", platforms: ["windows", "linux"] },
  { value: "isolate_asset", label: "Isolate IP (inbound)", placeholder: "IP (e.g. 203.0.113.100)",
    linuxPlaceholder: "IP to cut off (e.g. 45.95.147.3)", platforms: ["windows", "linux"] },
  { value: "block_access", label: "Block IP (inbound)", placeholder: "IP (e.g. 10.0.0.45)",
    linuxLabel: "Block IP (iptables / ufw)", platforms: ["windows", "linux"] },
  { value: "quarantine_device", label: "Quarantine device", placeholder: "Device ID (e.g. DEV-ABC123)",
    platforms: ["windows"] },
  { value: "force_logout", label: "Force logout", placeholder: "Windows user name",
    linuxLabel: "Log the user out of their sessions", linuxPlaceholder: "Linux user name (e.g. deploy)", platforms: ["windows", "linux"] },
  { value: "revoke_identity", label: "Revoke identity", placeholder: "Windows user name",
    linuxLabel: "Lock the account (until an admin unlocks it)", linuxPlaceholder: "Linux user name (e.g. deploy)", platforms: ["windows", "linux"] },
  { value: "pseudo_lock", label: "Pseudo-lock", placeholder: "Label (optional, e.g. suspicious-host)",
    linuxLabel: "Open decoy port (honeypot listener)", platforms: ["windows", "linux"] },
  { value: "restrict_identity", label: "Restrict account 30 min (auto re-enable)", placeholder: "Windows user name",
    linuxLabel: "Lock the account for 30 min (auto unlock)", linuxPlaceholder: "Linux user name (e.g. deploy)", platforms: ["windows", "linux"] },
  { value: "lift_restriction", label: "Lift account restriction now", placeholder: "Windows user name",
    linuxLabel: "Unlock the account now", linuxPlaceholder: "Linux user name (e.g. deploy)", platforms: ["windows", "linux"] },
  { value: "throttle_segment", label: "Throttle IP / range 256 kbps, 30 min", placeholder: "IP or range (e.g. 45.95.147.3 or 192.168.1.0/24)",
    linuxLabel: "Rate-limit an IP (iptables hashlimit, approx.)", platforms: ["windows", "linux"] },
  { value: "remove_throttle", label: "Remove throttle", placeholder: "Same IP or range as before",
    linuxLabel: "Remove the rate limit", platforms: ["windows", "linux"] },
  { value: "step_up_auth", label: "Lock screen (user must sign in again)", placeholder: "Windows user name",
    linuxLabel: "Close the sessions (they must sign in again)", linuxPlaceholder: "Linux user name (e.g. deploy)", platforms: ["windows", "linux"] },
];

const isLinuxEndpoint = (platform?: string) => String(platform || "").toLowerCase().startsWith("linux");
const actionsFor = (platform?: string) => {
  const want = isLinuxEndpoint(platform) ? "linux" : "windows";
  return DISPATCH_ACTIONS.filter((a) => a.platforms.includes(want));
};

// ---- Status badge styles ----
const STATUS_STYLES: Record<
  string,
  { icon: string; label: string; cls: string }
> = {
  success: {
    icon: "✅",
    label: "Success",
    cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  },
  failed: {
    icon: "❌",
    label: "Failed",
    cls: "border-red-500/40 bg-red-500/10 text-red-300",
  },
  pending: {
    icon: "⏳",
    label: "Pending",
    cls: "border-slate-500/40 bg-slate-500/10 text-slate-300",
  },
  active: {
    icon: "🔴",
    label: "Active",
    cls: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  },
};

// ---- Time helpers ----
function fmtTime(iso: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
}
function fmtFull(iso: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

// ---- Status badge component ----
function StatusBadge({ status }: { status: string }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.pending;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[9px] font-medium",
        s.cls
      )}
    >
      <span aria-hidden>{s.icon}</span>
      {s.label}
    </span>
  );
}

// ---- Online agent shape (from GET /api/agent/agents-online) ----
interface OnlineAgent {
  endpointId: string;
  hostname: string;
  lastSeen: string;
  platform?: string;              // 'windows' | 'linux' | ...
  channel?: 'socket' | 'rest';    // rest = the Linux Sentinel polling over HTTPS
}

export default function AgentConsole({
  findings,
  correlated,
  gateDecisions,
  pseudoLocks,
  actions,
  onRestoreLock,
  onSendTestEvent,
  onRefreshActions,
  onRetryAction,
  actionsLoading = false,
}: {
  findings: AgentFinding[];
  correlated: CorrelatedAlert[];
  gateDecisions: GateDecision[];
  pseudoLocks: PseudoLock[];
  actions: ActionRecord[];
  onRestoreLock: (id: string) => void;
  onSendTestEvent: (evt: unknown) => void;
  onRefreshActions?: () => void | Promise<void>;
  actionsLoading?: boolean;
  onRetryAction?: (record: ActionRecord) => void | Promise<void>;
}) {
  const [tab, setTab] = useState<
    "findings" | "correlated" | "gates" | "locks" | "actions" | "send"
  >("findings");
  const [form, setForm] = useState({
    source: "test-sensor",
    event_type: "network_intrusion",
    message: "Test network intrusion from 10.0.0.1",
    severity: "high",
    src_ip: "10.0.0.1",
    dst_port: "443",
    user_id: "",
    signature: "",
  });
  const [sending, setSending] = useState(false);
  const [sendResult, setSendResult] = useState("");

  // ---- Isolation & Termination tab local state ----
  const [actionFilter, setActionFilter] = useState<ActionFilter>("all");
  const [actionSearch, setActionSearch] = useState("");
  const [selectedAction, setSelectedAction] = useState<ActionRecord | null>(null);
  const [retryingId, setRetryingId] = useState<string | null>(null);

  // ---- Remote dispatch form state ----
  const [onlineAgents, setOnlineAgents] = useState<OnlineAgent[]>([]);
  const [dispatchEndpoint, setDispatchEndpoint] = useState("");
  const [dispatchAction, setDispatchAction] = useState("terminate_process");
  const [dispatchTarget, setDispatchTarget] = useState("");
  const [dispatching, setDispatching] = useState(false);
  const [dispatchResult, setDispatchResult] = useState("");
  const [dispatchStatus, setDispatchStatus] = useState<"ok" | "err" | "">("");

  // ---- Poll online agents every 10s while the Actions or Send tab is open ----
  useEffect(() => {
    if (tab !== "actions" && tab !== "send") return;
    let cancelled = false;

    const load = async () => {
      try {
        const res = await api.get("/agent/agents-online");
        if (cancelled) return;
        const list: OnlineAgent[] = Array.isArray(res.data?.agents)
          ? res.data.agents
          : [];
        setOnlineAgents(list);
        setDispatchEndpoint((prev) => {
          // Keep current selection if it's still online, otherwise pick first
          if (prev && list.some((a) => a.endpointId === prev)) return prev;
          return list[0]?.endpointId || "";
        });
      } catch {
        if (!cancelled) setOnlineAgents([]);
      }
    };

    load();
    const iv = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(iv);
    };
  }, [tab]);

  // ---- Derived: filtered actions ----
  const filteredActions = useMemo(() => {
    const def = ACTION_FILTERS.find((f) => f.key === actionFilter)!;
    const term = actionSearch.trim().toLowerCase();

    return actions.filter((r) => {
      if (actionFilter === "failed" && r.status !== "failed") return false;
      if (def.actions && !def.actions.includes(r.action)) return false;

      if (term) {
        const hay = [
          r.action,
          r.action_label,
          r.target,
          r.endpoint,
          r.details,
          r.agent,
          r.reason,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!hay.includes(term)) return false;
      }
      return true;
    });
  }, [actions, actionFilter, actionSearch]);

  // ---- Derived: per-filter counts ----
  const actionCounts = useMemo(() => {
    const map: Record<ActionFilter, number> = {
      all: actions.length,
      terminated: 0,
      isolated: 0,
      quarantined: 0,
      "pseudo-locked": 0,
      failed: 0,
    };
    for (const r of actions) {
      if (r.status === "failed") map.failed++;
      if (["terminate_process", "force_logout"].includes(r.action)) map.terminated++;
      if (["isolate_asset", "block_access", "lock_zone", "throttle_segment"].includes(r.action)) map.isolated++;
      if (["quarantine_device", "quarantine_file"].includes(r.action)) map.quarantined++;
      if (["pseudo_lock", "revoke_identity", "restrict_identity"].includes(r.action)) map["pseudo-locked"]++;
    }
    return map;
  }, [actions]);

  // Send Event goes Dashboard -> backend -> agent command channel, so it
  // works for any connected agent (not only one on this PC / port 8001).
  const sendEvent = async () => {
    if (!dispatchEndpoint) {
      setSendResult("❌ No agent connected — start the agent and wait for it to appear in the list");
      return;
    }
    setSending(true);
    setSendResult("");
    const endpoint = dispatchEndpoint;
    try {
      const payload: Record<string, unknown> = {};
      if (form.src_ip.trim()) payload.src_ip = form.src_ip.trim();
      if (form.dst_port.trim()) payload.dst_port = parseInt(form.dst_port, 10) || form.dst_port.trim();
      if (form.user_id.trim()) payload.user_id = form.user_id.trim();
      if (form.signature) payload.signature = form.signature;
      const res = await api.post("/agent/test-event", {
        endpoint_id: endpoint,
        event: {
          source: form.source,
          event_type: form.event_type,
          message: form.message,
          severity: form.severity,
          payload,
        },
      });
      const cmdId = res.data?.cmd_id || "";
      setSendResult(`⏳ Sent to ${endpoint} — waiting for the agent…`);
      const outcome = await waitForCommand(cmdId, 15000);
      if (outcome.status === "executed") {
        const id = String(outcome.result?.event_id || "?");
        setSendResult(`✅ ${endpoint} accepted the event — ID: ${id}. Findings appear in a few seconds (only high/critical results are shown).`);
        onSendTestEvent(outcome.result);
      } else if (outcome.status === "failed") {
        setSendResult(`❌ ${endpoint} rejected the event: ${outcome.error || "unknown error"}`);
      } else {
        setSendResult(`⚠️ No answer from ${endpoint} within 15s — check the agent window`);
      }
    } catch (e: unknown) {
      setSendResult(`❌ ${apiErrorMessage(e, "Failed to send event")}`);
    } finally {
      setSending(false);
    }
  };

  const handleRetry = async (record: ActionRecord) => {
    if (!onRetryAction) return;
    setRetryingId(record.id);
    try {
      await onRetryAction(record);
    } finally {
      setRetryingId(null);
    }
  };

  // ---- Remote dispatch handler ----
  // 1) POST /agent/commands  -> backend pushes the command to the agent
  // 2) Poll GET /agent/commands for the agent's ack
  //    (sent -> received -> executed | failed) and show the real outcome.
  const pollCommandStatus = async (cmdId: string, endpoint: string, label: string) => {
    const deadline = Date.now() + 20000;
    let lastStatus = "sent";
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 1000));
      try {
        const res = await api.get("/agent/commands");
        const list: { cmd_id: string; status: string; error?: string | null }[] =
          Array.isArray(res.data?.commands) ? res.data.commands : [];
        const cmd = list.find((c) => c.cmd_id === cmdId);
        if (!cmd) continue;
        if (cmd.status === "executed") {
          setDispatchResult(`✅ Done on ${endpoint}: ${label}`);
          setDispatchStatus("ok");
          onRefreshActions?.();
          return;
        }
        if (cmd.status === "failed") {
          setDispatchResult(`❌ Failed on ${endpoint}: ${cmd.error || "unknown error"}`);
          setDispatchStatus("err");
          onRefreshActions?.();
          return;
        }
        if (cmd.status !== lastStatus) {
          lastStatus = cmd.status;
          setDispatchResult(`⏳ ${endpoint} received the command — executing ${label}…`);
          setDispatchStatus("");
        }
      } catch {
        /* keep polling */
      }
    }
    setDispatchResult(
      `⚠️ No result from ${endpoint} within 20s — check the agent window for errors`
    );
    setDispatchStatus("err");
  };

  const dispatchRemote = async () => {
    if (!dispatchEndpoint) {
      setDispatchResult("❌ No agent selected");
      setDispatchStatus("err");
      return;
    }
    if (!dispatchAction) {
      setDispatchResult("❌ No action selected");
      setDispatchStatus("err");
      return;
    }
    const target = dispatchTarget.trim();
    if (!target) {
      setDispatchResult(`❌ Enter a target: ${dispatchPlaceholder}`);
      setDispatchStatus("err");
      return;
    }

    setDispatching(true);
    setDispatchResult("");
    setDispatchStatus("");

    const params: Record<string, unknown> = {};
    if (dispatchAction === "terminate_process" && /^\d+$/.test(target)) {
      params.pid = parseInt(target, 10);
    }

    const endpoint = dispatchEndpoint;
    const label = `${dispatchAction} → ${target}`;
    let cmdId = "";
    try {
      const res = await api.post("/agent/commands", {
        endpoint_id: endpoint,
        action: dispatchAction,
        target,
        params,
      });

      cmdId = res.data?.cmd_id || "";
      setDispatchResult(`⏳ Sent to ${endpoint} (cmd ${cmdId || "?"}) — waiting for agent…`);
      setDispatchStatus("");
      setDispatchTarget("");
    } catch (e: unknown) {
      const err = e as {
        response?: { data?: { error?: string; message?: string } };
        message?: string;
      };
      setDispatchResult(
        `❌ ${err.response?.data?.error || err.response?.data?.message || err.message || "Dispatch failed"}`
      );
      setDispatchStatus("err");
    } finally {
      setDispatching(false);
    }

    if (cmdId) await pollCommandStatus(cmdId, endpoint, label);
  };

  const tabs = [
    { k: "findings" as const, label: `Findings (${findings.length})` },
    { k: "correlated" as const, label: `Correlated (${correlated.length})` },
    { k: "gates" as const, label: `TriGate (${gateDecisions.length})` },
    {
      k: "locks" as const,
      label: `Locks (${pseudoLocks.filter((l) => l.active).length} active)`,
    },
    { k: "actions" as const, label: `Isolation & Termination (${actions.length})` },
    { k: "send" as const, label: "Send Event" },
  ];

  // The endpoint currently chosen in the dispatch form decides the wording and
  // the list of actions (a Linux server has no "lock screen").
  const selectedAgent = onlineAgents.find((a) => a.endpointId === dispatchEndpoint);
  const selectedIsLinux = isLinuxEndpoint(selectedAgent?.platform);
  const availableActions = actionsFor(selectedAgent?.platform);
  const dispatchActionDef = availableActions.find((a) => a.value === dispatchAction);
  const dispatchPlaceholder =
    (selectedIsLinux ? dispatchActionDef?.linuxPlaceholder : undefined) ||
    dispatchActionDef?.placeholder ||
    "target";

  // if the endpoint changes to one that cannot run the chosen action, pick the first
  useEffect(() => {
    if (!dispatchActionDef) setDispatchAction(availableActions[0]?.value || "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dispatchEndpoint, selectedAgent?.platform]);

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
                  <p className="text-slate-500 text-sm">No agent findings yet</p>
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
                      <p className="text-xs text-slate-300 mb-2">{f.summary}</p>
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
                  <p className="text-slate-500 text-sm">No attack chains yet</p>
                  <p className="mt-1 text-[11px] text-slate-600">
                    An incident appears when TriGate events for the same user, IP or PC show 2+ attack stages within 60 minutes
                    (e.g. password guessing, then a new admin account), or 3 BLOCKs of the same kind.
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
                          {a.incident?.kind === "repeated" ? "REPEATED ATTACK" : a.incident ? "ATTACK CHAIN" : "CORRELATED ALERT"}
                        </span>
                        {a.source && <span className="text-[10px] text-slate-400">🖥️ {a.source}</span>}
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
                  {a.incident && (
                    <div className="mb-3 space-y-1.5 text-[11px]">
                      <div className="flex flex-wrap items-center gap-1">
                        {a.incident.stages.map((st, i) => (
                          <span key={st.key} className="flex items-center gap-1">
                            {i > 0 && <span className="text-slate-600">→</span>}
                            <span className="rounded border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-red-200">{st.label}</span>
                          </span>
                        ))}
                      </div>
                      <div className="flex flex-wrap gap-3 text-slate-400">
                        {a.incident.users.length > 0 && <span>👤 {a.incident.users.join(", ")}</span>}
                        {a.incident.ips.length > 0 && <span>🌐 {a.incident.ips.join(", ")}</span>}
                        <span>📊 max risk {a.incident.max_risk}</span>
                        <span>🧩 {a.incident.count} events{a.incident.span_minutes !== undefined ? ` in ${a.incident.span_minutes} min` : ""}</span>
                      </div>
                    </div>
                  )}
                  <div className="space-y-1.5">
                    {a.findings.map((f, i) => (
                      <div
                        key={f.id || i}
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
                  <p className="text-slate-500 text-sm">No gate decisions yet</p>
                </div>
              )}
              {gateDecisions.length > 0 && (
                <p className="text-[11px] text-slate-500">
                  Every Windows event goes through all three gates: Trust (who?), Intent (attack?),
                  Impact (how bad?). Click 👍 False alarm to teach the agent - it remembers across restarts.
                </p>
              )}
              {gateDecisions.map((d, i) =>
                d.metadata?.trigate?.risk ? (
                  <TriGateCard key={`${d.event_id}-${i}`} decision={d} />
                ) : (
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
                )
              )}
            </div>
          )}

          {tab === "locks" && (
            <div className="space-y-3">
              {pseudoLocks.length === 0 && (
                <div className="py-8 text-center">
                  <p className="text-slate-500 text-sm">No pseudo-locks recorded</p>
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
                      <p className="text-xs text-slate-300 mb-1">{lock.summary}</p>
                      <div className="text-[10px] text-slate-500 space-y-0.5">
                        <div>Agent: {lock.agent}{lock.source ? ` · Endpoint: ${lock.source}` : ""}</div>
                        {lock.decoy_port ? (
                          <div className="text-amber-300/80">
                            Decoy port: {lock.decoy_port}{lock.active ? " (open)" : " (closed)"}
                            {typeof lock.hits === "number" && lock.hits > 0 ? ` · ${lock.hits} hit(s)` : ""}
                          </div>
                        ) : null}
                        <div>
                          Locked: {new Date(lock.locked_at).toLocaleString()}
                        </div>
                        {lock.restored_at && (
                          <div>
                            Restored: {new Date(lock.restored_at).toLocaleString()}
                          </div>
                        )}
                        {lock.restore_message && (
                          <div className="text-slate-400">{lock.restore_message}</div>
                        )}
                      </div>
                    </div>
                    {lock.active && (
                      <button
                        onClick={() => onRestoreLock(lock.lock_id)}
                        disabled={!!lock.restoring}
                        title="Ask the agent to close the decoy port"
                        className="flex-shrink-0 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-500/20 transition font-medium disabled:opacity-50"
                      >
                        {lock.restoring ? "Closing…" : "Restore"}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ============================================================
              Isolation & Termination tab
             ============================================================ */}
          {tab === "actions" && (
            <div className="space-y-3">
              {/* ---- Remote dispatch panel ----------------------------- */}
              <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-[10px] uppercase tracking-[0.15em] text-cyan-300 font-semibold">
                    Dispatch Remote Action
                  </div>
                  <div className="text-[10px] text-slate-500">
                    {onlineAgents.length === 0
                      ? "No agents online"
                      : `${onlineAgents.length} agent${
                          onlineAgents.length > 1 ? "s" : ""
                        } online`}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <select
                    value={dispatchEndpoint}
                    onChange={(e) => setDispatchEndpoint(e.target.value)}
                    className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100 focus:border-cyan-500/50 focus:outline-none"
                  >
                    {onlineAgents.length === 0 && (
                      <option value="">No agents online</option>
                    )}
                    {onlineAgents.map((a) => (
                      <option key={a.endpointId} value={a.endpointId}>
                        {a.endpointId}
                        {a.hostname && a.hostname !== a.endpointId
                          ? ` (${a.hostname})`
                          : ""}
                        {isLinuxEndpoint(a.platform) ? " - Linux" : " - Windows"}
                      </option>
                    ))}
                  </select>

                  <select
                    value={dispatchAction}
                    onChange={(e) => setDispatchAction(e.target.value)}
                    className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100 focus:border-cyan-500/50 focus:outline-none"
                  >
                    {availableActions.map((a) => (
                      <option key={a.value} value={a.value}>
                        {selectedIsLinux && a.linuxLabel ? a.linuxLabel : a.label}
                      </option>
                    ))}
                  </select>

                  <input
                    value={dispatchTarget}
                    onChange={(e) => setDispatchTarget(e.target.value)}
                    placeholder={dispatchPlaceholder}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") dispatchRemote();
                    }}
                    className="flex-1 min-w-[180px] rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                  />

                  <button
                    onClick={dispatchRemote}
                    disabled={dispatching || !dispatchEndpoint || !dispatchAction}
                    className="rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 px-3 py-1.5 text-xs font-bold text-slate-950 hover:from-cyan-400 hover:to-emerald-400 transition disabled:opacity-50"
                  >
                    {dispatching ? "Dispatching…" : "Dispatch"}
                  </button>
                </div>

                {dispatchResult && (
                  <div
                    className={cn(
                      "mt-2 rounded-lg border px-3 py-1.5 text-[11px]",
                      dispatchStatus === "ok"
                        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                        : dispatchStatus === "err"
                        ? "border-red-500/40 bg-red-500/10 text-red-300"
                        : "border-slate-700 bg-slate-900/60 text-slate-300"
                    )}
                  >
                    {dispatchResult}
                  </div>
                )}

                {onlineAgents.length === 0 && (
                  <div className="mt-2 text-[10px] text-slate-500">
                    Remote dispatch requires an agent connected to the
                    command channel (WebSocket /agent-channel).
                  </div>
                )}
              </div>

              {/* ---- Filter chips + search ----------------------------- */}
              <div className="flex flex-wrap items-center gap-2">
                {ACTION_FILTERS.map((f) => (
                  <button
                    key={f.key}
                    onClick={() => setActionFilter(f.key)}
                    className={cn(
                      "rounded-full border px-3 py-1 text-[10px] font-medium transition",
                      actionFilter === f.key
                        ? "border-cyan-500/60 bg-cyan-500/10 text-cyan-200"
                        : "border-slate-700 bg-slate-900 text-slate-400 hover:text-slate-200"
                    )}
                  >
                    {f.label}
                    <span className="ml-1.5 text-[9px] text-slate-500">
                      {actionCounts[f.key]}
                    </span>
                  </button>
                ))}

                <div className="flex-1 min-w-[180px]" />

                <input
                  type="search"
                  placeholder="Search target, endpoint, details…"
                  value={actionSearch}
                  onChange={(e) => setActionSearch(e.target.value)}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                />

                {onRefreshActions && (
                  <button
                    onClick={() => onRefreshActions()}
                    disabled={actionsLoading}
                    className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-300 hover:text-slate-100 hover:border-slate-600 transition"
                  >
                    {actionsLoading ? "Refreshing..." : "Refresh"}
                  </button>
                )}
              </div>

              {/* ---- Table -------------------------------------------- */}
              <div className="rounded-xl border border-slate-800/80 overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="bg-slate-900/60 border-b border-slate-800">
                      <tr className="text-[10px] uppercase tracking-wider text-slate-500">
                        <th className="px-3 py-2 font-semibold w-[110px]">
                          Timestamp
                        </th>
                        <th className="px-3 py-2 font-semibold w-[120px]">
                          Endpoint
                        </th>
                        <th className="px-3 py-2 font-semibold w-[170px]">
                          Action
                        </th>
                        <th className="px-3 py-2 font-semibold">Target</th>
                        <th className="px-3 py-2 font-semibold w-[120px]">
                          Status
                        </th>
                        <th className="px-3 py-2 font-semibold">Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredActions.length === 0 && (
                        <tr>
                          <td
                            colSpan={6}
                            className="px-3 py-10 text-center text-xs text-slate-500"
                          >
                            No response actions recorded yet.
                          </td>
                        </tr>
                      )}
                      {filteredActions.map((r) => (
                        <tr
                          key={r.id}
                          onClick={() => setSelectedAction(r)}
                          className={cn(
                            "border-b border-slate-800/60 text-xs cursor-pointer transition",
                            selectedAction?.id === r.id
                              ? "bg-cyan-500/5"
                              : "hover:bg-slate-900/60"
                          )}
                        >
                          <td className="px-3 py-2 font-mono text-[11px] text-slate-400">
                            {fmtTime(r.timestamp)}
                          </td>
                          <td className="px-3 py-2">
                            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-300">
                              {r.endpoint}
                            </span>
                          </td>
                          <td className="px-3 py-2">
                            <span className="font-mono text-[11px] text-cyan-300">
                              {r.action}
                            </span>
                            {r.dry_run && (
                              <span className="ml-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[8px] text-amber-300">
                                dry-run
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-2 text-slate-200">
                            <div className="truncate max-w-[260px]" title={r.target}>
                              {r.target || "—"}
                              {r.target_type && r.target_type !== "unknown" && (
                                <span className="ml-1 text-[10px] text-slate-500">
                                  · {r.target_type}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-3 py-2">
                            <StatusBadge status={r.status} />
                          </td>
                          <td className="px-3 py-2 text-slate-400">
                            <div className="truncate max-w-[280px]" title={r.error || r.details}>
                              {r.error ? (
                                <span className="text-red-400">{r.error}</span>
                              ) : (
                                r.details || "—"
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* ---- Detail side panel -------------------------------- */}
              {selectedAction && (
                <div className="rounded-xl border border-cyan-500/30 bg-slate-900/60 p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-bold text-slate-100">
                        {selectedAction.action_label || selectedAction.action}
                      </h3>
                      <StatusBadge status={selectedAction.status} />
                      {selectedAction.containment && (
                        <span className="rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[9px] text-red-300">
                          containment
                        </span>
                      )}
                    </div>
                    <button
                      onClick={() => setSelectedAction(null)}
                      className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-400 hover:text-slate-100 transition"
                    >
                      Close
                    </button>
                  </div>

                  <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-[11px]">
                    <div>
                      <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                        Timestamp
                      </dt>
                      <dd className="font-mono text-slate-300">
                        {fmtFull(selectedAction.timestamp)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                        Endpoint
                      </dt>
                      <dd className="text-slate-300">{selectedAction.endpoint}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                        Target
                      </dt>
                      <dd className="font-mono text-slate-300">
                        {selectedAction.target || "—"}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                        Target type
                      </dt>
                      <dd className="text-slate-300">{selectedAction.target_type}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                        Triggered by
                      </dt>
                      <dd className="font-mono text-slate-300">
                        {selectedAction.triggered_by || "—"}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                        Agent
                      </dt>
                      <dd className="text-slate-300">{selectedAction.agent || "—"}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                        Severity
                      </dt>
                      <dd>
                        <span
                          className={cn(
                            "rounded-full px-2 py-0.5 text-[9px] ring-1",
                            sevCls(selectedAction.severity)
                          )}
                        >
                          {String(selectedAction.severity).toUpperCase()}
                        </span>
                      </dd>
                    </div>
                    {selectedAction.retried_from && (
                      <div>
                        <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                          Retry of
                        </dt>
                        <dd className="font-mono text-slate-300">
                          {selectedAction.retried_from}
                        </dd>
                      </div>
                    )}
                    <div className="sm:col-span-2">
                      <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                        Reason
                      </dt>
                      <dd className="text-slate-300">
                        {selectedAction.reason || "—"}
                      </dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                        Details
                      </dt>
                      <dd className="text-slate-300">
                        {selectedAction.details || "—"}
                      </dd>
                    </div>
                    {selectedAction.error && (
                      <div className="sm:col-span-2">
                        <dt className="text-slate-500 uppercase tracking-wider text-[9px] mb-0.5">
                          Error
                        </dt>
                        <dd className="text-red-400">{selectedAction.error}</dd>
                      </div>
                    )}
                  </dl>

                  {selectedAction.metadata &&
                    Object.keys(selectedAction.metadata).length > 0 && (
                      <details className="mt-3">
                        <summary className="text-[10px] uppercase tracking-wider text-slate-500 cursor-pointer">
                          Metadata
                        </summary>
                        <pre className="mt-2 rounded-lg border border-slate-800 bg-slate-950 p-2 text-[10px] text-slate-400 overflow-x-auto">
                          {JSON.stringify(selectedAction.metadata, null, 2)}
                        </pre>
                      </details>
                    )}

                  {onRetryAction && (
                    <div className="mt-4">
                      <button
                        onClick={() => handleRetry(selectedAction)}
                        disabled={retryingId === selectedAction.id}
                        className="rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 px-4 py-1.5 text-xs font-bold text-slate-950 hover:from-cyan-400 hover:to-emerald-400 transition disabled:opacity-50"
                      >
                        {retryingId === selectedAction.id
                          ? "Retrying…"
                          : "Retry action"}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {tab === "send" && (
            <div className="max-w-lg space-y-4">
              <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 text-[11px] text-cyan-300/80">
                Send a test threat event to a connected agent. The agent runs
                it through its detection pipeline and any high/critical
                findings appear in the Findings tab in real time.
              </div>
              <div>
                <label className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400 mb-1.5">
                  Agent
                </label>
                <select
                  value={dispatchEndpoint}
                  onChange={(e) => setDispatchEndpoint(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:outline-none"
                >
                  {onlineAgents.length === 0 && <option value="">No agents connected</option>}
                  {onlineAgents.map((a) => (
                    <option key={a.endpointId} value={a.endpointId}>
                      {a.endpointId}{a.hostname && a.hostname !== a.endpointId ? ` (${a.hostname})` : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { l: "Source", k: "source" },
                  { l: "Source IP", k: "src_ip" },
                  { l: "Destination Port", k: "dst_port" },
                  { l: "User (optional)", k: "user_id" },
                  { l: "Message", k: "message" },
                ].map((f) => (
                  <div
                    key={f.k}
                    className={f.k === "message" ? "col-span-2" : ""}
                  >
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
              <div>
                <label className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400 mb-1.5">
                  Attack Signature (optional)
                </label>
                <select
                  value={form.signature}
                  onChange={(e) => setForm((p) => ({ ...p, signature: e.target.value }))}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:outline-none"
                >
                  <option value="">None - generic event</option>
                  <option value="RANSOMWARE_C2">RANSOMWARE_C2 - known malicious (opens a real decoy lock)</option>
                  <option value="RCE_EXPLOIT">RCE_EXPLOIT - known malicious (opens a real decoy lock)</option>
                  <option value="SQL_INJECTION">SQL_INJECTION - known malicious (opens a real decoy lock)</option>
                  <option value="SSH_BRUTE_FORCE">SSH_BRUTE_FORCE - brute force (opens a real decoy lock)</option>
                  <option value="PORT_SCAN">PORT_SCAN - suspicious only (no lock)</option>
                </select>
              </div>
              <button
                onClick={sendEvent}
                disabled={sending || !dispatchEndpoint}
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
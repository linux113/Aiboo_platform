import { useEffect, useState } from "react";
import { cn } from "../utils/cn";
import { sevCls, detIcon, threatIcon } from "../utils/helpers";
import api, { authH, API, waitForCommand, apiErrorMessage } from "../utils/api";
import { logger } from "../utils/logger";
import KPI from "./KPI";
import type { Threat, Detection, Camera, AgentFinding, CorrelatedAlert, GateDecision } from "../types";

// ---- Endpoint type ----
export interface EndpointInfo {
  source: string;
  lastSeen: string;
  active: boolean;
}

// One-click playbooks. "dispatch" ones run a real action on a connected
// agent (same pipeline as Agent Console -> Isolation & Termination).
// Buttons with no system behind them are shown as "not connected" instead
// of pretending to work.
type Playbook = {
  id: string;
  label: string;
  critical?: boolean;
  kind: "dispatch" | "war_room" | "badge" | "unavailable";
  action?: string;
  // extra number fields sent as params (e.g. minutes, kbps)
  extras?: { key: string; label: string; def: number; min: number; max: number }[];
  targetLabel?: string;
  placeholder?: string;
  optionalTarget?: boolean;
  explain: string;
};

const PLAYBOOKS: Playbook[] = [
  {
    id: "isolate", label: "Isolate Host", critical: true, kind: "dispatch", action: "isolate_asset",
    targetLabel: "IP address to cut off", placeholder: "e.g. 203.0.113.50",
    explain: "Adds a Windows Firewall rule on the selected PC that blocks incoming traffic from this IP. (Remove the rule in Windows Firewall to undo.)",
  },
  {
    id: "lock", label: "Lock Perimeter", kind: "dispatch", action: "pseudo_lock",
    targetLabel: "Label (optional)", placeholder: "e.g. suspicious-host", optionalTarget: true,
    explain: "Opens a decoy (honeypot) port on the selected PC and logs anyone who connects. Undo with Agent Console -> Locks -> Restore.",
  },
  {
    id: "quarantine", label: "Quarantine Identity", kind: "dispatch", action: "revoke_identity",
    targetLabel: "Windows user name", placeholder: "e.g. guest",
    explain: "Disables this local Windows account on the selected PC (net user <name> /active:no). The account the agent runs as is refused.",
  },
  {
    id: "restrict", label: "Restrict Account", kind: "dispatch", action: "restrict_identity",
    targetLabel: "Windows user name", placeholder: "e.g. guest",
    extras: [{ key: "minutes", label: "Minutes", def: 30, min: 1, max: 1440 }],
    explain: "Temporarily disables this Windows account and logs off its sessions. The agent turns it back on automatically when the time is up (or use Agent Console -> Lift restriction).",
  },
  {
    id: "throttle", label: "Throttle Segment", kind: "dispatch", action: "throttle_segment",
    targetLabel: "IP address or range", placeholder: "e.g. 45.95.147.3 or 192.168.1.0/24",
    extras: [
      { key: "kbps", label: "Speed limit (kbit/s)", def: 256, min: 64, max: 100000 },
      { key: "minutes", label: "Minutes", def: 30, min: 1, max: 1440 },
    ],
    explain: "Limits the speed of traffic the selected PC sends to this IP / range (uploads, downloads it asks for, malware call-backs) with a Windows QoS policy - no extra hardware needed. Removed automatically when the time is up.",
  },
  {
    id: "badge", label: "Freeze Badge", kind: "badge",
    targetLabel: "Badge number / employee ID", placeholder: "e.g. EMP-1042",
    explain: "Asks your door / badge access system to block this badge. Works when BADGE_WEBHOOK_URL is set in backend/.env (your badge system, or an automation tool such as Power Automate / n8n in front of it).",
  },
  {
    id: "warroom", label: "Open War Room", kind: "war_room",
    targetLabel: "Note (optional)", placeholder: "e.g. ransomware on finance PC", optionalTarget: true,
    explain: "Sends a critical alert to every analyst who has the dashboard open right now.",
  },
];

interface OnlineAgent {
  endpointId: string;
  hostname: string;
}

const THREAT_ACTIONS = [
  { label: "Isolate", endpoint: "/respond/isolate", color: "border-cyan-400/80 hover:text-cyan-100" },
  { label: "Auto-respond", endpoint: "/respond/auto", color: "border-emerald-400/80 hover:text-emerald-100" },
  { label: "Escalate", endpoint: "/respond/escalate", color: "border-amber-400/80 hover:text-amber-100" },
];

export default function DashboardModule({
  threats,
  detections,
  cameras,
  findings,
  correlated,
  gateDecisions = [],
  activeLocks,
  sources,
  onNotify,
}: {
  threats: Threat[];
  detections: Detection[];
  cameras: Camera[];
  findings: AgentFinding[];
  correlated: CorrelatedAlert[];
  gateDecisions?: GateDecision[];
  activeLocks: number;
  sources: EndpointInfo[];
  onNotify?: (type: "critical" | "warning" | "info", title: string, body: string) => void;
}) {
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  // ---- Playbook panel state ----
  const [openPlaybook, setOpenPlaybook] = useState<Playbook | null>(null);
  const [pbAgents, setPbAgents] = useState<OnlineAgent[]>([]);
  const [pbEndpoint, setPbEndpoint] = useState("");
  const [pbTarget, setPbTarget] = useState("");
  const [pbRunning, setPbRunning] = useState(false);
  const [pbResult, setPbResult] = useState<{ ok: boolean | null; text: string } | null>(null);
  const [pbExtras, setPbExtras] = useState<Record<string, number>>({});
  const [badgeReady, setBadgeReady] = useState<boolean | null>(null);

  useEffect(() => {
    api.get("/agent/playbooks/status")
      .then((r) => setBadgeReady(!!r.data?.badge?.configured))
      .catch(() => setBadgeReady(null));
  }, []);

  // Load connected agents while a dispatch playbook is open
  useEffect(() => {
    if (!openPlaybook || openPlaybook.kind !== "dispatch") return;
    let cancelled = false;
    const load = async () => {
      try {
        const res = await api.get("/agent/agents-online");
        if (cancelled) return;
        const list: OnlineAgent[] = Array.isArray(res.data?.agents) ? res.data.agents : [];
        setPbAgents(list);
        setPbEndpoint((prev) => (prev && list.some((a) => a.endpointId === prev) ? prev : list[0]?.endpointId || ""));
      } catch {
        if (!cancelled) setPbAgents([]);
      }
    };
    load();
    const iv = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(iv);
    };
  }, [openPlaybook]);

  // "Open Threats" = open threat reports (database) + serious agent findings
  // from the last 24h. The old card showed only the first (usually 0) with the
  // all-time critical-finding count underneath, so the numbers never matched.
  const openReports = (Array.isArray(threats) ? threats : []).filter((t) => t?.status === "open").length;
  const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const recentFindings = (Array.isArray(findings) ? findings : []).filter((f) => {
    const ts = Date.parse(f.timestamp || "");
    return Number.isNaN(ts) || ts >= dayAgo;
  });
  const crit = recentFindings.filter((f) => f.severity === "critical").length;
  const high = recentFindings.filter((f) => f.severity === "high").length;
  const open = openReports + crit + high;
  const openSub = `${crit} critical · ${high} high (24h)` + (openReports ? ` · ${openReports} reports` : "");
  const online = (Array.isArray(cameras) ? cameras : []).filter((c) => c.status === "online").length;
  const weapons = (Array.isArray(detections) ? detections : []).filter((d) => d.type?.includes("weapon")).length;

  const handleThreatAction = async (action: string, threat: Threat) => {
    const key = `${action}-${threat._id}`;
    setActionLoading(key);
    try {
      const meta = (threat.metadata || {}) as Record<string, unknown>;
      const ip = meta.ip || meta.src_ip || meta.source_ip;
      await api.post(`${API}${action}`, { threatId: threat._id, title: threat.title, ...(ip ? { ip } : {}) }, authH());
      onNotify?.("info", "Response recorded", `${action.split("/").pop()} -> ${threat.title}`);
    } catch (e) {
      logger.error(`Failed to ${action} on ${threat.title}`);
      onNotify?.("warning", "Action failed", apiErrorMessage(e, `Could not run ${action}`));
    } finally {
      setActionLoading(null);
    }
  };

  const openPlaybookPanel = (pb: Playbook) => {
    setOpenPlaybook((cur) => (cur?.id === pb.id ? null : pb));
    setPbTarget("");
    setPbResult(null);
    setPbExtras(Object.fromEntries((pb.extras || []).map((x) => [x.key, x.def])));
  };

  const runPlaybook = async () => {
    const pb = openPlaybook;
    if (!pb || pb.kind === "unavailable") return;
    const target = pbTarget.trim();
    if (!pb.optionalTarget && !target) {
      setPbResult({ ok: false, text: `Enter the ${pb.targetLabel?.toLowerCase() || "target"}` });
      return;
    }
    setPbRunning(true);
    setPbResult(null);
    try {
      if (pb.kind === "war_room") {
        await api.post("/agent/war-room", { note: target });
        setPbResult({ ok: true, text: "War room opened - every open dashboard was alerted." });
        return;
      }
      if (pb.kind === "badge") {
        const r = await api.post("/agent/playbooks/freeze-badge", { badge_id: target, reason: "Freeze Badge playbook (dashboard)" });
        setPbResult({ ok: true, text: r.data?.message || "Badge system accepted the request." });
        onNotify?.("info", "Freeze Badge sent", target);
        return;
      }
      if (!pbEndpoint) {
        setPbResult({ ok: false, text: "No agent connected - start the agent first." });
        return;
      }
      const endpoint = pbEndpoint;
      const res = await api.post("/agent/commands", {
        endpoint_id: endpoint,
        action: pb.action,
        target,
        params: { ...pbExtras },
      });
      setPbResult({ ok: null, text: `Sent to ${endpoint} - waiting for the agent...` });
      const outcome = await waitForCommand(res.data?.cmd_id || "");
      if (outcome.status === "executed") {
        setPbResult({ ok: true, text: `Done on ${endpoint}: ${pb.label}${target ? ` -> ${target}` : ""}. Details in Agent Console -> Isolation & Termination.` });
        onNotify?.("info", `${pb.label} done`, `${endpoint}${target ? ` -> ${target}` : ""}`);
      } else if (outcome.status === "failed") {
        setPbResult({ ok: false, text: `Failed on ${endpoint}: ${outcome.error || "unknown error"}` });
      } else {
        setPbResult({ ok: false, text: `No answer from ${endpoint} within 20s - check the agent window.` });
      }
    } catch (e) {
      setPbResult({ ok: false, text: apiErrorMessage(e, `${pb.label} failed`) });
    } finally {
      setPbRunning(false);
    }
  };

  // TriGate decisions worth a look (PASS = normal activity, not shown)
  const feedGates = (Array.isArray(gateDecisions) ? gateDecisions : [])
    .filter((g) => g.verdict === "hold" || g.verdict === "block")
    .slice(0, 6);

  // Compute online/offline counts
  const activeCount = sources.filter((s) => s.active).length;
  const offlineCount = sources.length - activeCount;

  return (
    <div className="grid h-full grid-cols-1 gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1.5fr)]">
      <div className="flex flex-col gap-4">
        {/* KPI row */}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <KPI label="Open Threats" value={open} sub={openSub} red={crit > 0} />
          <KPI label="Cameras Online" value={`${online}/${cameras.length}`} sub="YOLOv8 active" cyan />
          <KPI label="Weapon Alerts" value={weapons} sub="Camera detections" red={weapons > 0} />
          <KPI label="Pseudo-Locks" value={activeLocks} sub="Active endpoint locks" amber={activeLocks > 0} />
        </div>

        {/* ---- Endpoints Registered (with green/red dots) ---- */}
        <div className="rounded-xl border border-slate-700/80 bg-slate-950/80 p-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <span className="text-lg">🖥️</span>
              <span className="text-sm font-medium text-slate-300">Endpoints Registered</span>
            </div>
            <div className="flex items-center gap-1.5">
              {activeCount > 0 && (
                <span className="rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] text-emerald-300">
                  {activeCount} online
                </span>
              )}
              {offlineCount > 0 && (
                <span className="rounded-full bg-red-500/20 px-2 py-0.5 text-[10px] text-red-300">
                  {offlineCount} offline
                </span>
              )}
              <span className="rounded-full bg-cyan-500/20 px-2 py-0.5 text-[10px] text-cyan-300">
                {sources.length}
              </span>
            </div>
          </div>
          <div className="mt-2 max-h-40 overflow-y-auto space-y-1">
            {sources.length === 0 ? (
              <p className="text-xs text-slate-500">No endpoints connected yet</p>
            ) : (
              sources.map((ep) => (
                <div key={ep.source} className="flex items-center justify-between text-xs">
                  <div className="flex flex-col">
                    <span className="text-slate-200">{ep.source}</span>
                    <span className="text-[10px] text-slate-500">
                      {ep.lastSeen
                        ? ep.active
                          ? `Online · ${new Date(ep.lastSeen).toLocaleTimeString()}`
                          : `Offline · last seen ${new Date(ep.lastSeen).toLocaleTimeString()}`
                        : "Never seen"}
                    </span>
                  </div>
                  <span
                    title={ep.active ? "Online" : "Offline"}
                    className={cn(
                      "h-2 w-2 rounded-full flex-shrink-0",
                      ep.active
                        ? "bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.6)]"
                        : "bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.6)]"
                    )}
                  />
                </div>
              ))
            )}
          </div>
          <div className="mt-2 text-xs text-slate-500">
            <button
              onClick={() => (window.location.hash = "endpoints")}
              className="hover:text-cyan-300 transition"
            >
              View all →
            </button>
          </div>
        </div>

        {/* Two panels: Live Threat Feed & Agent Findings */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 flex-1">
          <div className="flex flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
            <div className="mb-2 flex items-center justify-between">
              <div>
                <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
                  Live Threat Feed
                </div>
                <div className="text-[11px] text-slate-500">
                  Attack chains + TriGate HOLD / BLOCK
                </div>
              </div>
              <span className="flex items-center gap-1 text-[10px] text-slate-500">
                <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                Live
              </span>
            </div>
            <div className="flex-1 space-y-2 overflow-auto pr-1">
              {threats.length === 0 && findings.length === 0 && feedGates.length === 0 && correlated.length === 0 && (
                <p className="py-6 text-center text-[11px] text-slate-600">
                  No findings yet - start the agent (python main.py) or use Agent Console → Send Event
                </p>
              )}
              {correlated.slice(0, 2).map((a) => (
                <div
                  key={a.alert_id}
                  className="rounded-lg border border-red-500/50 bg-red-500/5 px-2.5 py-2 text-xs"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-red-400 font-bold text-[10px]">
                      🔗 CORRELATED
                    </span>
                    <span
                      className={cn(
                        "rounded-full px-2 py-0.5 text-[9px] font-medium ring-1",
                        sevCls(a.severity)
                      )}
                    >
                      {a.severity}
                    </span>
                    <span className="text-[10px] text-slate-500 ml-auto">
                      {(a.confidence * 100) | 0}%
                    </span>
                  </div>
                  <div className="text-[12px] font-medium text-slate-100">
                    {a.description.replace("[CORRELATED] ", "")}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {new Date(a.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              ))}
              {feedGates.map((g) => {
                const tri = g.metadata?.trigate;
                const ctx = (tri?.context || {}) as Record<string, any>;
                const block = g.verdict === "block";
                return (
                  <div key={g.event_id}
                    className={cn("rounded-lg border px-2.5 py-2 text-xs", block ? "border-red-500/40 bg-red-500/5" : "border-amber-500/40 bg-amber-500/5")}>
                    <div className="mb-1 flex items-center gap-2">
                      <span className={cn("text-[10px] font-bold", block ? "text-red-400" : "text-amber-300")}>
                        {block ? "⛔ BLOCK" : "✋ HOLD"}
                      </span>
                      <span className={cn("rounded-full px-2 py-0.5 text-[9px] font-medium ring-1", sevCls(tri?.risk?.level || g.severity))}>
                        risk {tri?.risk?.score ?? "?"}
                      </span>
                      <span className="ml-auto text-[10px] text-slate-500">{new Date(g.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div className="text-[12px] font-medium text-slate-100">
                      {ctx.pattern_label || g.threat_type}{ctx.entity ? ` - ${ctx.entity}` : ""}
                    </div>
                    <div className="mt-0.5 truncate text-[10px] text-slate-400">
                      {[g.source, ctx.src_ip, ctx.description].filter(Boolean).join(" · ")}
                    </div>
                  </div>
                );
              })}
              {threats.slice(0, 4).map((t) => (
                <div
                  key={t._id}
                  className="rounded-lg border border-slate-800/90 bg-slate-950/90 px-2.5 py-2 text-xs"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className={cn(
                        "rounded-full px-2 py-0.5 text-[9px] font-medium ring-1 ring-inset",
                        sevCls(t.severity)
                      )}
                    >
                      {t.severity}
                    </span>
                    <span className="text-[11px] text-slate-500">
                      {t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : "N/A"}
                    </span>
                    <span
                      className={cn(
                        "ml-auto text-[10px] font-medium",
                        (t as any).status === "open"
                          ? "text-red-400"
                          : (t as any).status === "investigating"
                            ? "text-amber-400"
                            : "text-emerald-400"
                      )}
                    >
                      {(t as any).status || "unknown"}
                    </span>
                  </div>
                  <div className="text-[13px] font-medium text-slate-100">
                    {t.title}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    {t.asset} · {t.source}
                  </div>
                  <div className="flex gap-1.5 mt-1.5 text-[10px]">
                    {THREAT_ACTIONS.map(({ label, endpoint, color }) => (
                      <button
                        key={label}
                        onClick={() => handleThreatAction(endpoint, t)}
                        disabled={actionLoading === `${endpoint}-${t._id}`}
                        className={cn(
                          "rounded-full border border-slate-700/80 bg-slate-900/90 px-2 py-0.5 text-slate-300 active:scale-95 transition disabled:opacity-50",
                          color
                        )}
                      >
                        {actionLoading === `${endpoint}-${t._id}` ? "..." : label}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
            <div className="mb-2 flex items-center justify-between">
              <div>
                <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
                  Agent Findings & Detections
                </div>
                <div className="text-[11px] text-slate-500">
                  Tri-gate + YOLOv8
                </div>
              </div>
              <span className="rounded border border-cyan-500/50 bg-cyan-500/10 px-2 py-0.5 text-[10px] text-cyan-200">
                AI Active
              </span>
            </div>
            <div className="flex-1 space-y-1.5 overflow-auto pr-1">
              {findings.length === 0 && detections.length === 0 && (
                <p className="py-6 text-center text-[11px] text-slate-600">
                  No findings yet — agents monitoring
                </p>
              )}
              {findings.slice(0, 4).map((f) => (
                <div
                  key={f.id}
                  className={cn(
                    "flex items-start gap-2 rounded-lg border px-2.5 py-1.5",
                    f.severity === "critical"
                      ? "border-red-500/50 bg-red-500/5"
                      : f.severity === "high"
                        ? "border-amber-500/40 bg-amber-500/5"
                        : "border-slate-800 bg-slate-950/90"
                  )}
                >
                  <span className="text-sm mt-0.5 flex-shrink-0">
                    {threatIcon(f.threat_type)}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-medium text-slate-200 truncate">
                        {f.agent_name}
                      </span>
                      <span className="text-[10px] text-slate-500">
                        {(f.confidence * 100) | 0}%
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-400 truncate">
                      {f.summary.substring(0, 60)}
                    </div>
                  </div>
                  <span
                    className={cn(
                      "flex-shrink-0 rounded-full px-2 py-0.5 text-[9px] font-medium ring-1",
                      sevCls(f.severity)
                    )}
                  >
                    {f.severity}
                  </span>
                </div>
              ))}
              {detections.slice(0, 4).map((d) => (
                <div
                  key={d._id}
                  className={cn(
                    "flex items-start gap-2 rounded-lg border px-2.5 py-1.5",
                    d.type.includes("weapon")
                      ? "border-red-500/50 bg-red-500/5"
                      : "border-slate-800 bg-slate-900/40"
                  )}
                >
                  <span className="text-sm mt-0.5 flex-shrink-0">
                    {detIcon(d.type)}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-[11px] font-medium text-slate-200">
                      {d.label}
                    </div>
                    <div className="text-[10px] text-slate-500 truncate">
                      {d.cameraName} · {new Date(d.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                  <span
                    className={cn(
                      "flex-shrink-0 rounded-full px-2 py-0.5 text-[9px] font-medium ring-1",
                      sevCls(d.severity)
                    )}
                  >
                    {d.severity}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Right column: Orchestration, Pseudo-Lock, Timeline */}
      <div className="flex flex-col gap-4">
        <div className="flex flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
                Response Orchestration
              </div>
              <div className="text-[11px] text-slate-500">
                One-click playbooks
              </div>
            </div>
            <span className="rounded border border-cyan-500/40 bg-cyan-500/10 px-2 py-0.5 text-[10px] text-cyan-200">
              Runs on connected agents
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2 text-[11px] md:grid-cols-3">
            {PLAYBOOKS.map((pb) => (
              <button
                key={pb.id}
                onClick={() => openPlaybookPanel(pb)}
                title={pb.explain}
                className={cn(
                  "flex items-center justify-between rounded-lg border px-2.5 py-2 text-left font-medium transition active:scale-95",
                  pb.kind === "unavailable"
                    ? "border-slate-800 bg-slate-900/40 text-slate-500"
                    : pb.critical
                      ? "border-red-500/70 bg-red-500/10 text-red-100 shadow-[0_0_14px_rgba(248,113,113,0.4)] hover:bg-red-500/20"
                      : "border-slate-700/80 bg-slate-900/80 text-slate-200 hover:border-cyan-400/80 hover:bg-cyan-500/5 hover:text-cyan-100",
                  openPlaybook?.id === pb.id && "ring-1 ring-cyan-400/70"
                )}
              >
                <span>{pb.label}</span>
                {pb.kind === "unavailable" && (
                  <span className="text-[9px] text-slate-600">not connected</span>
                )}
                {pb.kind === "badge" && badgeReady === false && (
                  <span className="text-[9px] text-amber-500/80">needs setup</span>
                )}
              </button>
            ))}
          </div>

          {openPlaybook && (
            <div className="mt-3 space-y-2 rounded-lg border border-slate-700/80 bg-slate-900/60 p-3 text-[11px]">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-100">{openPlaybook.label}</span>
                <button
                  onClick={() => setOpenPlaybook(null)}
                  className="text-slate-500 hover:text-slate-300"
                  aria-label="Close"
                >
                  ✕
                </button>
              </div>
              <p className="text-slate-400">{openPlaybook.explain}</p>

              {openPlaybook.kind !== "unavailable" && (
                <>
                  {openPlaybook.kind === "dispatch" && (
                    <div>
                      <label className="mb-1 block text-[10px] uppercase tracking-[0.15em] text-slate-500">Agent</label>
                      <select
                        value={pbEndpoint}
                        onChange={(e) => setPbEndpoint(e.target.value)}
                        className="w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-100 focus:outline-none"
                      >
                        {pbAgents.length === 0 && <option value="">No agents connected</option>}
                        {pbAgents.map((a) => (
                          <option key={a.endpointId} value={a.endpointId}>
                            {a.endpointId}{a.hostname && a.hostname !== a.endpointId ? ` (${a.hostname})` : ""}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}
                  <div>
                    <label className="mb-1 block text-[10px] uppercase tracking-[0.15em] text-slate-500">
                      {openPlaybook.targetLabel}
                    </label>
                    <input
                      value={pbTarget}
                      onChange={(e) => setPbTarget(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") runPlaybook(); }}
                      placeholder={openPlaybook.placeholder}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                    />
                  </div>
                  {(openPlaybook.extras || []).length > 0 && (
                    <div className="grid grid-cols-2 gap-2">
                      {(openPlaybook.extras || []).map((x) => (
                        <div key={x.key}>
                          <label className="mb-1 block text-[10px] uppercase tracking-[0.15em] text-slate-500">{x.label}</label>
                          <input
                            type="number" min={x.min} max={x.max}
                            value={pbExtras[x.key] ?? x.def}
                            onChange={(e) => setPbExtras((p) => ({ ...p, [x.key]: Math.min(x.max, Math.max(x.min, Number(e.target.value) || x.def)) }))}
                            className="w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-100 focus:outline-none"
                          />
                        </div>
                      ))}
                    </div>
                  )}
                  {openPlaybook.kind === "badge" && badgeReady === false && (
                    <div className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-amber-200">
                      No badge system connected yet. Add <code>BADGE_WEBHOOK_URL=...</code> to backend/.env and restart the backend.
                    </div>
                  )}
                  <button
                    onClick={runPlaybook}
                    disabled={pbRunning || (openPlaybook.kind === "dispatch" && !pbEndpoint)}
                    className={cn(
                      "w-full rounded-lg py-1.5 font-bold transition disabled:opacity-50",
                      openPlaybook.critical
                        ? "bg-red-500/80 text-white hover:bg-red-500"
                        : "bg-cyan-500/80 text-slate-950 hover:bg-cyan-400"
                    )}
                  >
                    {pbRunning ? "Running..." : `Confirm: ${openPlaybook.label}`}
                  </button>
                </>
              )}

              {pbResult && (
                <div
                  className={cn(
                    "rounded border px-2 py-1.5",
                    pbResult.ok === true
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
                      : pbResult.ok === false
                        ? "border-red-500/40 bg-red-500/10 text-red-200"
                        : "border-slate-700 bg-slate-900 text-slate-300"
                  )}
                >
                  {pbResult.text}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="flex flex-col rounded-xl border border-amber-500/20 bg-slate-950/80 p-3">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-amber-400/80">
                Pseudo-Lock Status
              </div>
              <div className="text-[11px] text-slate-500">
                Active endpoint isolation
              </div>
            </div>
            <span
              className={cn(
                "rounded-full px-2 py-0.5 text-[10px] font-medium",
                activeLocks > 0
                  ? "bg-amber-500/15 text-amber-300"
                  : "bg-emerald-500/10 text-emerald-400"
              )}
            >
              {activeLocks > 0 ? `${activeLocks} Active` : "None Active"}
            </span>
          </div>
          {activeLocks === 0 ? (
            <p className="text-[11px] text-slate-600 py-2">
              No locks active — system nominal
            </p>
          ) : (
            <p className="text-[11px] text-amber-300/70">
              {activeLocks} endpoint(s) locked → decoy routing. See Agent Console
              to restore.
            </p>
          )}
        </div>

        <div className="flex flex-1 flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
                Shift Timeline
              </div>
              <div className="text-[11px] text-slate-500">
                All events chronological
              </div>
            </div>
            <span className="text-[10px] text-slate-500">Live</span>
          </div>
          <div className="flex-1 space-y-1.5 overflow-auto pr-1">
            {[...findings.slice(0, 3).map((f) => ({ time: f.timestamp, text: `${threatIcon(f.threat_type)} [${f.agent_name}] ${f.summary.substring(0, 50)}…`, type: "finding" as const })), ...detections.slice(0, 2).map((d) => ({ time: d.timestamp, text: `${detIcon(d.type)} ${d.label} — ${d.cameraName}`, type: "camera" as const })), ...correlated.slice(0, 2).map((a) => ({ time: a.timestamp, text: `🔗 ${a.description.replace("[CORRELATED] ", "").substring(0, 50)}`, type: "alert" as const }))]
              .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime())
              .slice(0, 8)
              .map((ev, i) => (
                <div key={i} className="flex gap-2">
                  <div className="mt-1 h-4 w-px bg-gradient-to-b from-cyan-400/80 to-slate-700/80 flex-shrink-0" />
                  <div
                    className={cn(
                      "flex-1 rounded-lg border px-2 py-1.5",
                      ev.type === "alert"
                        ? "border-red-500/30 bg-red-500/5"
                        : ev.type === "finding"
                          ? "border-amber-500/20 bg-amber-500/5"
                          : "border-slate-800/80 bg-slate-900/80"
                    )}
                  >
                    <div className="flex justify-between text-[10px] text-slate-500 mb-0.5">
                      <span>{new Date(ev.time).toLocaleTimeString()}</span>
                      <span className="capitalize text-cyan-300/70">
                        {ev.type}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-200">{ev.text}</div>
                  </div>
                </div>
              ))}
            {findings.length === 0 && detections.length === 0 && (
              <p className="py-4 text-center text-[11px] text-slate-600">
                No events yet
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
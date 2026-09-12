import { useState } from "react";
import { cn } from "../utils/cn";
import { sevCls, detIcon, threatIcon } from "../utils/helpers";
import api, { authH, API } from "../utils/api";
import { logger } from "../utils/logger";
import KPI from "./KPI";
import type { Threat, Detection, Camera, AgentFinding, CorrelatedAlert } from "../types";

const ORCHESTRATION_ACTIONS = [
  { label: "Isolate Host", endpoint: "/respond/isolate", critical: true },
  { label: "Lock Perimeter", endpoint: "/respond/lock-perimeter", critical: false },
  { label: "Quarantine Identity", endpoint: "/respond/quarantine", critical: false },
  { label: "Freeze Badge", endpoint: "/respond/freeze-badge", critical: false },
  { label: "Throttle Segment", endpoint: "/respond/throttle", critical: false },
  { label: "Open War Room", endpoint: "/respond/war-room", critical: false },
];

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
  activeLocks,
  sources,
}: {
  threats: Threat[];
  detections: Detection[];
  cameras: Camera[];
  findings: AgentFinding[];
  correlated: CorrelatedAlert[];
  activeLocks: number;
  sources: string[];
}) {
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [orchestrationLoading, setOrchestrationLoading] = useState<string | null>(null);

  // Cast threats to any to access 'status' safely
  const open = (Array.isArray(threats) ? threats : []).filter((t) => (t as any).status === "open").length;
  const crit = (Array.isArray(findings) ? findings : []).filter((f) => f.severity === "critical").length;
  const online = (Array.isArray(cameras) ? cameras : []).filter((c) => c.status === "online").length;
  const weapons = (Array.isArray(detections) ? detections : []).filter((d) => d.type?.includes("weapon")).length;

  const handleThreatAction = async (action: string, threat: Threat) => {
    const key = `${action}-${threat._id}`;
    setActionLoading(key);
    try {
      await api.post(`${API}${action}`, { threatId: threat._id, title: threat.title }, authH());
    } catch {
      logger.error(`Failed to ${action} on ${threat.title}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleOrchestration = async (endpoint: string, label: string) => {
    setOrchestrationLoading(label);
    try {
      await api.post(`${API}${endpoint}`, {}, authH());
    } catch {
      logger.error(`Failed to execute ${label}`);
    } finally {
      setOrchestrationLoading(null);
    }
  };

  // Deduplicate sources to prevent duplicates in the UI
  const uniqueSources = [...new Set(sources)];

  return (
    <div className="grid h-full grid-cols-1 gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1.5fr)]">
      <div className="flex flex-col gap-4">
        {/* KPI row */}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <KPI label="Open Threats" value={open} sub={`${crit} critical findings`} red={crit > 0} />
          <KPI label="Cameras Online" value={`${online}/${cameras.length}`} sub="YOLOv8 active" cyan />
          <KPI label="Weapon Alerts" value={weapons} sub="Camera detections" red={weapons > 0} />
          <KPI label="Pseudo-Locks" value={activeLocks} sub="Active endpoint locks" amber={activeLocks > 0} />
        </div>

        {/* ---- Endpoints Registered (Deduplicated) ---- */}
        <div className="rounded-xl border border-slate-700/80 bg-slate-950/80 p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-lg">🖥️</span>
              <span className="text-sm font-medium text-slate-300">Endpoints Registered</span>
            </div>
            <span className="rounded-full bg-cyan-500/20 px-2 py-0.5 text-xs text-cyan-300">
              {uniqueSources.length}
            </span>
          </div>
          <div className="mt-2 max-h-32 overflow-y-auto space-y-1">
            {uniqueSources.length === 0 ? (
              <p className="text-xs text-slate-500">No endpoints connected yet</p>
            ) : (
              uniqueSources.map((src) => (
                <div key={src} className="flex items-center justify-between text-xs">
                  <span className="text-slate-200">{src}</span>
                  <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.6)]" />
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
                  Tri-Gate correlated events
                </div>
              </div>
              <span className="flex items-center gap-1 text-[10px] text-slate-500">
                <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                Live
              </span>
            </div>
            <div className="flex-1 space-y-2 overflow-auto pr-1">
              {threats.length === 0 && findings.length === 0 && (
                <p className="py-6 text-center text-[11px] text-slate-600">
                  Send events to agent on port 8001
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
            <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-200">
              Auto-mode · On
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2 text-[11px] md:grid-cols-3">
            {ORCHESTRATION_ACTIONS.map(({ label, endpoint, critical }, idx) => (
              <button
                key={label}
                onClick={() => handleOrchestration(endpoint, label)}
                disabled={orchestrationLoading === label}
                className={cn(
                  "flex items-center justify-between rounded-lg border px-2.5 py-2 text-left font-medium transition active:scale-95 disabled:opacity-50",
                  critical
                    ? "border-red-500/70 bg-red-500/10 text-red-100 shadow-[0_0_14px_rgba(248,113,113,0.4)] hover:bg-red-500/20"
                    : "border-slate-700/80 bg-slate-900/80 text-slate-200 hover:border-cyan-400/80 hover:bg-cyan-500/5 hover:text-cyan-100"
                )}
              >
                <span>{orchestrationLoading === label ? "..." : label}</span>
                <span className="text-[9px] text-slate-500">⌘{idx + 1}</span>
              </button>
            ))}
          </div>
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
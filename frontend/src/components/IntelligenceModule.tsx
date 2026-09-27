import { useState, useEffect } from "react";
import { cn } from "../utils/cn";
import api, { authH, API } from "../utils/api";
import { detIcon } from "../utils/helpers";
import { logger } from "../utils/logger";
import type { Detection, Camera, AgentFinding } from "../types";

interface IdentityRow {
  id: number;
  user: string;
  role: string;
  lastSeen: string;
  access: string;
  anomaly: number;
}

export default function IntelligenceModule({
  detections,
  cameras,
  findings,
}: {
  detections: Detection[];
  cameras: Camera[];
  findings: AgentFinding[];
}) {
  const [identityRows, setIdentityRows] = useState<IdentityRow[]>([]);
  const [loadingIdentity, setLoadingIdentity] = useState(true);

  useEffect(() => {
    const fetchIdentities = async () => {
      setLoadingIdentity(true);
      try {
        const res = await api.get(`${API}/agent/identities`, authH());
        if (Array.isArray(res.data)) {
          setIdentityRows(res.data);
        }
      } catch {
        logger.warn("Failed to fetch identities, showing empty state");
        setIdentityRows([]);
      } finally {
        setLoadingIdentity(false);
      }
    };
    fetchIdentities();
  }, []);

  const byType = detections.reduce<Record<string, number>>((a, d) => {
    a[d.type] = (a[d.type] || 0) + 1;
    return a;
  }, {});
  const camAct = cameras
    .map((c) => ({
      ...c,
      cnt: detections.filter((d) => d.cameraId === c._id).length,
    }))
    .sort((a, b) => b.cnt - a.cnt)
    .slice(0, 5);
  const bySev = detections.reduce<Record<string, number>>((a, d) => {
    a[d.severity] = (a[d.severity] || 0) + 1;
    return a;
  }, {});

  return (
    <div className="grid h-full grid-cols-1 gap-4 xl:grid-cols-2">
      <div className="flex flex-col gap-4">
        <div className="flex flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
          <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
            Identity Risk Surface
          </div>
          <div className="overflow-auto rounded-lg border border-slate-800">
            <table className="min-w-full text-xs">
              <thead className="bg-slate-900/80 text-[10px] uppercase tracking-[0.14em] text-slate-500">
                <tr>
                  {["User", "Role", "Last Seen", "Access", "Score"].map(
                    (h) => (
                      <th
                        key={h}
                        className="px-2 py-2 text-left font-medium"
                      >
                        {h}
                      </th>
                    )
                  )}
                </tr>
              </thead>
              <tbody>
                {loadingIdentity ? (
                  <tr>
                    <td colSpan={5} className="px-2 py-4 text-center text-slate-500">
                      Loading...
                    </td>
                  </tr>
                ) : (
                  identityRows.map((r) => (
                    <tr
                      key={r.id}
                      className="border-t border-slate-800/60 hover:bg-slate-900/40 transition"
                    >
                      <td className="px-2 py-1.5 font-mono text-[11px] text-slate-100">
                        {r.user}
                      </td>
                      <td className="px-2 py-1.5 text-slate-400">{r.role}</td>
                      <td className="px-2 py-1.5 text-slate-400">
                        {r.lastSeen}
                      </td>
                      <td className="px-2 py-1.5 text-slate-400 text-[10px]">
                        {r.access}
                      </td>
                      <td className="px-2 py-1.5">
                        <div className="flex items-center gap-1.5">
                          <span
                            className={cn(
                              "font-medium",
                              r.anomaly > 80
                                ? "text-red-300"
                                : r.anomaly > 60
                                  ? "text-amber-300"
                                  : "text-slate-200"
                            )}
                          >
                            {r.anomaly}
                          </span>
                          <div className="h-1.5 w-12 rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className={cn(
                                "h-full rounded-full",
                                r.anomaly > 80
                                  ? "bg-gradient-to-r from-red-500 to-amber-400"
                                  : r.anomaly > 60
                                    ? "bg-amber-400"
                                    : "bg-cyan-400"
                              )}
                              style={{ width: `${r.anomaly}%` }}
                            />
                          </div>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
        <div className="flex flex-1 flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
          <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
            Detection Breakdown
          </div>
          {Object.keys(byType).length === 0 ? (
            <p className="py-4 text-center text-[11px] text-slate-600">
              No detections yet
            </p>
          ) : (
            <div className="space-y-2">
              {Object.entries(byType)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 7)
                .map(([type, count]) => {
                  const max = Math.max(...Object.values(byType));
                  const isCrit =
                    type.includes("weapon") || type.includes("watchlist");
                  return (
                    <div key={type} className="flex items-center gap-2.5">
                      <span className="text-sm flex-shrink-0">
                        {detIcon(type)}
                      </span>
                      <div className="flex-1">
                        <div className="flex justify-between mb-0.5">
                          <span className="text-[11px] text-slate-300 capitalize">
                            {type.replace(/_/g, " ")}
                          </span>
                          <span
                            className={cn(
                              "text-[11px] font-medium",
                              isCrit ? "text-red-300" : "text-slate-400"
                            )}
                          >
                            {count}
                          </span>
                        </div>
                        <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                          <div
                            className={cn(
                              "h-full rounded-full",
                              isCrit
                                ? "bg-gradient-to-r from-red-500 to-amber-400"
                                : "bg-gradient-to-r from-cyan-500 to-emerald-400"
                            )}
                            style={{ width: `${(count / max) * 100}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  );
                })}
            </div>
          )}
        </div>
      </div>
      <div className="flex flex-col gap-4">
        <div className="flex flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
          <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
            Severity Distribution
          </div>
          <div className="grid grid-cols-4 gap-2">
            {(["critical", "high", "medium", "low"] as const).map((s) => (
              <div
                key={s}
                className={cn(
                  "rounded-lg border p-3 text-center",
                  s === "critical"
                    ? "border-red-500/25 bg-red-500/5"
                    : s === "high"
                      ? "border-amber-500/20 bg-amber-500/5"
                      : s === "medium"
                        ? "border-cyan-500/20 bg-cyan-500/5"
                        : "border-emerald-500/20 bg-emerald-500/5"
                )}
              >
                <div
                  className={cn(
                    "text-2xl font-bold",
                    s === "critical"
                      ? "text-red-300"
                      : s === "high"
                        ? "text-amber-300"
                        : s === "medium"
                          ? "text-cyan-300"
                          : "text-emerald-300"
                  )}
                >
                  {bySev[s] || 0}
                </div>
                <div className="text-[10px] text-slate-500 capitalize mt-0.5">
                  {s}
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="flex flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
          <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
            Camera Activity Heatmap
          </div>
          <div className="space-y-2">
            {camAct.length === 0 ? (
              <p className="py-2 text-center text-[11px] text-slate-600">
                No data
              </p>
            ) : (
              camAct.map((c) => (
                <div key={c._id} className="flex items-center gap-2.5">
                  <span
                    className={cn(
                      "h-2 w-2 rounded-full flex-shrink-0",
                      c.status === "online" ? "bg-emerald-400" : "bg-red-400"
                    )}
                  />
                  <div className="flex-1">
                    <div className="flex justify-between mb-0.5">
                      <span className="text-[11px] text-slate-300 truncate">
                        {c.name}
                      </span>
                      <span className="text-[11px] text-slate-400">
                        {c.cnt}
                      </span>
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-400"
                        style={{ width: `${Math.min(100, c.cnt * 12)}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
        <div className="flex flex-1 flex-col rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
          <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
            Agent Insight Stream
          </div>
          <div className="space-y-2 flex-1 overflow-auto">
            {findings.slice(0, 4).map((f) => (
              <div
                key={f.id}
                className={cn(
                  "rounded-lg border px-2.5 py-2 text-[11px]",
                  f.severity === "critical"
                    ? "border-red-500/30 bg-red-500/5 text-red-200"
                    : "border-slate-800 bg-slate-900/80 text-slate-300"
                )}
              >
                <div className="font-medium text-slate-200 mb-0.5">
                  {f.agent_name} · {(f.confidence * 100) | 0}%
                </div>
                {f.summary}
              </div>
            ))}
            {findings.length === 0 && (
              <p className="text-[11px] text-slate-600 py-2">
                No agent findings yet. Send events to port 8001.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

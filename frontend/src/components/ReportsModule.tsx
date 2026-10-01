// Reports (risk / compliance / executive as PDF, CSV or JSON) and the full
// compliance check list of every PC (ISO 27001:2022 + NIST CSF 2.0).
import { useCallback, useEffect, useState } from "react";
import api, { apiErrorMessage } from "../utils/api";
import { cn } from "../utils/cn";
import { downloadReport, timeAgo, type ReportType, type ReportFormat } from "../utils/reports";
import type { ComplianceReport } from "../types";

const REPORTS: { id: ReportType; title: string; icon: string; who: string; contains: string[] }[] = [
  {
    id: "executive", title: "Executive Security Summary", icon: "📊", who: "For management / board",
    contains: ["Posture score and key figures", "Alerts-per-day chart", "Top attack types and targeted users", "Latest serious alerts", "Compliance gaps"],
  },
  {
    id: "risk", title: "Risk Report", icon: "⚠️", who: "For the security team",
    contains: ["How the posture score is calculated", "Alerts by severity and per day", "Top attacking IPs and PCs", "Every alert, highest risk first (CSV = full list)"],
  },
  {
    id: "compliance", title: "Compliance Report", icon: "✅", who: "For auditors (ISO 27001 / NIST CSF)",
    contains: ["Score per PC", "ISO 27001:2022 and NIST CSF 2.0 controls met", "Every check with status and detail", "How to fix each gap"],
  },
];

const STATUS_CLS: Record<string, string> = {
  pass: "bg-emerald-500/15 text-emerald-300",
  warn: "bg-amber-500/15 text-amber-300",
  fail: "bg-red-500/15 text-red-300",
  unknown: "bg-slate-800 text-slate-400",
};

export default function ReportsModule({
  refreshTick,
  onNotify,
}: {
  refreshTick: number;
  onNotify?: (type: "critical" | "warning" | "info", title: string, body: string) => void;
}) {
  const [days, setDays] = useState(30);
  const [busy, setBusy] = useState("");
  const [reports, setReports] = useState<ComplianceReport[]>([]);
  const [endpoint, setEndpoint] = useState("");
  const [onlyGaps, setOnlyGaps] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await api.get("/agent/compliance");
      const list: ComplianceReport[] = Array.isArray(res.data) ? res.data : [];
      setReports(list);
      setEndpoint((cur) => (cur && list.some((r) => r.endpoint === cur) ? cur : list[0]?.endpoint || ""));
      setError("");
    } catch (e) {
      setError(apiErrorMessage(e, "Could not load compliance data"));
    }
  }, []);
  useEffect(() => { load(); }, [load, refreshTick]);

  const get = async (type: ReportType, format: ReportFormat) => {
    setBusy(`${type}-${format}`);
    try {
      await downloadReport(type, format, days);
      onNotify?.("info", "Report downloaded", `${type} report (${format.toUpperCase()}, last ${days} days)`);
    } catch (e: any) {
      onNotify?.("warning", "Report failed", e.message);
    } finally {
      setBusy("");
    }
  };

  const current = reports.find((r) => r.endpoint === endpoint);
  const checks = (current?.checks || []).filter((c) => !onlyGaps || c.status === "fail" || c.status === "warn");

  return (
    <div className="flex flex-col gap-4">
      {/* ---------------- report downloads */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">Reports</div>
            <div className="text-[11px] text-slate-500">PDF to read or share, CSV to open in Excel, JSON for other tools.</div>
          </div>
          <label className="flex items-center gap-2 text-[11px] text-slate-400">
            Period
            <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200">
              <option value={1}>Last 24 hours</option>
              <option value={7}>Last 7 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
              <option value={365}>Last 12 months</option>
            </select>
          </label>
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {REPORTS.map((r) => (
            <div key={r.id} className="flex flex-col rounded-lg border border-slate-800 bg-slate-900/40 p-3">
              <div className="flex items-center gap-2">
                <span className="text-xl">{r.icon}</span>
                <div>
                  <div className="text-[13px] font-semibold text-slate-100">{r.title}</div>
                  <div className="text-[10px] text-slate-500">{r.who}</div>
                </div>
              </div>
              <ul className="my-2 flex-1 list-disc space-y-0.5 pl-4 text-[11px] text-slate-400">
                {r.contains.map((c) => <li key={c}>{c}</li>)}
              </ul>
              <div className="flex gap-1.5 text-[11px]">
                <button disabled={!!busy} onClick={() => get(r.id, "pdf")}
                  className="flex-1 rounded bg-cyan-500/80 py-1 font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50">
                  {busy === `${r.id}-pdf` ? "Preparing…" : "⬇ PDF"}
                </button>
                <button disabled={!!busy} onClick={() => get(r.id, "csv")}
                  className="flex-1 rounded border border-slate-600 py-1 text-slate-200 hover:border-cyan-500/60 disabled:opacity-50">
                  {busy === `${r.id}-csv` ? "…" : "⬇ CSV"}
                </button>
                <button disabled={!!busy} onClick={() => get(r.id, "json")}
                  className="rounded border border-slate-700 px-2 py-1 text-slate-400 hover:text-slate-200 disabled:opacity-50">JSON</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ---------------- compliance detail */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">Compliance checks</div>
            <div className="text-[11px] text-slate-500">
              Each agent checks its own PC and maps the result to ISO/IEC 27001:2022 Annex A and NIST CSF 2.0.
            </div>
          </div>
          <div className="flex items-center gap-2 text-[11px]">
            {reports.length > 0 && (
              <select value={endpoint} onChange={(e) => setEndpoint(e.target.value)} className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200">
                {reports.map((r) => <option key={r.endpoint} value={r.endpoint}>{r.endpoint}</option>)}
              </select>
            )}
            <label className="flex items-center gap-1 text-slate-400">
              <input type="checkbox" checked={onlyGaps} onChange={(e) => setOnlyGaps(e.target.checked)} /> only gaps
            </label>
            <button onClick={load} className="rounded border border-slate-700 px-2 py-1 text-slate-300">↻</button>
          </div>
        </div>

        {error && <div className="mb-2 rounded border border-red-500/40 bg-red-500/10 px-2 py-1 text-[11px] text-red-200">{error}</div>}

        {!current ? (
          <div className="py-8 text-center text-[12px] text-slate-500">
            No compliance report yet.
            <div className="mt-1 text-[11px] text-slate-600">
              Start the agent as Administrator. Within about a minute of starting (then every 15 minutes, setting device_check_minutes) it checks antivirus, firewall,
              Windows updates, BitLocker, UAC, audit policy, password policy, Guest account, SMBv1, Remote Desktop and the security log, and sends the result here.
            </div>
          </div>
        ) : (
          <>
            <div className="mb-3 grid grid-cols-2 gap-2 md:grid-cols-6">
              <Box label="Score" value={current.score === null ? "n/a" : `${current.score}%`}
                tone={current.score === null ? "" : current.score >= 80 ? "text-emerald-300" : current.score >= 60 ? "text-amber-300" : "text-red-300"} />
              <Box label="Pass" value={current.counts.pass ?? 0} tone="text-emerald-300" />
              <Box label="Warning" value={current.counts.warn ?? 0} tone="text-amber-300" />
              <Box label="Fail" value={current.counts.fail ?? 0} tone="text-red-300" />
              {Object.entries(current.frameworks || {}).map(([fw, f]) => (
                <Box key={fw} label={`${fw} controls met`} value={`${f.met} / ${f.controls}`}
                  sub={f.failing.length ? `failing: ${f.failing.join(", ")}` : "none failing"} />
              ))}
            </div>
            <div className="mb-2 text-[10px] text-slate-500">
              Last check {timeAgo(current.checked_at || current.checkedAt)} · score: pass = 1 point, warning = ½, fail = 0, "unknown" (could not be read) is left out.
            </div>
            <div className="overflow-auto">
              <table className="w-full text-left text-[11px]">
                <thead className="text-[10px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="py-1.5">Check</th>
                    <th>Status</th>
                    <th className="hidden md:table-cell">ISO 27001:2022</th>
                    <th className="hidden md:table-cell">NIST CSF 2.0</th>
                    <th>Detail / how to fix</th>
                  </tr>
                </thead>
                <tbody>
                  {checks.map((c) => (
                    <tr key={c.id} className="border-t border-slate-800/70 align-top">
                      <td className="py-1.5 pr-2 text-slate-200">{c.title}</td>
                      <td className="pr-2"><span className={cn("rounded px-1.5 py-0.5 text-[10px]", STATUS_CLS[c.status])}>{c.status}</span></td>
                      <td className="hidden pr-2 text-slate-400 md:table-cell">{c.iso27001.join(", ")}</td>
                      <td className="hidden pr-2 text-slate-400 md:table-cell">{c.nist_csf.join(", ")}</td>
                      <td className="text-slate-400">
                        {c.detail}
                        {c.fix && <div className="mt-0.5 text-cyan-300/90">🔧 {c.fix}</div>}
                      </td>
                    </tr>
                  ))}
                  {checks.length === 0 && (
                    <tr><td colSpan={5} className="py-4 text-center text-slate-500">No gaps - every check passed. 🎉</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function Box({ label, value, sub, tone }: { label: string; value: string | number; sub?: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2">
      <div className="text-[9px] uppercase tracking-[0.15em] text-slate-500">{label}</div>
      <div className={cn("text-lg font-semibold text-slate-100", tone)}>{value}</div>
      {sub && <div className="truncate text-[10px] text-slate-500" title={sub}>{sub}</div>}
    </div>
  );
}

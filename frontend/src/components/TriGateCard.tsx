import { useState } from "react";
import { cn } from "../utils/cn";
import api, { waitForCommand, apiErrorMessage } from "../utils/api";
import { sevCls, verdictCls } from "../utils/helpers";
import type { GateDecision, TriGateFactor, TriGateScore } from "../types";

// Remote actions that can be run with one click from a recommendation
const RUNNABLE = new Set([
  "block_access", "revoke_identity", "isolate_asset",
  // dynamic access control (agent/response/access_control.py)
  "restrict_identity", "force_logout", "terminate_process", "throttle_segment",
]);

const GATES: {
  key: "trust" | "intent" | "impact";
  title: string;
  question: string;
  // colour of the bar: for Trust high is GOOD, for Intent/Impact high is BAD
  barCls: (score: number) => string;
}[] = [
  {
    key: "trust",
    title: "Gate 1 · Trust",
    question: "Who is it - can we trust them?",
    barCls: (s) => (s >= 70 ? "bg-emerald-400" : s >= 40 ? "bg-amber-400" : "bg-red-500"),
  },
  {
    key: "intent",
    title: "Gate 2 · Intent",
    question: "Is it an attack?",
    barCls: (s) => (s >= 70 ? "bg-red-500" : s >= 40 ? "bg-amber-400" : "bg-emerald-400"),
  },
  {
    key: "impact",
    title: "Gate 3 · Impact",
    question: "How bad would it be?",
    barCls: (s) => (s >= 70 ? "bg-red-500" : s >= 40 ? "bg-orange-400" : "bg-emerald-400"),
  },
];

const RISK_CLS: Record<string, string> = {
  critical: "border-red-500/60 bg-red-500/15 text-red-300",
  high: "border-orange-500/60 bg-orange-500/15 text-orange-300",
  medium: "border-amber-500/60 bg-amber-500/10 text-amber-300",
  low: "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
};

function Factor({ f }: { f: TriGateFactor }) {
  return (
    <li className="flex gap-2 text-[11px] leading-snug">
      <span
        className={cn(
          "w-9 flex-shrink-0 text-right font-mono",
          f.points > 0 ? "text-sky-300" : f.points < 0 ? "text-rose-300" : "text-slate-500"
        )}
      >
        {f.points > 0 ? `+${f.points}` : f.points}
      </span>
      <span className="text-slate-300">{f.text}</span>
    </li>
  );
}

function GateBar({ gate, data }: { gate: (typeof GATES)[number]; data?: TriGateScore }) {
  const score = Math.max(0, Math.min(100, data?.score ?? 0));
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[11px] font-bold text-slate-200">{gate.title}</span>
        <span className="text-sm font-bold text-slate-100">
          {data ? score : "-"}
          <span className="text-[10px] font-normal text-slate-500">/100</span>
        </span>
      </div>
      <div className="text-[10px] text-slate-500">
        {gate.question} {data?.level ? <span className="text-slate-300">→ {data.level}</span> : null}
      </div>
      <div className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className={cn("h-full rounded-full transition-all", gate.barCls(score))}
          style={{ width: `${score}%` }}
        />
      </div>
      <ul className="mt-2 space-y-0.5">
        {(data?.factors ?? []).map((f, i) => (
          <Factor key={i} f={f} />
        ))}
      </ul>
    </div>
  );
}

export default function TriGateCard({ decision: d }: { decision: GateDecision }) {
  const tri = d.metadata?.trigate ?? {};
  const ctx = tri.context;
  const risk = tri.risk;
  const [feedback, setFeedback] = useState(d.feedback?.kind ?? null);
  const [fbMsg, setFbMsg] = useState<string | null>(
    d.feedback ? (d.feedback.status === "failed" ? `Agent error: ${d.feedback.error}` : "Saved") : null
  );
  const [busy, setBusy] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const sendFeedback = async (kind: "false_alarm" | "confirmed") => {
    setBusy(kind);
    setFbMsg("Sending to agent…");
    try {
      const res = await api.post(`/agent/gate-decisions/${encodeURIComponent(d.event_id)}/feedback`, {
        feedback: kind,
      });
      const outcome = await waitForCommand(res.data.cmd_id, 15000);
      if (outcome.status === "executed") {
        setFeedback(kind);
        setFbMsg(
          kind === "false_alarm"
            ? "Saved on the agent - similar events will score LOWER from now on"
            : "Saved on the agent - similar events will score HIGHER from now on"
        );
      } else if (outcome.status === "failed") {
        setFbMsg(`Agent error: ${outcome.error}`);
      } else {
        setFbMsg("No answer from the agent (is it running?)");
      }
    } catch (err) {
      setFbMsg(apiErrorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const runAction = async (action: string, target: string) => {
    if (!d.source) return;
    if (!window.confirm(`Run "${action.replace(/_/g, " ")}" on ${d.source} for "${target}"?`)) return;
    setBusy(action);
    setActionMsg("Sending…");
    try {
      const res = await api.post("/agent/commands", { endpoint_id: d.source, action, target });
      const outcome = await waitForCommand(res.data.cmd_id, 20000);
      setActionMsg(
        outcome.status === "executed"
          ? `✅ ${action.replace(/_/g, " ")} done - see the Isolation & Termination tab`
          : outcome.status === "failed"
            ? `❌ ${outcome.error}`
            : "No answer from the agent"
      );
    } catch (err) {
      setActionMsg(apiErrorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 space-y-2.5">
      {/* header */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] font-bold tracking-wide text-cyan-300">TRIGATE</span>
        {risk && (
          <span
            className={cn(
              "rounded border px-2 py-0.5 text-[10px] font-bold uppercase",
              RISK_CLS[risk.level] ?? RISK_CLS.low
            )}
          >
            Risk {risk.score}/100 · {risk.level}
          </span>
        )}
        <span className={cn("rounded border px-2 py-0.5 text-[9px] font-bold uppercase", verdictCls(d.verdict))}>
          {d.verdict}
        </span>
        <span className={cn("rounded-full px-2 py-0.5 text-[9px] font-medium ring-1", sevCls(d.severity))}>
          {d.severity}
        </span>
        {d.source && <span className="text-[10px] text-slate-400">🖥️ {d.source}</span>}
        {ctx?.test_event && (
          <span className="rounded bg-violet-500/20 px-1.5 py-0.5 text-[9px] text-violet-300">TEST</span>
        )}
        <span className="text-[10px] text-slate-600 ml-auto">{new Date(d.timestamp).toLocaleString()}</span>
      </div>

      {/* what happened */}
      <div>
        <div className="text-sm font-semibold text-slate-100">
          {ctx?.pattern_label ?? d.threat_type}
          {ctx?.event_id_raw ? (
            <span className="ml-2 text-[10px] font-normal text-slate-500">Windows event {String(ctx.event_id_raw)}</span>
          ) : null}
          {ctx?.mitre_id ? (
            <span className="ml-2 rounded bg-slate-800 px-1.5 py-0.5 text-[9px] font-normal text-slate-300">
              MITRE {ctx.mitre_id}
            </span>
          ) : null}
        </div>
        {ctx?.description && <p className="text-xs text-slate-400">{ctx.description}</p>}
        <p className="text-[11px] text-slate-500 mt-0.5">
          Final risk = 30% × (100 − Trust) + 40% × Intent + 30% × Impact
        </p>
      </div>

      {/* three bars */}
      <div className="grid gap-2 md:grid-cols-3">
        {GATES.map((g) => (
          <GateBar key={g.key} gate={g} data={tri[g.key]} />
        ))}
      </div>

      {/* recommendations */}
      {tri.recommended && tri.recommended.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
          <div className="text-[11px] font-bold text-slate-200 mb-1">Recommended actions</div>
          <ul className="space-y-1">
            {tri.recommended.map((r, i) => (
              <li key={i} className="flex items-center gap-2 text-[11px] text-slate-300">
                <span className="text-slate-500">•</span>
                <span className="flex-1">{r.text}</span>
                {RUNNABLE.has(r.action) && r.target && d.source && (
                  <button
                    disabled={busy !== null}
                    onClick={() => runAction(r.action, r.target)}
                    className="rounded border border-cyan-500/40 bg-cyan-500/10 px-2 py-0.5 text-[10px] text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-40"
                  >
                    Run
                  </button>
                )}
              </li>
            ))}
          </ul>
          {actionMsg && <p className="mt-1 text-[10px] text-slate-400">{actionMsg}</p>}
        </div>
      )}

      {/* learning */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] text-slate-500">Teach the TriGate:</span>
        <button
          disabled={busy !== null || !d.source}
          onClick={() => sendFeedback("false_alarm")}
          className={cn(
            "rounded border px-2.5 py-1 text-[10px] font-medium disabled:opacity-40",
            feedback === "false_alarm"
              ? "border-emerald-400 bg-emerald-500/20 text-emerald-200"
              : "border-slate-600 text-slate-300 hover:bg-slate-800"
          )}
        >
          👍 False alarm
        </button>
        <button
          disabled={busy !== null || !d.source}
          onClick={() => sendFeedback("confirmed")}
          className={cn(
            "rounded border px-2.5 py-1 text-[10px] font-medium disabled:opacity-40",
            feedback === "confirmed"
              ? "border-red-400 bg-red-500/20 text-red-200"
              : "border-slate-600 text-slate-300 hover:bg-slate-800"
          )}
        >
          🚨 Real threat
        </button>
        {fbMsg && <span className="text-[10px] text-slate-400">{fbMsg}</span>}
      </div>
    </div>
  );
}

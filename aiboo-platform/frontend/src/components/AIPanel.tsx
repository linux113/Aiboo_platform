import { useState, useEffect, useRef } from "react";
import { cn } from "../utils/cn";
import api, { authH, API } from "../utils/api";
import type { Detection, Threat, AgentFinding, CorrelatedAlert, ChatMsg } from "../types";

interface SpeechRecognitionErrorEvent {
  error: string;
}

interface SpeechRecognitionResult {
  isFinal: boolean;
  [index: number]: { transcript: string };
}

interface SpeechRecognitionResultList {
  [index: number]: SpeechRecognitionResult;
  length: number;
}

interface SpeechRecognitionEvent {
  results: SpeechRecognitionResultList;
}

interface SpeechRecognition extends EventTarget {
  lang: string;
  interimResults: boolean;
  maxAlternatives: number;
  onstart: (() => void) | null;
  onend: (() => void) | null;
  onresult: ((e: SpeechRecognitionEvent) => void) | null;
  onerror: ((e: SpeechRecognitionErrorEvent) => void) | null;
  start: () => void;
  stop: () => void;
}

interface SpeechRecognitionConstructor {
  new (): SpeechRecognition;
}

export default function AIPanel({
  dets,
  threats,
  findings,
  correlated,
}: {
  dets: Detection[];
  threats: Threat[];
  findings: AgentFinding[];
  correlated: CorrelatedAlert[];
}) {
  const [open, setOpen] = useState(true);
  const [msgs, setMsgs] = useState<ChatMsg[]>([
    {
      id: 1,
      role: "assistant",
      content:
        "JARVIS online. AiBoO Tri-Gate platform active. I have context from all 4 agents, the correlation engine, and camera feeds. Ask me anything about threats, gate decisions, pseudo-locks, or identity risks.",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [listening, setListening] = useState(false);
  const [speaking, setSpeaking] = useState(false);
  const [offlineMode, setOfflineMode] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);
  const recRef = useRef<SpeechRecognition | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const waveRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (open) endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgs, open]);

  useEffect(() => {
    return () => {
      if (waveRef.current) cancelAnimationFrame(waveRef.current);
    };
  }, []);

  const speak = (text: string) => {
    if (!("speechSynthesis" in window)) return;
    window.speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(text.substring(0, 250));
    u.rate = 0.88;
    u.pitch = 0.9;
    u.volume = 1;
    const vs = window.speechSynthesis.getVoices();
    const v =
      vs.find(
        (v) => v.name.includes("Google") || v.name.includes("Microsoft")
      ) ||
      vs.find((v) => v.lang === "en-US") ||
      vs[0];
    if (v) u.voice = v;
    u.onstart = () => setSpeaking(true);
    u.onend = () => setSpeaking(false);
    window.speechSynthesis.speak(u);
  };

  const stopSpeak = () => {
    window.speechSynthesis.cancel();
    setSpeaking(false);
  };

  const addTypingAndReplace = (content: string, meta?: { confidence?: number; sources?: string }) => {
    const typingId = Date.now() + 1;
    setMsgs((p) => [
      ...p,
      { id: typingId, role: "assistant" as const, content: "", isTyping: true },
    ]);
    setTimeout(() => {
      setMsgs((p) =>
        p.map((m) =>
          m.id === typingId
            ? { id: typingId, role: "assistant" as const, content, meta, isTyping: false }
            : m
        )
      );
      speak(content);
    }, 600);
  };

  const send = async (text?: string) => {
    const content = (text ?? input).trim();
    if (!content || loading) return;
    setInput("");
    setMsgs((p) => [...p, { id: Date.now(), role: "user", content }]);
    setLoading(true);
    setOfflineMode(false);
    try {
      const hist = msgs.slice(-6).map((m) => ({
        role: m.role,
        content: m.content,
      }));
      const res = await api.post(
        `${API}/ai/chat`,
        { message: content, history: hist },
        authH()
      );
      const meta = res.data.confidence
        ? { confidence: res.data.confidence, sources: res.data.sources || "tri-gate agents · camera feed · threat db" }
        : undefined;
      addTypingAndReplace(res.data.content, meta);
    } catch {
      setOfflineMode(true);
      addTypingAndReplace(fallback(content, dets, threats, findings, correlated));
    } finally {
      setLoading(false);
    }
  };

  function fallback(
    msg: string,
    d: Detection[],
    t: Threat[],
    f: AgentFinding[],
    c: CorrelatedAlert[]
  ) {
    const m = msg.toLowerCase();
    const w = d.filter((x) => x.type.includes("weapon"));
    const crit = f.filter((x) => x.severity === "critical");
    const high = f.filter((x) => x.severity === "high");
    const isQ = (s: string) => m.includes(s);
    const byAgent = f.reduce<Record<string, number>>((a, x) => {
      a[x.agent_name] = (a[x.agent_name] || 0) + 1;
      return a;
    }, {});
    const byType = f.reduce<Record<string, number>>((a, x) => {
      a[x.threat_type] = (a[x.threat_type] || 0) + 1;
      return a;
    }, {});
    const topAgent = Object.entries(byAgent)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);
    const topType = Object.entries(byType)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);
    const detTypes = d.reduce<Record<string, number>>((a, x) => {
      a[x.type] = (a[x.type] || 0) + 1;
      return a;
    }, {});
    const topDet = Object.entries(detTypes)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);
    const activeLocks = f.filter((x) => x.actions.includes("pseudo_lock")).length;
    const openThreats = t.filter((x) => x.status === "open").length;

    if (
      isQ("hello") ||
      isQ("hi") ||
      isQ("hey") ||
      isQ("good morning") ||
      isQ("good evening")
    )
      return `Hello! JARVIS online. ${f.length} findings · ${d.length} detections · ${c.length} correlated · ${activeLocks} active locks. How can I assist you?`;
    if (
      isQ("status") ||
      isQ("situation") ||
      isQ("sitrep") ||
      isQ("report") ||
      isQ("summary")
    )
      return `📊 SITREP — Open threats: ${openThreats} · Agent findings: ${f.length} (${crit.length} critical, ${high.length} high) · Correlated alerts: ${c.length} · Camera detections: ${d.length} · Weapon alerts: ${w.length} · Active pseudo-locks: ${activeLocks}. ${c.length > 0 ? "⚠️ CORRELATED ATTACK PATTERNS ACTIVE — check Intelligence tab." : "All systems nominal."}`;
    if (isQ("weapon") || isQ("gun") || isQ("knife") || isQ("firearm"))
      return w.length > 0
        ? `⚠️ CRITICAL: ${w.length} weapon detection(s). Latest: ${w[0].label} at ${w[0].cameraName} (${w[0].confidence}%, ${new Date(w[0].timestamp).toLocaleTimeString()}). ${w.length > 1 ? `${w.length - 1} additional detection(s).` : ""} Initiating lockdown protocol recommendation.`
        : "No weapon detections in current session. Perimeter secure.";
    if (isQ("correl") || isQ("pattern") || isQ("attack"))
      return c.length > 0
        ? `🔗 ${c.length} correlated alert(s). Latest: ${c[0].description.replace("[CORRELATED] ", "").substring(0, 120)} (${c[0].severity}, ${(c[0].confidence * 100) | 0}% confidence). ${c.length > 1 ? `${c.length - 1} more alert(s) — check Agent Console.` : ""}`
        : "No correlated attack patterns detected. Multi-domain correlation engine active and monitoring.";
    if (isQ("pseudo") || isQ("lock") || isQ("endpoint") || isQ("honeypot"))
      return activeLocks > 0
        ? `🔒 ${activeLocks} active pseudo-lock(s). Affected endpoints redirected to decoy honeypots. See Agent Console → Locks tab to restore.`
        : "No active pseudo-locks. All endpoints nominal. PseudoLockAgent ready to isolate on threat detection.";
    if (isQ("gate") || isQ("pipeline") || isQ("tri"))
      return `Tri-gate pipeline: Gate 1 (Perimeter) → ${f.filter((x) => x.agent_name === "CyberThreatAgent").length > 0 ? "active" : "standby"} · Gate 2 (Behavioural) → ${f.filter((x) => x.agent_name === "IdentityVerificationAgent").length > 0 ? "active" : "standby"} · Gate 3 (Adaptive) → ${activeLocks > 0 ? "active" : "standby"}. ${f.length} total findings processed.`;
    if (isQ("agent") || isQ("jarvis") || isQ("who") || isQ("your"))
      return `I am AiBoO JARVIS — your AI security co-pilot. Monitoring ${Object.keys(byAgent).length} active agents: ${Object.entries(byAgent).map(([a, n]) => `${a} (${n})`).join(", ") || "CyberThreatAgent, IdentityVerificationAgent, SurveillanceAgent, PseudoLockAgent"}. Voice-enabled, multi-domain context synthesis active.`;
    if (isQ("camera") || isQ("surveillance") || isQ("feed"))
      return `Monitoring ${new Set(d.map((x) => x.cameraId)).size} active cameras · ${d.length} detections this session · ${topDet.map(([t, n]) => `${t.replace(/_/g, " ")}: ${n}`).join(", ")}. CV service: YOLOv8 + DeepSORT tracking active.`;
    if (isQ("threat") || isQ("danger") || isQ("intrusion") || isQ("breach"))
      return t.length > 0
        ? `${openThreats} active threats. ${crit.length > 0 ? `${crit.length} critical findings require immediate attention: ${crit.slice(0, 2).map((x) => x.summary.substring(0, 40)).join("; ")}.` : "No critical findings currently."}`
        : "No threats in database. All clear.";
    if (isQ("identity") || isQ("user") || isQ("access") || isQ("mismatch"))
      return `Identity risk monitoring active. ${f.filter((x) => x.threat_type === "identity_mismatch").length} identity mismatch findings. Zero Trust PDP enforcing policy. Check Intelligence tab for detailed risk surface.`;
    if (isQ("memory") || isQ("scan") || isQ("malware") || isQ("ransomware"))
      return f.filter((x) => x.threat_type === "memory_threat" || x.threat_type === "ransomware_prelude").length > 0
        ? `🧠 Memory threat detected. CyberThreatAgent scanning active. ${f.filter((x) => x.threat_type === "memory_threat").length} memory findings.`
        : "No memory threats detected. CyberThreatAgent memory scanner active.";
    if (isQ("physical") || isQ("perimeter") || isQ("zone") || isQ("access_control"))
      return f.filter((x) => x.threat_type === "physical_intrusion").length > 0
        ? `🏢 ${f.filter((x) => x.threat_type === "physical_intrusion").length} physical intrusion findings. SurveillanceAgent monitoring all zones.`
        : "No physical intrusions detected. All zones secure.";
    if (isQ("help") || isQ("what can") || isQ("commands") || isQ("guide"))
      return `I can help with: "status" for full SITREP · "weapon alerts" · "active locks" · "correlated attacks" · "gate pipeline" · "identity risks" · "camera feed" · "memory scan" · "physical intrusions" · "top findings". For OpenAI-powered responses, add an API key in backend .env.`;
    if (isQ("top") || isQ("most") || isQ("summary"))
      return `📈 Summary: Top agents — ${topAgent.map(([a, n]) => `${a} (${n})`).join(", ")}. Top threats — ${topType.map(([t, n]) => `${t.replace(/_/g, " ")} (${n})`).join(", ")}. Top detections — ${topDet.map(([t, n]) => `${t.replace(/_/g, " ")} (${n})`).join(", ")}.`;
    if (isQ("thank"))
      return 'You\'re welcome. JARVIS standing by. Say "status" anytime for a full SITREP or ask about specific agents, threats, or camera feeds.';

    const recent = f
      .slice(0, 3)
      .map(
        (x) =>
          `• [${x.severity.toUpperCase()}] ${x.agent_name}: ${x.summary.substring(0, 50)}`
      )
      .join("\n");
    return `JARVIS analyzing: "${msg}". I found ${f.length} agent findings and ${d.length} camera detections in context.\n${recent ? `\nRecent findings:\n${recent}` : ""}\n\nConfigure OpenAI API key in backend .env for full AI-powered natural language responses. For now, try: "status", "weapon alerts", "active locks", "correlated attacks".`;
  }

  const startListen = () => {
    const SR: SpeechRecognitionConstructor | undefined =
      (window as unknown as { SpeechRecognition?: SpeechRecognitionConstructor }).SpeechRecognition ||
      (window as unknown as { webkitSpeechRecognition?: SpeechRecognitionConstructor }).webkitSpeechRecognition;
    if (!SR) {
      alert(
        "Speech recognition not supported in this browser. Use Chrome."
      );
      return;
    }
    const r = new SR();
    r.lang = "en-US";
    r.interimResults = false;
    r.maxAlternatives = 1;
    r.onstart = () => setListening(true);
    r.onend = () => setListening(false);
    r.onresult = (e) => {
      const t = e.results[0][0].transcript;
      setInput(t);
      setTimeout(() => send(t), 200);
    };
    r.onerror = () => {
      setListening(false);
    };
    r.start();
    recRef.current = r;
  };

  const stopListen = () => {
    recRef.current?.stop();
    setListening(false);
  };

  const QUICK = [
    "Full SITREP",
    "Weapon alerts?",
    "Active locks?",
    "Correlated attacks?",
    "Top findings",
    "Identity risks?",
  ];

  return (
    <div
      className={cn(
        "pointer-events-auto fixed right-2 z-40 flex max-h-[85vh] flex-col rounded-2xl border shadow-2xl backdrop-blur transition-all duration-300",
        open
          ? "bottom-2 w-[340px] sm:w-[380px] border-cyan-500/30 bg-slate-950/97 shadow-[0_0_40px_rgba(34,211,238,0.15)]"
          : "bottom-2 w-[200px] border-slate-800/80 bg-slate-950/96"
      )}
    >
      <div
        className={cn(
          "flex items-center justify-between border-b border-slate-800/80 px-3 py-2.5 rounded-t-2xl",
          open ? "bg-gradient-to-r from-cyan-500/8 to-emerald-500/5" : ""
        )}
      >
        <div className="flex items-center gap-2.5">
          <div className="relative flex-shrink-0">
            <div
              className={cn(
                "h-8 w-8 rounded-full flex items-center justify-center text-sm font-black",
                speaking
                  ? "bg-gradient-to-br from-cyan-400 to-emerald-400 shadow-[0_0_20px_rgba(34,211,238,0.8)]"
                  : "bg-gradient-to-br from-cyan-500/30 to-emerald-500/20 border border-cyan-500/40"
              )}
            >
              {speaking ? "🔊" : "🤖"}
            </div>
            <span
              className={cn(
                "absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2 border-slate-950",
                listening
                  ? "bg-red-400 animate-pulse"
                  : speaking
                    ? "bg-cyan-400 animate-pulse"
                    : "bg-emerald-400"
              )}
            />
          </div>
          <div className="flex flex-col">
            <span className="text-[12px] font-bold text-slate-100">
              AiBoO JARVIS
            </span>
            {open && (
              <span className="text-[9px] text-cyan-400/70">
                {offlineMode
                  ? "⚡ Offline mode"
                  : listening
                    ? "🎙 Listening…"
                    : speaking
                      ? "🔊 Speaking…"
                      : "Tri-gate context · Voice enabled"}
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          {open && speaking && (
            <button
              onClick={stopSpeak}
              className="rounded border border-red-500/40 bg-red-500/10 px-1.5 py-0.5 text-[9px] text-red-300 hover:bg-red-500/20"
            >
              Stop
            </button>
          )}
          {open && (
            <button
              onClick={listening ? stopListen : startListen}
              className={cn(
                "rounded border px-2 py-0.5 text-[10px] transition font-medium",
                listening
                  ? "border-red-500/60 bg-red-500/20 text-red-300 animate-pulse"
                  : "border-cyan-500/40 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20"
              )}
            >
              {listening ? "■ Stop" : "🎙"}
            </button>
          )}
          <button
            onClick={() => setOpen((o) => !o)}
            className="rounded border border-slate-700/80 bg-slate-900/80 px-2 py-0.5 text-[10px] text-slate-400 hover:border-cyan-400/80 hover:text-cyan-100 transition"
          >
            {open ? "−" : "＋"}
          </button>
        </div>
      </div>

      {open && (
        <>
          <div className="flex-1 space-y-2 overflow-auto px-3 py-2.5 pr-2">
            {msgs.map((m) => (
              <div
                key={m.id}
                className={cn(
                  "flex",
                  m.role === "user" ? "justify-end" : "justify-start"
                )}
              >
                {m.role === "assistant" && (
                  <div className="mr-1.5 mt-1 flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 ring-1 ring-cyan-400/30 text-[10px] font-bold text-cyan-300">
                    J
                  </div>
                )}
                <div className="flex flex-col max-w-[84%]">
                  <div
                    className={cn(
                      "rounded-2xl px-3 py-2 text-[11px] leading-relaxed",
                      m.role === "user"
                        ? "bg-gradient-to-br from-cyan-500/25 to-emerald-500/15 text-cyan-50 ring-1 ring-cyan-500/30 rounded-tr-sm"
                        : "bg-slate-900/90 text-slate-100 ring-1 ring-slate-800/80 rounded-tl-sm"
                    )}
                  >
                    {m.isTyping ? (
                      <div className="flex gap-1 items-center py-0.5">
                        <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" />
                        <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "150ms" }} />
                        <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "300ms" }} />
                      </div>
                    ) : (
                      m.content
                    )}
                  </div>
                  {m.role === "assistant" && !m.isTyping && m.meta && (
                    <div className="flex items-center gap-2 mt-0.5 ml-1">
                      {typeof m.meta.confidence === "number" && (
                        <span className="text-[9px] text-slate-600">
                          Conf {(m.meta.confidence * 100).toFixed(0)}%
                        </span>
                      )}
                      {m.meta.sources && (
                        <span className="text-[9px] text-slate-600 truncate">
                          {m.meta.sources}
                        </span>
                      )}
                      <button
                        onClick={() => speak(m.content)}
                        className="text-slate-600 hover:text-cyan-400 transition text-[10px]"
                        title="Read aloud"
                      >
                        🔊
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex justify-start">
                <div className="mr-1.5 mt-1 flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 ring-1 ring-cyan-400/30 text-[10px] font-bold text-cyan-300">
                  J
                </div>
                <div className="rounded-2xl rounded-tl-sm bg-slate-900/90 px-3 py-2 ring-1 ring-slate-800/80">
                  <div className="flex gap-1 items-center">
                    <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" />
                    <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "150ms" }} />
                    <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "300ms" }} />
                  </div>
                </div>
              </div>
            )}
            <div ref={endRef} />
          </div>

          <div className="px-3 pb-1">
            <div className="flex gap-1.5 overflow-x-auto scrollbar-none pb-1">
              {QUICK.map((q) => (
                <button
                  key={q}
                  onClick={() => send(q)}
                  className="flex-shrink-0 rounded-full border border-slate-700/60 bg-slate-900/60 px-2.5 py-1 text-[10px] text-slate-400 hover:border-cyan-400/60 hover:text-cyan-200 hover:bg-cyan-500/5 transition whitespace-nowrap"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>

          <div className="border-t border-slate-800/60 px-3 pb-3 pt-2">
            <div className="flex items-center gap-2 rounded-xl border border-slate-700/60 bg-slate-900/70 px-3 py-2 focus-within:border-cyan-500/50 focus-within:shadow-[0_0_15px_rgba(34,211,238,0.1)] transition">
              <input
                ref={inputRef}
                className="flex-1 bg-transparent text-[12px] text-slate-100 placeholder:text-slate-600 focus:outline-none"
                placeholder="Ask anything…"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    send();
                  }
                }}
              />
              <div className="flex items-center gap-1 flex-shrink-0">
                <button
                  onClick={listening ? stopListen : startListen}
                  className={cn(
                    "h-7 w-7 flex items-center justify-center rounded-lg transition text-sm",
                    listening
                      ? "bg-red-500/20 text-red-300 ring-1 ring-red-500/40"
                      : "text-slate-500 hover:text-cyan-300 hover:bg-slate-800"
                  )}
                  title="Voice input"
                >
                  🎙
                </button>
                <button
                  onClick={() => send()}
                  disabled={!input.trim() || loading}
                  className="h-7 w-7 flex items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-emerald-500 text-slate-950 text-xs font-bold shadow-[0_0_10px_rgba(34,211,238,0.5)] hover:shadow-[0_0_16px_rgba(34,211,238,0.7)] disabled:opacity-40 transition"
                >
                  ↑
                </button>
              </div>
            </div>
            <div className="text-center text-[9px] text-slate-700 mt-1.5">
              JARVIS · Tri-gate · Voice enabled · Press Enter to send
            </div>
          </div>
        </>
      )}
    </div>
  );
}

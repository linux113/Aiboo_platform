import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { io, Socket } from "socket.io-client";
import { cn } from "./utils/cn";
import api, { authH, setToken as storeToken, getToken, clearToken, API, SOCKET_URL, CV_URL, AGENT_URL } from "./utils/api";
import { logger } from "./utils/logger";
import Login from "./Login";
import TopBar from "./components/TopBar";
import DashboardModule from "./components/DashboardModule";
import SurveillanceModule from "./components/SurveillanceModule";
import IntelligenceModule from "./components/IntelligenceModule";
import AgentConsole from "./components/AgentConsole";
import SettingsModule from "./components/SettingsModule";
import AIPanel from "./components/AIPanel";
import EndpointsList from "./components/EndpointsList";
import type { Camera, Detection, Threat, AgentFinding, CorrelatedAlert, GateDecision, PseudoLock, Notification, NavId, SearchResult } from "./types";

const NAV: { id: NavId; label: string; icon: string }[] = [
  { id: "dashboard", label: "Dashboard", icon: "⌘" },
  { id: "surveillance", label: "Surveillance", icon: "👁" },
  { id: "intelligence", label: "Intelligence", icon: "🧠" },
  { id: "agent", label: "Agent Console", icon: "🤖" },
  { id: "endpoints", label: "Endpoints", icon: "📡" },
  { id: "settings", label: "Settings", icon: "⚙" },
];

function useSearch(threats: Threat[], detections: Detection[], cameras: Camera[], findings: AgentFinding[]) {
  const [q, setQ] = useState("");
  const results = useMemo(() => {
    if (!q.trim() || q.length < 2) return [];
    const lq = q.toLowerCase();
    const safe = <T,>(arr: T[]): T[] => Array.isArray(arr) ? arr : [];
    const out: SearchResult[] = [];
    safe(threats).filter(t => t.title?.toLowerCase().includes(lq) || t.source?.toLowerCase().includes(lq) || t.asset?.toLowerCase().includes(lq)).slice(0, 3).forEach(t => out.push({ type: "threat", title: t.title, sub: `${t.source} · ${t.status}`, severity: t.severity, nav: "dashboard" }));
    safe(cameras).filter(c => c.name?.toLowerCase().includes(lq) || c.location?.toLowerCase().includes(lq) || c.zone?.toLowerCase().includes(lq)).slice(0, 3).forEach(c => out.push({ type: "camera", title: c.name, sub: `${c.location} · ${c.status}`, nav: "surveillance" }));
    safe(detections).filter(d => d.label?.toLowerCase().includes(lq) || d.cameraName?.toLowerCase().includes(lq)).slice(0, 3).forEach(d => out.push({ type: "detection", title: d.label, sub: `${d.cameraName} · ${d.confidence}%`, severity: d.severity, nav: "surveillance" }));
    safe(findings).filter(f => f.summary?.toLowerCase().includes(lq) || f.agent_name?.toLowerCase().includes(lq) || f.threat_type?.toLowerCase().includes(lq)).slice(0, 3).forEach(f => out.push({ type: "finding", title: f.agent_name, sub: f.summary.substring(0, 60), severity: f.severity, nav: "agent" }));
    return out;
  }, [q, threats, detections, cameras, findings]);
  return { q, setQ, results };
}

function parseToken(token: string | null): { email?: string; name?: string; role?: string } | null {
  if (!token || token === "undefined" || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(atob(parts[1]));
  } catch {
    logger.warn("Failed to parse JWT token");
    return null;
  }
}

export default function App() {
  const [token, setTokenState] = useState<string | null>(() => {
    const stored = getToken();
    if (stored && stored !== "undefined" && parseToken(stored)) return stored;
    if (stored === "undefined") clearToken();
    return null;
  });
  const [active, setActive] = useState<NavId>("dashboard");
  const [cameras, setCameras] = useState<Camera[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [findings, setFindings] = useState<AgentFinding[]>([]);
  const [correlated, setCorrelated] = useState<CorrelatedAlert[]>([]);
  const [gateDecisions, setGateDecisions] = useState<GateDecision[]>([]);
  const [pseudoLocks, setPseudoLocks] = useState<PseudoLock[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [userName, setUserName] = useState("Akshay Upadhyay");
  const [userEmail, setUserEmail] = useState("admin@example.com");
  const [userRole, setUserRole] = useState("Admin");
  const socketRef = useRef<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [agentOnline, setAgentOnline] = useState<boolean | null>(null);
  const [cvOnline, setCvOnline] = useState<boolean | null>(null);
  const [initialLoad, setInitialLoad] = useState(true);
  const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);
  const [sources, setSources] = useState<string[]>([]);

  const addNotif = (type: "critical" | "warning" | "info", title: string, body: string) => {
    const n: Notification = { id: Date.now().toString(), type, title, body, timestamp: new Date().toISOString(), read: false };
    setNotifications(p => [n, ...p.slice(0, 49)]);
  };

  // ---- fetchAll: staggered requests with 200ms delay ----
  const fetchAll = useCallback(async () => {
    if (!token) return;
    try {
      console.log("📊 Fetching initial data (staggered)...");
      
      const requestConfigs = [
        { name: "cameras", fn: () => api.get(`${API}/cameras`).catch(() => ({ data: [] })) },
        { name: "detections", fn: () => api.get(`${API}/cameras/detections`).catch(() => ({ data: [] })) },
        { name: "threats", fn: () => api.get(`${API}/threats`).catch(() => ({ data: [] })) },
        { name: "findings", fn: () => api.get(`${API}/agent/findings`).catch(() => ({ data: [] })) },
        { name: "correlated", fn: () => api.get(`${API}/agent/correlated`).catch(() => ({ data: [] })) },
        { name: "gates", fn: () => api.get(`${API}/agent/gate-decisions`).catch(() => ({ data: [] })) },
        { name: "locks", fn: () => api.get(`${API}/agent/pseudo-locks`).catch(() => ({ data: [] })) },
        { name: "sources", fn: () => api.get(`${API}/agent/sources`).catch(() => ({ data: [] })) },
      ];

      const results = [];
      for (let i = 0; i < requestConfigs.length; i++) {
        const req = requestConfigs[i];
        try {
          console.log(`   Fetching ${req.name}...`);
          const resp = await req.fn();
          results.push(resp);
          // Small delay between requests (200ms)
          if (i < requestConfigs.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 200));
          }
        } catch (e) {
          console.error(`Error fetching ${req.name}:`, e);
          results.push({ data: [] });
        }
      }

      const extract = <T,>(resp: any, fallback: T[] = []): T[] => {
        if (Array.isArray(resp.data)) return resp.data;
        if (resp.data && Array.isArray(resp.data.data)) return resp.data.data;
        return fallback;
      };

      const [c, d, t, f, cor, gates, locks, sourcesResp] = results;
      setCameras(extract<Camera>(c));
      setDetections(extract<Detection>(d));
      setThreats(extract<Threat>(t));
      setFindings(extract<AgentFinding>(f));
      setCorrelated(extract<CorrelatedAlert>(cor));
      setGateDecisions(extract<GateDecision>(gates));
      setPseudoLocks(extract<PseudoLock>(locks));
      setSources(Array.isArray(sourcesResp.data) ? sourcesResp.data : []);
      console.log("✅ Initial data loaded");
    } catch (e) {
      logger.error("Fetch error", e);
    } finally {
      setInitialLoad(false);
    }
  }, [token]);

  // ---- Main effect: socket + initial fetch ----
  useEffect(() => {
    if (!token) return;
    const payload = parseToken(token);
    if (payload?.email) setUserEmail(payload.email);
    if (payload?.name) setUserName(payload.name);
    if (payload?.role) setUserRole(payload.role);
    fetchAll();

    // ---- Connect to backend WebSocket (stable) ----
    console.log("🔌 Connecting to backend socket at", SOCKET_URL);
    const socket = io(SOCKET_URL, {
      auth: { token },
      transports: ["websocket"],
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      timeout: 10000,
      forceNew: false, // ✅ Reuse existing connection if possible
    });
    socketRef.current = socket;

    socket.on("connect", () => {
      setConnected(true);
      console.log("✅ Socket connected to backend");
    });
    socket.on("disconnect", (reason) => {
      setConnected(false);
      console.log("❌ Socket disconnected:", reason);
      // Do NOT fetch here – let reconnection handle it
    });
    socket.on("connect_error", (err) => {
      console.error("Socket connection error:", err.message);
    });

    socket.emit("init");
    socket.on("init:data", (data: { cameras?: Camera[]; detections?: Detection[]; threats?: Threat[] }) => {
      if (data.cameras?.length) setCameras(data.cameras);
      if (data.detections?.length) setDetections(data.detections);
      if (data.threats?.length) setThreats(data.threats);
    });
    socket.on("detection:new", (d: Detection) => {
      setDetections(p => [d, ...p.slice(0, 199)]);
      if (d.type.includes("weapon")) addNotif("critical", "Weapon Detected", `${d.label} at ${d.cameraName} — ${d.confidence}% confidence`);
      else if (d.type.includes("watchlist")) addNotif("critical", "Watchlist Match", `Face matched at ${d.cameraName}`);
    });
    socket.on("threat:new", (t: Threat) => { setThreats(p => [t, ...p.slice(0, 99)]); addNotif(t.severity === "critical" ? "critical" : "warning", `New Threat: ${t.title}`, `Source: ${t.source} · Asset: ${t.asset}`); });
    socket.on("camera:added", (c: Camera) => { setCameras(p => [c, ...p]); addNotif("info", "Camera Added", `${c.name} added to surveillance grid`); });
    socket.on("camera:updated", (c: Camera) => setCameras(p => p.map(x => x._id === c._id ? c : x)));
    socket.on("camera:deleted", ({ id }: { id: string }) => setCameras(p => p.filter(c => c._id !== id)));

    // ---- LIVE AGENT FINDINGS (from remote agents via backend) ----
    socket.on("agent:finding", (f: AgentFinding) => {
      console.log("🔥 Live alert received from agent:", f);
      setFindings(p => [f, ...p.slice(0, 199)]);
      if (f.severity === "critical") {
        addNotif("critical", `Critical: ${f.agent_name}`, f.summary.substring(0, 80));
      }
      // Auto-refresh sources if new endpoint appears
      const newSource = f.source;
      if (newSource && typeof newSource === 'string' && !sources.includes(newSource)) {
        setSources(prev => [...prev, newSource]);
      }
    });

    socket.on("agent:correlated", (a: CorrelatedAlert) => {
      setCorrelated(p => [a, ...p.slice(0, 99)]);
      addNotif("critical", "Correlated Attack Detected", a.description.replace("[CORRELATED] ", "").substring(0, 80));
    });
    socket.on("agent:gate", (g: GateDecision) => setGateDecisions(p => [g, ...p.slice(0, 199)]));
    socket.on("agent:pseudo-lock", (l: PseudoLock) => {
      setPseudoLocks(p => {
        const e = p.find(x => x.lock_id === l.lock_id);
        return e ? p.map(x => x.lock_id === l.lock_id ? l : x) : [l, ...p];
      });
      addNotif("warning", "Pseudo-Lock Applied", `Endpoint isolation active: ${l.lock_id}`);
    });
    socket.on("agent:pseudo-lock-restore", ({ lock_id }: { lock_id: string }) =>
      setPseudoLocks(p => p.map(l => l.lock_id === lock_id ? { ...l, active: false } : l))
    );

    // Fallback bridge event (if any)
    socket.on("agent_alert", (data: any) => {
      console.log("📨 Agent alert via bridge:", data);
      if (data.agent_name) {
        setFindings(prev => [data, ...prev.slice(0, 199)]);
        if (data.severity === "critical") {
          addNotif("critical", `Critical: ${data.agent_name}`, data.summary?.substring(0, 80) || "Alert from agent");
        }
      }
    });

    // ❌ Removed the setInterval fallback – socket reconnection handles it

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [token]); // ✅ Only depend on token (sources removed)

  // ---- Health checks for Agent and CV services ----
  useEffect(() => {
    if (!token) return;
    const check = async () => {
      try { await api.get(`${API}/agent/findings`); } catch { return; }
      try { await api.get(`${AGENT_URL}/health`, { timeout: 2000 }); setAgentOnline(true); } catch { setAgentOnline(false); }
      try { await api.get(`${CV_URL}/health`, { timeout: 2000 }); setCvOnline(true); } catch { setCvOnline(false); }
    };
    check();
    const hiv = setInterval(check, 30000);
    return () => clearInterval(hiv);
  }, [token]);

  const restoreLock = async (lockId: string) => {
    try {
      await api.post(`${API}/agent/pseudo-locks/${lockId}/restore`, {}, authH());
      setPseudoLocks(p => p.map(l => l.lock_id === lockId ? { ...l, active: false } : l));
    } catch {
      addNotif("warning", "Failed to restore lock", "Could not restore pseudo-lock");
    }
  };

  const activeLocks = pseudoLocks.filter(l => l.active).length;
  const unreadNotifs = notifications.filter(n => !n.read).length;
  const searchState = useSearch(threats, detections, cameras, findings);

  const handleLogin = (t: string) => {
    if (t && t !== "undefined") {
      storeToken(t);
      setTokenState(t);
    }
  };

  const handleLogout = () => {
    clearToken();
    socketRef.current?.disconnect();
    setTokenState(null);
  };

  if (!token) return <Login onLogin={handleLogin} />;

  return (
    <div className="flex min-h-screen flex-col bg-[#020617] text-slate-50">
      <TopBar
        active={active}
        setActive={setActive}
        notifications={notifications}
        onReadNotif={(id) => setNotifications(p => p.map(n => n.id === id ? { ...n, read: true } : n))}
        onClearNotifs={() => setNotifications([])}
        onLogout={handleLogout}
        userName={userName}
        searchState={searchState}
        onSearchNav={(nav) => setActive(nav)}
      />
      <main className="relative flex-1 overflow-hidden bg-gradient-to-br from-[#020617] via-slate-950 to-slate-950/90" style={{ height: "calc(100vh - 56px)" }}>
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.08),transparent_60%),radial-gradient(circle_at_bottom,_rgba(15,118,110,0.15),transparent_60%)] opacity-80" />
        <div className="relative z-10 flex h-full flex-col">
          <div className="flex items-center justify-between px-5 pt-3 pb-2 text-[11px] flex-shrink-0">
            <div className="flex items-center gap-2">
              <span className="rounded-full border border-slate-700/80 bg-slate-900/80 px-2.5 py-0.5 text-[10px] uppercase tracking-[0.16em] text-slate-400">
                {active === "dashboard" ? "Command & Control" : active === "surveillance" ? "Surveillance Intelligence" : active === "intelligence" ? "Intelligence & Identity" : active === "agent" ? "Agent Console · Tri-Gate" : active === "endpoints" ? "Endpoints · Distributed Agents" : "Platform Settings"}
              </span>
              <span className="hidden text-[10px] text-slate-500 md:inline">Live · Tri-Gate · YOLOv8 · JARVIS</span>
            </div>
            <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
              {activeLocks > 0 && <span className="rounded-full border border-amber-500/50 bg-amber-500/10 px-2 py-0.5 text-amber-300 font-medium animate-pulse">{activeLocks} Lock{activeLocks > 1 ? "s" : ""} Active</span>}
              {unreadNotifs > 0 && <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-cyan-300">{unreadNotifs} new</span>}
              <span title="Socket" className={cn("flex items-center gap-1 rounded-full border px-1.5 py-0.5", connected ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300" : "border-red-500/40 bg-red-500/10 text-red-300")}>
                <span className={cn("h-1.5 w-1.5 rounded-full", connected ? "bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.9)]" : "bg-red-400")} />{connected ? "Live" : "Off"}
              </span>
              {agentOnline !== null && <span title="Agent Service" className={cn("rounded-full border px-1.5 py-0.5", agentOnline ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-amber-500/30 bg-amber-500/10 text-amber-300")}>Agent {agentOnline ? "✓" : "?"}</span>}
              {cvOnline !== null && <span title="CV Service" className={cn("rounded-full border px-1.5 py-0.5", cvOnline ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-amber-500/30 bg-amber-500/10 text-amber-300")}>CV {cvOnline ? "✓" : "?"}</span>}
            </div>
          </div>
          <div className="flex-1 overflow-auto px-5 pb-4 pt-1 min-h-0">
            {initialLoad ? (
              <div className="flex h-full items-center justify-center">
                <div className="flex flex-col items-center gap-3">
                  <svg className="h-8 w-8 animate-spin text-cyan-400" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  <span className="text-sm text-slate-500">Loading platform data...</span>
                </div>
              </div>
            ) : (
              <>
                {active === "dashboard" && <DashboardModule threats={threats} detections={detections} cameras={cameras} findings={findings} correlated={correlated} activeLocks={activeLocks} sources={sources} />}
                {active === "surveillance" && <SurveillanceModule cameras={cameras} detections={detections} onCamsChange={setCameras} />}
                {active === "intelligence" && <IntelligenceModule detections={detections} cameras={cameras} findings={findings} />}
                {active === "agent" && <AgentConsole findings={findings} correlated={correlated} gateDecisions={gateDecisions} pseudoLocks={pseudoLocks} onRestoreLock={restoreLock} onSendTestEvent={() => setTimeout(fetchAll, 2000)} />}
                {active === "endpoints" && (
                  <EndpointsList
                    onSelectEndpoint={setSelectedEndpoint}
                    selectedEndpoint={selectedEndpoint}
                  />
                )}
                {active === "settings" && <SettingsModule userName={userName} userEmail={userEmail} userRole={userRole} />}
              </>
            )}
          </div>
        </div>
        <AIPanel dets={detections} threats={threats} findings={findings} correlated={correlated} />
      </main>
      <nav className="md:hidden fixed inset-x-0 bottom-0 z-30 flex h-12 items-center justify-around border-t border-slate-800/80 bg-black/90 backdrop-blur">
        {NAV.map(n => <button key={n.id} onClick={() => setActive(n.id)} className={cn("flex flex-1 flex-col items-center gap-0.5 py-2 text-[9px]", active === n.id ? "text-cyan-300" : "text-slate-500")}><span>{n.icon}</span>{n.label.split(" ")[0]}</button>)}
      </nav>
    </div>
  );
}
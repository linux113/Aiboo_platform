import { useState, useEffect, useRef, useCallback, useMemo, lazy, Suspense } from "react";
import { io, Socket } from "socket.io-client";
import { cn } from "./utils/cn";
import api, { authH, setToken as storeToken, getToken, clearToken, API, SOCKET_URL, waitForCommand, apiErrorMessage } from "./utils/api";
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
// charts library is big: load the Executive screen only when it is opened
const ExecutiveModule = lazy(() => import("./components/ExecutiveModule"));
import AlertsModule from "./components/AlertsModule";
import ReportsModule from "./components/ReportsModule";
import type { Camera, Detection, Threat, AgentFinding, CorrelatedAlert, GateDecision, PseudoLock, Notification, NavId, SearchResult, ActionRecord } from "./types";

// ---- Endpoint type (with active flag) ----
export interface EndpointInfo {
  source: string;
  lastSeen: string;
  active: boolean;
}

// ---- Safety cap so a long-running dashboard doesn't grow unbounded ----
const MAX_ACTIONS_IN_MEMORY = 2000;

const NAV: { id: NavId; label: string; icon: string }[] = [
  { id: "dashboard", label: "Dashboard", icon: "⌘" },
  { id: "executive", label: "Executive", icon: "📈" },
  { id: "alerts", label: "Alerts", icon: "🚨" },
  { id: "reports", label: "Reports", icon: "📄" },
  { id: "surveillance", label: "Surveillance", icon: "👁" },
  { id: "intelligence", label: "Intelligence", icon: "🧠" },
  { id: "agent", label: "Agent Console", icon: "🤖" },
  { id: "endpoints", label: "Endpoints", icon: "📡" },
  { id: "settings", label: "Settings", icon: "⚙" },
];

// ---- Merge incoming action records with existing ones (dedupe by id) ----
function mergeActions(existing: ActionRecord[], incoming: ActionRecord[]): ActionRecord[] {
  const byId = new Map<string, ActionRecord>();
  for (const r of existing) byId.set(r.id, r);
  for (const r of incoming) {
    // Incoming wins, but merge so we keep any fields the server omitted
    byId.set(r.id, { ...(byId.get(r.id) || {}), ...r } as ActionRecord);
  }
  return Array.from(byId.values())
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, MAX_ACTIONS_IN_MEMORY);
}

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
  // lock ids already shown, so updates (e.g. "restoring") don't re-notify
  const seenLocksRef = useRef<Set<string>>(new Set());
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [userName, setUserName] = useState("Akshay Upadhyay");
  const [userEmail, setUserEmail] = useState("admin@example.com");
  const [userRole, setUserRole] = useState("Admin");
  const [mustChangePw, setMustChangePw] = useState(() => localStorage.getItem("aiboo_must_change_pw") === "1");
  const socketRef = useRef<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [agentOnline, setAgentOnline] = useState<boolean | null>(null);
  const [agentNames, setAgentNames] = useState<string[]>([]);
  const [cvOnline, setCvOnline] = useState<boolean | null>(null);
  const [initialLoad, setInitialLoad] = useState(true);
  const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);

  // ---- CHANGED: sources now stores endpoint objects with active flag ----
  const [sources, setSources] = useState<EndpointInfo[]>([]);

  // ---- NEW: response actions for the "Isolation & Termination" tab ----
  const [actions, setActions] = useState<ActionRecord[]>([]);
  const [actionsLoading, setActionsLoading] = useState(false);
  // bumps on every alert:new / alert:updated so Alerts / Executive reload
  const [alertTick, setAlertTick] = useState(0);
  const [openAlertCount, setOpenAlertCount] = useState(0);
  // a burst of alerts (e.g. 30 wrong passwords) causes ONE reload, not 30
  const alertTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const bumpAlerts = useCallback(() => {
    if (alertTimerRef.current) return;
    alertTimerRef.current = setTimeout(() => {
      alertTimerRef.current = null;
      setAlertTick(t => t + 1);
    }, 3000);
  }, []);

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
        // ---- CHANGED: fetch /endpoints instead of /sources ----
        { name: "endpoints", fn: () => api.get(`${API}/agent/endpoints`).catch(() => ({ data: [] })) },
        // ---- NEW: fetch response actions ----
        { name: "actions", fn: () => api.get(`${API}/agent/actions?limit=500`).catch(() => ({ data: { actions: [] } })) },
      ];

      const results = [];
      for (let i = 0; i < requestConfigs.length; i++) {
        const req = requestConfigs[i];
        try {
          console.log(`   Fetching ${req.name}...`);
          const resp = await req.fn();
          results.push(resp);
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

      const [c, d, t, f, cor, gates, locks, endpointsResp, actionsResp] = results;
      setCameras(extract<Camera>(c));
      setDetections(extract<Detection>(d));
      setThreats(extract<Threat>(t));
      setFindings(extract<AgentFinding>(f));
      setCorrelated(extract<CorrelatedAlert>(cor));
      setGateDecisions(extract<GateDecision>(gates));
      const lockList = extract<PseudoLock>(locks);
      lockList.forEach(l => seenLocksRef.current.add(l.lock_id));
      setPseudoLocks(lockList);

      // ---- CHANGED: parse endpoint objects ----
      const endpointList: EndpointInfo[] = Array.isArray(endpointsResp.data)
        ? endpointsResp.data
        : [];
      setSources(endpointList);

      // ---- NEW: merge fetched actions ----
      const fetchedActions: ActionRecord[] = Array.isArray(actionsResp?.data?.actions)
        ? actionsResp.data.actions
        : Array.isArray(actionsResp?.data)
        ? actionsResp.data
        : [];
      if (fetchedActions.length) {
        setActions(prev => mergeActions(prev, fetchedActions));
      }

      console.log("✅ Initial data loaded");
    } catch (e) {
      logger.error("Fetch error", e);
    } finally {
      setInitialLoad(false);
    }
  }, [token]);

  // ---- NEW: dedicated refresh for just the actions list ----
  const refreshActions = useCallback(async () => {
    if (!token) return;
    setActionsLoading(true);
    try {
      const res = await api.get(`${API}/agent/actions?limit=500`);
      const fetched: ActionRecord[] = Array.isArray(res?.data?.actions)
        ? res.data.actions
        : Array.isArray(res?.data)
        ? res.data
        : [];
      setActions(prev => mergeActions(prev, fetched));
    } catch (err) {
      console.warn("Failed to refresh actions", err);
    } finally {
      setActionsLoading(false);
    }
  }, [token]);

  // ---- Retry an action: re-dispatch it to the agent over the command channel ----
  // (Previously this only re-posted a "pending" record to the backend, so
  // nothing was ever executed on the endpoint.)
  const handleRetryAction = useCallback(async (record: ActionRecord) => {
    const endpoint = record.endpoint || record.source;
    const meta = (record.metadata || {}) as Record<string, unknown>;
    const target = String(
      meta.pid ?? meta.src_ip ?? meta.user_id ?? meta.device_id ?? record.target ?? ""
    );
    const params: Record<string, unknown> = { retried_from: record.id };
    if (meta.pid !== undefined) params.pid = meta.pid;

    try {
      const res = await api.post(`${API}/agent/commands`, {
        endpoint_id: endpoint,
        action: record.action,
        target,
        params,
      }, authH());
      addNotif(
        "info",
        "Retry Dispatched",
        `${record.action} → ${target} sent to ${endpoint} (cmd ${res?.data?.cmd_id || "?"})`,
      );
    } catch (err: any) {
      console.error("Retry failed", err);
      addNotif(
        "warning",
        "Retry Failed",
        err?.response?.data?.error || `Could not re-dispatch ${record.action} to ${endpoint}`,
      );
    }
  }, []);

  // ---- Main effect: socket + initial fetch ----
  useEffect(() => {
    if (!token) return;
    const payload = parseToken(token);
    if (payload?.email) setUserEmail(payload.email);
    if (payload?.name) setUserName(payload.name);
    if (payload?.role) setUserRole(payload.role);
    fetchAll();

    console.log("🔌 Connecting to backend socket at", SOCKET_URL);
    const socket = io(SOCKET_URL, {
      auth: { token },
      transports: ["websocket"],
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      timeout: 10000,
      forceNew: false,
    });
    socketRef.current = socket;

    socket.on("connect", () => {
      setConnected(true);
      console.log("✅ Socket connected to backend");
    });
    socket.on("disconnect", (reason) => {
      setConnected(false);
      console.log("❌ Socket disconnected:", reason);
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

    // ---- LIVE AGENT FINDINGS ----
    socket.on("agent:finding", (f: AgentFinding) => {
      console.log("🔥 Live alert received from agent:", f);
      setFindings(p => [f, ...p.slice(0, 199)]);
      if (f.severity === "critical") {
        addNotif("critical", `Critical: ${f.agent_name}`, f.summary.substring(0, 80));
      }
      // ---- CHANGED: auto-add new endpoint as an "active" object ----
      const newSource = (f as any).source;
      if (newSource && typeof newSource === "string") {
        setSources(prev => {
          const exists = prev.find(ep => ep.source === newSource);
          if (exists) {
            // Update lastSeen to now (agent is active)
            return prev.map(ep =>
              ep.source === newSource
                ? { ...ep, lastSeen: new Date().toISOString(), active: true }
                : ep
            );
          }
          return [
            { source: newSource, lastSeen: new Date().toISOString(), active: true },
            ...prev,
          ];
        });
      }
    });

    socket.on("agent:correlated", (a: CorrelatedAlert) => {
      // a growing incident is re-sent with the same alert_id: replace, don't duplicate
      setCorrelated(p => [a, ...p.filter(x => x.alert_id !== a.alert_id).slice(0, 99)]);
      addNotif(a.severity === "critical" ? "critical" : "warning", "Attack chain detected", (a.description || "").replace("[CORRELATED] ", "").substring(0, 80));
    });
    socket.on("agent:gate", (g: GateDecision) => setGateDecisions(p => [g, ...p.slice(0, 199)]));
    // ---- Alert management (backend/services/alertStore.js) ----
    socket.on("alert:new", (a: { title?: string; severity?: string; source?: string }) => {
      bumpAlerts();
      setOpenAlertCount(c => c + 1);
      if (a.severity === "critical" || a.severity === "high") {
        addNotif(a.severity === "critical" ? "critical" : "warning", `New ${a.severity} alert`, `${a.title || "Alert"}${a.source ? ` · ${a.source}` : ""}`);
      }
    });
    socket.on("alert:updated", bumpAlerts);
    socket.on("agent:compliance", bumpAlerts);
    socket.on("agent:pseudo-lock", (l: PseudoLock) => {
      const isNew = !seenLocksRef.current.has(l.lock_id);
      seenLocksRef.current.add(l.lock_id);
      setPseudoLocks(p => {
        const e = p.find(x => x.lock_id === l.lock_id);
        return e ? p.map(x => x.lock_id === l.lock_id ? { ...x, ...l } : x) : [l, ...p];
      });
      if (isNew && l.active && !l.restoring) {
        addNotif("warning", "Pseudo-Lock Applied",
          l.decoy_port ? `Decoy port ${l.decoy_port} opened on ${l.source || "endpoint"} (${l.lock_id})` : `Endpoint isolation active: ${l.lock_id}`);
      }
    });
    socket.on("agent:pseudo-lock-restore", ({ lock_id, restored_at, message }: { lock_id: string; restored_at?: string; message?: string }) =>
      setPseudoLocks(p => p.map(l => l.lock_id === lock_id
        ? { ...l, active: false, restoring: false, restored_at: restored_at || new Date().toISOString(), restore_message: message || l.restore_message }
        : l))
    );
    socket.on("war-room:opened", (w: { opened_by?: string; note?: string }) =>
      addNotif("critical", "War Room Opened", `${w.opened_by || "An analyst"} opened a war room${w.note ? `: ${w.note}` : ""}`)
    );

    // ---- NEW: live response actions for Isolation & Termination tab ----
    socket.on("agent:action", (a: ActionRecord) => {
      setActions(prev => mergeActions(prev, [a]));

      // Emit a notification for high-impact / failed actions
      if (a.status === "failed") {
        addNotif("warning", `Action Failed: ${a.action_label || a.action}`, a.error || a.details || a.target || "");
      } else if (a.status === "active" && a.action === "pseudo_lock") {
        addNotif("info", "Pseudo-Lock Active", a.details || `Decoy deployed for ${a.target}`);
      }
    });

    socket.on("agent_alert", (data: any) => {
      console.log("📨 Agent alert via bridge:", data);
      if (data.agent_name) {
        setFindings(prev => [data, ...prev.slice(0, 199)]);
        if (data.severity === "critical") {
          addNotif("critical", `Critical: ${data.agent_name}`, data.summary?.substring(0, 80) || "Alert from agent");
        }
      }
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [token]);

  // ---- NEW: refresh endpoints list every 30 seconds so active/offline status updates ----
  useEffect(() => {
    if (!token) return;
    const refresh = async () => {
      try {
        const resp = await api.get(`${API}/agent/endpoints`).catch(() => ({ data: [] }));
        const endpointList: EndpointInfo[] = Array.isArray(resp.data) ? resp.data : [];
        setSources(endpointList);
      } catch (e) {
        // silent
      }
    };
    const iv = setInterval(refresh, 30000);
    return () => clearInterval(iv);
  }, [token]);

  // ---- Alerts that still need action (badge on the Alerts tab) ----
  useEffect(() => {
    if (!token) return;
    let stop = false;
    const t = setTimeout(async () => {
      try {
        const r = await api.get(`${API}/alerts`, { params: { status: "open,acknowledged", limit: 1, days: 365 } });
        if (!stop) setOpenAlertCount(Number(r.data?.total) || 0);
      } catch { /* backend without alert routes - keep 0 */ }
    }, 800);
    return () => { stop = true; clearTimeout(t); };
  }, [token, alertTick]);

  // ---- NEW: fallback poll for actions every 5s when socket is offline ----
  useEffect(() => {
    if (!token || connected) return;
    const iv = setInterval(refreshActions, 5000);
    return () => clearInterval(iv);
  }, [token, connected, refreshActions]);

  // ---- Health checks for Agent and CV services ----
  useEffect(() => {
    if (!token) return;
    const check = async () => {
      try { await api.get(`${API}/agent/findings`); } catch { return; }
      // Ask the backend which agents are connected on the command channel.
      // (The old check called localhost:8001 from the browser, which is the
      // wrong port and never works when the agent is on another PC.)
      try {
        const r = await api.get(`${API}/agent/agents-online`, { timeout: 4000 });
        const list: { endpointId?: string }[] = Array.isArray(r.data?.agents) ? r.data.agents : [];
        setAgentNames(list.map(a => a.endpointId || "?"));
        setAgentOnline(list.length > 0);
      } catch { setAgentNames([]); setAgentOnline(false); }
      // Camera service is optional; the backend checks it for us.
      try {
        const r = await api.get(`${API}/dashboard/services`, { timeout: 5000 });
        setCvOnline(!!r.data?.cv?.online);
      } catch { setCvOnline(false); }
    };
    check();
    const hiv = setInterval(check, 30000);
    return () => clearInterval(hiv);
  }, [token]);

  // Restore = ask the agent that opened the decoy to close the real port.
  // The lock only flips to RESTORED once the agent confirms.
  const restoreLock = async (lockId: string) => {
    const setLock = (patch: Partial<PseudoLock>) =>
      setPseudoLocks(p => p.map(l => l.lock_id === lockId ? { ...l, ...patch } : l));
    setLock({ restoring: true });
    try {
      const res = await api.post(`${API}/agent/pseudo-locks/${lockId}/restore`, {}, authH());
      const data = res.data || {};
      if (data.already_restored) {
        setLock({ active: false, restoring: false });
        return;
      }
      if (!data.dispatched) {
        // agent offline: backend cleared it and explained why
        setLock({ active: false, restoring: false, restored_at: new Date().toISOString(), restore_message: data.note });
        addNotif("warning", "Lock cleared on dashboard only", data.note || "Agent not connected");
        return;
      }
      const outcome = await waitForCommand(data.cmd_id);
      if (outcome.status === "executed") {
        const msg = String(outcome.result?.message || "Decoy port closed");
        setLock({ active: false, restoring: false, restored_at: new Date().toISOString(), restore_message: msg });
        addNotif("info", "Pseudo-Lock Restored", `${lockId}: ${msg}`);
      } else if (outcome.status === "failed") {
        setLock({ restoring: false });
        addNotif("warning", "Restore failed", outcome.error || "Agent could not close the decoy");
      } else {
        setLock({ restoring: false });
        addNotif("warning", "Restore pending", `No answer from ${data.endpoint} within 20s - check the agent window`);
      }
    } catch (e) {
      setLock({ restoring: false });
      addNotif("warning", "Failed to restore lock", apiErrorMessage(e, "Could not restore pseudo-lock"));
    }
  };

  const activeLocks = pseudoLocks.filter(l => l.active).length;
  // viewers can look but not change alerts (backend enforces the same rule)
  const canEdit = ["admin", "analyst"].includes(String(userRole || "").toLowerCase());
  const unreadNotifs = notifications.filter(n => !n.read).length;
  const searchState = useSearch(threats, detections, cameras, findings);

  const handleLogin = (t: string) => {
    if (t && t !== "undefined") {
      storeToken(t);
      setTokenState(t);
      setMustChangePw(localStorage.getItem("aiboo_must_change_pw") === "1");
    }
  };

  const handleLogout = () => {
    clearToken();
    localStorage.removeItem("aiboo_must_change_pw");
    setMustChangePw(false);
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
        openAlerts={openAlertCount}
      />
      <main className="relative flex-1 overflow-hidden bg-gradient-to-br from-[#020617] via-slate-950 to-slate-950/90" style={{ height: "calc(100vh - 56px)" }}>
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.08),transparent_60%),radial-gradient(circle_at_bottom,_rgba(15,118,110,0.15),transparent_60%)] opacity-80" />
        <div className="relative z-10 flex h-full flex-col">
          {mustChangePw && (
            <div className="mx-5 mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-2 text-xs text-red-200 flex-shrink-0">
              <span>⚠️ You are logged in with a <b>default password</b>. Anyone who knows it can log in. Please change it now.</span>
              <button
                onClick={() => setActive("settings")}
                className="rounded-lg border border-red-400/50 bg-red-500/20 px-3 py-1 font-semibold text-red-100 hover:bg-red-500/30"
              >
                Change password
              </button>
            </div>
          )}
          <div className="flex items-center justify-between px-5 pt-3 pb-2 text-[11px] flex-shrink-0">
            <div className="flex items-center gap-2">
              <span className="rounded-full border border-slate-700/80 bg-slate-900/80 px-2.5 py-0.5 text-[10px] uppercase tracking-[0.16em] text-slate-400">
                {active === "dashboard" ? "Command & Control" : active === "executive" ? "Executive Dashboard · Trends" : active === "alerts" ? "Alert Management" : active === "reports" ? "Reports · Compliance" : active === "surveillance" ? "Surveillance Intelligence" : active === "intelligence" ? "Intelligence & Identity" : active === "agent" ? "Agent Console · Tri-Gate" : active === "endpoints" ? "Endpoints · Distributed Agents" : "Platform Settings"}
              </span>
              <span className="hidden text-[10px] text-slate-500 md:inline">Live · Tri-Gate · YOLOv8 · JARVIS</span>
            </div>
            <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
              {activeLocks > 0 && <span className="rounded-full border border-amber-500/50 bg-amber-500/10 px-2 py-0.5 text-amber-300 font-medium animate-pulse">{activeLocks} Lock{activeLocks > 1 ? "s" : ""} Active</span>}
              {unreadNotifs > 0 && <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-cyan-300">{unreadNotifs} new</span>}
              <span title="Socket" className={cn("flex items-center gap-1 rounded-full border px-1.5 py-0.5", connected ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300" : "border-red-500/40 bg-red-500/10 text-red-300")}>
                <span className={cn("h-1.5 w-1.5 rounded-full", connected ? "bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.9)]" : "bg-red-400")} />{connected ? "Live" : "Off"}
              </span>
              {agentOnline !== null && <span title={agentOnline ? `Connected agents: ${agentNames.join(", ")}` : "No agent connected to the backend"} className={cn("rounded-full border px-1.5 py-0.5", agentOnline ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-amber-500/30 bg-amber-500/10 text-amber-300")}>{agentOnline ? `Agent${agentNames.length > 1 ? `s ${agentNames.length}` : ""} ✓` : "Agent ✗"}</span>}
              {cvOnline !== null && <span title={cvOnline ? "Camera (CV) service running" : "Camera (CV) service not running - optional, only needed for cameras"} className={cn("rounded-full border px-1.5 py-0.5", cvOnline ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-slate-600/40 bg-slate-800/40 text-slate-400")}>{cvOnline ? "CV ✓" : "CV off"}</span>}
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
                {active === "dashboard" && <DashboardModule threats={threats} detections={detections} cameras={cameras} findings={findings} correlated={correlated} gateDecisions={gateDecisions} activeLocks={activeLocks} sources={sources} onNotify={addNotif} />}
                {active === "executive" && (
                  <Suspense fallback={<div className="py-10 text-center text-sm text-slate-500">Loading charts…</div>}>
                    <ExecutiveModule refreshTick={alertTick} onNavigate={setActive} onNotify={addNotif} />
                  </Suspense>
                )}
                {active === "alerts" && <AlertsModule canEdit={canEdit} userName={userName} refreshTick={alertTick} onNotify={addNotif} />}
                {active === "reports" && <ReportsModule refreshTick={alertTick} onNotify={addNotif} />}
                {active === "surveillance" && <SurveillanceModule cameras={cameras} detections={detections} onCamsChange={setCameras} />}
                {active === "intelligence" && <IntelligenceModule detections={detections} cameras={cameras} findings={findings} />}
                {active === "agent" && (
                  <AgentConsole
                    findings={findings}
                    correlated={correlated}
                    gateDecisions={gateDecisions}
                    pseudoLocks={pseudoLocks}
                    actions={actions}
                    actionsLoading={actionsLoading}
                    onRestoreLock={restoreLock}
                    onSendTestEvent={() => setTimeout(fetchAll, 2000)}
                    onRefreshActions={refreshActions}
                    onRetryAction={handleRetryAction}
                  />
                )}
                {active === "endpoints" && (
                  <EndpointsList
                    onSelectEndpoint={setSelectedEndpoint}
                    selectedEndpoint={selectedEndpoint}
                  />
                )}
                {active === "settings" && (
                  <SettingsModule
                    userName={userName}
                    userEmail={userEmail}
                    userRole={userRole}
                    mustChangePassword={mustChangePw}
                    onPasswordChanged={() => {
                      localStorage.removeItem("aiboo_must_change_pw");
                      setMustChangePw(false);
                    }}
                  />
                )}
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
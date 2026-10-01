// frontend/src/types.ts

export type NavId =
  | "dashboard"
  | "surveillance"
  | "intelligence"
  | "agent"
  | "endpoints"
  | "settings";

// ---- Severity type (reused across all record types) ----
export type Severity = "low" | "medium" | "high" | "critical";

export interface Camera {
  _id: string;
  name: string;
  location: string;
  zone: string;
  status: "online" | "offline" | "error";
  stream_url?: string;
  rtsp_url?: string;
  // fields from backend/models/Camera.js
  streamUrl?: string;
  enabled?: boolean;
  type?: "ip" | "rtsp" | "mobile" | "usb";
  resolution?: string;
  fps?: number;
  detectionEnabled?: boolean;
  metadata?: Record<string, unknown>;
}

export interface Detection {
  _id: string;
  cameraId: string;
  cameraName: string;
  label: string;
  type: string;
  confidence: number;
  severity: Severity;
  timestamp: string;
  image_url?: string;
  metadata?: Record<string, unknown>;
}

export interface Threat {
  _id: string;
  title: string;
  source: string;
  asset: string;
  severity: Severity;
  status: "open" | "investigating" | "resolved";   // backend/models/Threat.js
  timestamp: string;
  description?: string;
  actions?: string[];
  metadata?: Record<string, unknown>;
}

export interface AgentFinding {
  id: string;
  agent_name: string;
  event_id: string;
  threat_type: string;
  severity: Severity;
  confidence: number;
  summary: string;
  actions: string[];
  metadata: Record<string, unknown>;
  timestamp: string;
  source?: string;
}

export interface CorrelatedAlert {
  alert_id: string;
  threat_type: string;
  severity: Severity;
  confidence: number;
  description: string;
  findings: AgentFinding[];
  actions: string[];
  timestamp: string;
}

// ---- TriGate (Gate 1 Trust -> Gate 2 Intent -> Gate 3 Impact) ----
export interface TriGateFactor {
  points: number;
  text: string;
}

export interface TriGateScore {
  score: number;          // 0-100
  level: string;          // trusted/uncertain/untrusted, malicious/suspicious/..., severe/moderate/limited
  factors: TriGateFactor[];
}

export interface TriGateRecommendation {
  action: string;         // remote action (block_access, revoke_identity, isolate_asset) or "manual"/"log"/"notify_security"
  target: string;
  text: string;
}

export interface TriGateResult {
  context?: {
    pattern: string;
    pattern_label: string;
    mitre_id?: string;
    mitre_name?: string;
    description?: string;
    entity?: string;
    subject?: string;
    src_ip?: string;
    event_id_raw?: number | string | null;
    local_time?: string;
    test_event?: boolean;
  };
  trust?: TriGateScore;
  intent?: TriGateScore & { mitre?: { id?: string; name?: string } };
  impact?: TriGateScore & { importance?: Importance };
  risk?: { score: number; level: string };
  recommended?: TriGateRecommendation[];
  pattern?: string;
  entity?: string;
  subject?: string;
}

export type Importance = "low" | "normal" | "high" | "critical";

export interface GateDecision {
  gate: number;
  gate_label: string;
  event_id: string;
  threat_type: string;
  severity: Severity;
  verdict: "pass" | "hold" | "block" | "escalate";
  confidence: number;
  reason: string;
  actions: string[];
  timestamp: string;
  source?: string;
  metadata?: { trigate?: TriGateResult; [key: string]: unknown };
  feedback?: {
    kind: "false_alarm" | "confirmed";
    cmd_id?: string;
    by?: string;
    at?: string;
    status?: string;
    error?: string | null;
  };
}

export interface PseudoLock {
  lock_id: string;
  event_id: string;
  agent: string;
  severity: Severity;
  summary: string;
  active: boolean;
  locked_at: string;
  restored_at?: string;
  /** endpoint (agent) that opened the decoy */
  source?: string;
  decoy_port?: number | null;
  decoy_endpoint?: string;
  original_endpoint?: string;
  /** restore command sent, waiting for the agent to close the port */
  restoring?: boolean;
  restore_message?: string;
  hits?: number;
}

export interface Notification {
  id: string;
  type: "critical" | "warning" | "info";
  title: string;
  body: string;
  timestamp: string;
  read: boolean;
}

export interface SearchResult {
  type: "threat" | "camera" | "detection" | "finding";
  title: string;
  sub: string;
  severity?: string;
  nav: NavId;
}

// ============================================================
//  NEW: Response Action types (Isolation & Termination tab)
// ============================================================

/**
 * Lifecycle status of a response action:
 *   - pending  ⏳  Dispatched to the engine, not yet completed
 *   - success  ✅  Completed successfully
 *   - failed   ❌  Could not be completed (see `error`)
 *   - active   🔴  Ongoing containment (e.g. pseudo-lock, JIT grant)
 */
export type ActionStatus = "pending" | "success" | "failed" | "active";

/**
 * Known action identifiers. Extendable with a string fallback so
 * the UI never breaks if the agent starts emitting new action types.
 */
export type ActionType =
  | "terminate_process"
  | "isolate_asset"
  | "quarantine_device"
  | "pseudo_lock"
  | "revoke_identity"
  | "block_access"
  | "lock_zone"
  | "force_logout"
  | "quarantine_file"
  | string;

/**
 * What the action was applied to. Drives the "Target" column rendering
 * in the Isolation & Termination tab.
 */
export type ActionTargetType =
  | "process"
  | "ip"
  | "device"
  | "identity"
  | "file"
  | "zone"
  | "unknown"
  | string;

/**
 * A single response action record — one row in the
 * "Isolation & Termination" tab.
 *
 * Emitted by `RealResponseEngine` → forwarded by `DashboardBridge` →
 * stored by `POST /api/agent/actions` → delivered to the UI via REST
 * (`GET /api/agent/actions`) and Socket.IO (`agent:action`).
 */
export interface ActionRecord {
  /** Unique id assigned by the agent (or backend as a fallback). */
  id: string;

  /** ISO-8601 timestamp of when the action was executed. */
  timestamp: string;

  /** When the backend received the record (set server-side). */
  received_at?: string;

  /** Machine that performed the action. */
  endpoint: string;
  source: string;

  /** Action identifier, e.g. "terminate_process". */
  action: ActionType;

  /** Human-readable label, e.g. "Process Terminated". */
  action_label: string;

  /**
   * True when the action puts the endpoint into a contained state
   * (isolate / quarantine / lock zone / block). Drives the "Isolated"
   * and "Quarantined" filter chips.
   */
  containment?: boolean;

  /** What the action was applied to, e.g. "powershell.exe (PID: 1234)". */
  target: string;
  target_type: ActionTargetType;

  status: ActionStatus;
  details: string;
  reason: string;

  /** Agent that triggered the action (usually "RealResponseEngine"). */
  agent: string;
  severity: Severity | string;

  /** Originating finding / alert id this action was a response to. */
  triggered_by: string;

  success: boolean;
  error?: string | null;

  /** True when the engine ran in dry-run mode (no system changes). */
  dry_run?: boolean;

  /** If this was a manual retry, the id of the original record. */
  retried_from?: string | null;

  /** Free-form extra fields (pid, src_ip, decoy_host, etc.). */
  metadata: Record<string, unknown>;
}

/**
 * Aggregated stats returned by `GET /api/agent/actions/stats`.
 * Used for dashboard-style counters above the actions table.
 */
export interface ActionStats {
  ok: boolean;
  window_hours: number;
  total: number;
  by_action: Record<string, number>;
  by_status: Record<ActionStatus, number>;
  by_endpoint: Record<string, number>;
  by_severity: Record<Severity, number>;
  timeline: { bucket: string; count: number }[];
  success_rate: number;
  failure_rate: number;
  last_action_at: string | null;
}

/** One message in the JARVIS chat panel. */
export interface ChatMsg {
  id: number;
  role: "user" | "assistant";
  content: string;
  isTyping?: boolean;
  meta?: { confidence?: number; sources?: string };
}

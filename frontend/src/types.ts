// frontend/src/types.ts

export type NavId =
  | "dashboard"
  | "executive"
  | "alerts"
  | "response"
  | "reports"
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
  source?: string;
  // attack-chain details from the agent's incident correlator
  incident?: {
    stages: { key: string; label: string }[];
    users: string[];
    ips: string[];
    pcs?: string[];
    max_risk: number;
    count: number;
    span_minutes?: number;
    kind: "attack_chain" | "repeated";
  };
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


// ============================================================
//  Alert management, analytics, compliance (Task 29)
// ============================================================
export type AlertStatus = "open" | "acknowledged" | "closed";
export type CloseReason = "resolved" | "false_positive" | "duplicate" | "accepted_risk";

export interface AlertNote { by: string; text: string; at: string }
export interface AlertHistory { by: string; action: string; from?: string; to?: string; text?: string; at: string }

export interface SecurityAlert {
  alertId: string;
  kind: "trigate" | "finding" | "incident";
  source: string;
  title: string;
  description: string;
  severity: Severity;
  riskScore: number;
  verdict?: string;
  pattern?: string;
  entity?: string;
  subject?: string;
  srcIp?: string;
  status: AlertStatus;
  assignee: string;
  closeReason: CloseReason | "";
  notes: AlertNote[];
  history?: AlertHistory[];
  historyCount?: number;
  occurrences: number;
  firstSeen: string;
  lastSeen: string;
  acknowledgedAt?: string;
  acknowledgedBy?: string;
  closedAt?: string;
  closedBy?: string;
  data?: Record<string, any>;
}

export interface AlertList {
  total: number;
  page: number;
  limit: number;
  counts: Record<AlertStatus, number>;
  alerts: SecurityAlert[];
  storage: "mongodb" | "memory";
}

export interface TrendPoint { date: string; critical: number; high: number; medium: number; low: number; total: number; closed: number }
export interface NamedCount { name: string; count: number }

export interface ComplianceCheck {
  id: string;
  title: string;
  status: "pass" | "fail" | "warn" | "unknown";
  detail: string;
  iso27001: string[];
  nist_csf: string[];
  weight: number;
  fix: string;
}

export interface FrameworkSummary { controls: number; met: number; failing: string[]; assessed: number; score: number | null }

export interface ComplianceReport {
  endpoint: string;
  checked_at?: string;
  checkedAt?: string;
  score: number | null;
  counts: Partial<Record<"pass" | "fail" | "warn" | "unknown", number>>;
  frameworks: Record<string, FrameworkSummary>;
  checks: ComplianceCheck[];
}

export interface Analytics {
  generatedAt: string;
  days: number;
  tz: string;
  kpis: {
    totalAlerts: number; previousAlerts: number; changePct: number | null;
    open: number; acknowledged: number; openCritical: number; openHigh: number; closed: number; unassigned: number;
    mttaMinutes: number | null; mttrMinutes: number | null; falsePositiveRate: number | null;
    incidents: number; blocked: number; held: number; endpoints: number; endpointsOnline: number; avgCompliance: number | null;
  };
  posture: { score: number; level: "good" | "fair" | "poor" | "critical"; alertPenalty: number; compliancePenalty: number };
  bySeverity: Record<Severity, number>;
  openBySeverity: Record<Severity, number>;
  byStatus: Record<string, number>;
  byKind: Record<string, number>;
  byCloseReason: Record<string, number>;
  topPatterns: NamedCount[];
  topEntities: NamedCount[];
  topSources: NamedCount[];
  topIps: NamedCount[];
  trend: TrendPoint[];
  gateVerdicts: Record<string, number>;
  intel: { feedEntries: number; matches: number; scans: number; behaviourAlerts: number; incidents: number; restrictions: number; throttles: number };
  compliance: {
    average: number | null;
    endpoints: { endpoint: string; score: number | null; counts: ComplianceReport["counts"]; checkedAt?: string; frameworks: Record<string, FrameworkSummary> }[];
    failing: { id: string; title: string; status: string; endpoints: string[]; fix: string; iso: string[]; nist: string[] }[];
    trend: { date: string; score: number | null }[];
  };
  recentCritical: Pick<SecurityAlert, "alertId" | "title" | "severity" | "status" | "riskScore" | "source" | "entity" | "firstSeen" | "assignee">[];
}

export interface AgentStatusReport {
  endpoint: string;
  received_at: string;
  auto_response?: boolean;
  threat_intel?: {
    connection_scan?: boolean; interval_seconds?: number; scans?: number; matches?: number; last_error?: string;
    feeds?: { key: string; name: string; url: string; entries: number; updated: string; error: string }[];
    feed_entries?: number; abuseipdb?: boolean;
  };
  behaviour?: { enabled?: boolean; users?: number; learned?: number; alerts?: number; min_logons?: number; min_days?: number };
  correlation?: { open_incidents?: number; tracked?: number; emitted?: number; window_minutes?: number };
  access_control?: {
    restrictions?: { user: string; until: string; minutes_left: number; reason: string }[];
    throttles?: { segment: string; kbps: number; until: string; minutes_left: number }[];
  };
}

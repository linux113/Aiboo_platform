// frontend/src/types.ts

export type NavId =
  | "dashboard"
  | "surveillance"
  | "intelligence"
  | "agent"
  | "endpoints"
  | "settings";

export interface Camera {
  _id: string;
  name: string;
  location: string;
  zone: string;
  status: "online" | "offline" | "error";
  stream_url?: string;
  rtsp_url?: string;
  metadata?: Record<string, unknown>;
}

export interface Detection {
  _id: string;
  cameraId: string;
  cameraName: string;
  label: string;
  type: string;
  confidence: number;
  severity: "low" | "medium" | "high" | "critical";
  timestamp: string;
  image_url?: string;
  metadata?: Record<string, unknown>;
}

export interface Threat {
  _id: string;
  title: string;
  source: string;
  asset: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "active" | "investigating" | "contained" | "resolved";
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
  severity: "low" | "medium" | "high" | "critical";
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
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  description: string;
  findings: AgentFinding[];
  actions: string[];
  timestamp: string;
}

export interface GateDecision {
  gate: number;
  gate_label: string;
  event_id: string;
  threat_type: string;
  severity: "low" | "medium" | "high" | "critical";
  verdict: "pass" | "hold" | "block" | "escalate";
  confidence: number;
  reason: string;
  actions: string[];
  timestamp: string;
}

export interface PseudoLock {
  lock_id: string;
  event_id: string;
  agent: string;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
  active: boolean;
  locked_at: string;
  restored_at?: string;
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
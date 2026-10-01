import axios, { AxiosRequestConfig } from "axios";
import { logger } from "./logger";
import type { ActionRecord, ActionStats } from "../types";

export const API = import.meta.env.VITE_API_URL || "http://localhost:4000/api";
export const SOCKET_URL =
  import.meta.env.VITE_SOCKET_URL || "http://localhost:4000";
export const CV_URL = import.meta.env.VITE_CV_URL || "http://localhost:5050";
export const AGENT_URL =
  import.meta.env.VITE_AGENT_URL || "http://localhost:8001";

export function getToken(): string | null {
  return localStorage.getItem("token");
}

export function authH() {
  const token = getToken();
  if (!token || token === "undefined") {
    return { headers: {} };
  }
  return { headers: { Authorization: `Bearer ${token}` } };
}

export function setToken(token: string) {
  if (token && token !== "undefined") {
    localStorage.setItem("token", token);
  } else {
    logger.warn("Attempted to store invalid token");
  }
}

export function clearToken() {
  localStorage.removeItem("token");
}

const api = axios.create({
  baseURL: API,
  timeout: 15000,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token && token !== "undefined") {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      logger.warn("401 Unauthorized — redirecting to login");
      clearToken();
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

// ============================================================
//  NEW: Typed helpers for the "Isolation & Termination" tab
//  All helpers use relative paths (e.g. "/agent/actions") so they
//  respect the axios baseURL (which already includes "/api").
// ============================================================

/**
 * Query parameters accepted by GET /api/agent/actions.
 * All are optional — omit for the default (newest 200).
 */
export interface ActionQueryParams {
  /** Comma-separated action names, e.g. "terminate_process,isolate_asset". */
  action?: string;
  /** Comma-separated statuses, e.g. "success,active". */
  status?: string;
  /** Filter by machine that performed the action. */
  endpoint?: string;
  /** Alias for endpoint (agent-side "source" field). */
  source?: string;
  /** Filter by severity: low | medium | high | critical. */
  severity?: string;
  /** Substring match on the target field. */
  target?: string;
  /** ISO-8601 lower bound (inclusive). */
  since?: string;
  /** ISO-8601 upper bound (inclusive). */
  until?: string;
  /** Page size (max 1000, default 200). */
  limit?: number;
  /** Page offset (default 0). */
  offset?: number;
  /** Sort direction (default "desc" = newest first). */
  order?: "asc" | "desc";
}

/**
 * Build a query string from a params object, skipping empty values.
 * Returns "" when nothing to append, otherwise "?key=value&…".
 */
function toQuery(params?: Record<string, unknown>): string {
  if (!params) return "";
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    usp.set(k, String(v));
  }
  const s = usp.toString();
  return s ? `?${s}` : "";
}

/**
 * Fetch response actions from the backend.
 *
 * Accepts either a bare array or `{ actions: [...] }` from the server,
 * so it works with both the current shape and any future wrapper.
 *
 * Never throws — returns [] on failure so the UI stays stable.
 *
 *   const rows = await getActions({ status: "failed", limit: 50 });
 */
export async function getActions(
  params?: ActionQueryParams
): Promise<ActionRecord[]> {
  try {
    const res = await api.get(`/agent/actions${toQuery(params as Record<string, unknown> | undefined)}`);
    const data = res.data;
    if (Array.isArray(data)) return data as ActionRecord[];
    if (Array.isArray(data?.actions)) return data.actions as ActionRecord[];
    return [];
  } catch (err) {
    logger.warn("getActions failed", err);
    return [];
  }
}

/**
 * Post a response action (used by the "Retry action" button).
 *
 * The backend accepts either a single object or an array — this helper
 * always sends a single object.
 *
 * Returns the stored record on success, or throws on failure so the
 * caller can show an error toast / flip the optimistic row to failed.
 *
 *   const stored = await postAction({ ...record, retried_from: record.id });
 */
export async function postAction(
  record: Partial<ActionRecord>
): Promise<ActionRecord | null> {
  try {
    const res = await api.post("/agent/actions", record);
    const data = res.data;
    if (Array.isArray(data?.actions) && data.actions[0]) {
      return data.actions[0] as ActionRecord;
    }
    if (data?.action && typeof data.action === "object") {
      return data.action as ActionRecord;
    }
    if (data && typeof data === "object" && "id" in data) {
      return data as ActionRecord;
    }
    return null;
  } catch (err) {
    logger.error("postAction failed", err);
    throw err;
  }
}

/**
 * Fetch aggregated stats for the actions tab.
 *
 * Returns null on failure so the caller can render a placeholder.
 *
 *   const stats = await getActionStats({ window: 24 });
 */
export async function getActionStats(params?: {
  window?: number;
}): Promise<ActionStats | null> {
  try {
    const res = await api.get(`/agent/actions/stats${toQuery(params)}`);
    return res.data as ActionStats;
  } catch (err) {
    logger.warn("getActionStats failed", err);
    return null;
  }
}

/**
 * Convenience wrapper for retrying an existing action.
 * Sends a fresh POST with `retried_from` set, so the backend can
 * link the new record back to its origin.
 */
export async function retryAction(
  record: ActionRecord
): Promise<ActionRecord | null> {
  return postAction({
    action: record.action,
    target: record.target,
    target_type: record.target_type,
    endpoint: record.endpoint,
    source: record.source,
    agent: record.agent,
    severity: record.severity,
    reason: record.reason,
    triggered_by: record.triggered_by,
    status: "pending",
    details: "Manual retry requested from dashboard",
    retried_from: record.id,
    metadata: { ...(record.metadata || {}), retried_from: record.id },
  });
}

/**
 * Generic low-level request helpers — kept for backwards compatibility
 * with existing code that calls `api.get(url)` / `api.post(url, body, config)`.
 */
export const apiHelpers = {
  get: <T = unknown>(url: string, config?: AxiosRequestConfig) =>
    api.get<T>(url, config),
  post: <T = unknown>(
    url: string,
    body?: unknown,
    config?: AxiosRequestConfig
  ) => api.post<T>(url, body, config),
  put: <T = unknown>(
    url: string,
    body?: unknown,
    config?: AxiosRequestConfig
  ) => api.put<T>(url, body, config),
  del: <T = unknown>(url: string, config?: AxiosRequestConfig) =>
    api.delete<T>(url, config),
};

export default api;
// ============================================================
//  Remote command helpers (agent command channel)
// ============================================================

export interface CommandOutcome {
  status: "executed" | "failed" | "timeout";
  error?: string | null;
  result?: Record<string, unknown> | null;
}

/**
 * Poll GET /agent/commands until the agent acknowledges `cmdId` as
 * executed or failed (or the timeout passes).
 */
export async function waitForCommand(
  cmdId: string,
  timeoutMs = 20000,
  onProgress?: (status: string) => void
): Promise<CommandOutcome> {
  const deadline = Date.now() + timeoutMs;
  let last = "sent";
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1000));
    try {
      const res = await api.get("/agent/commands");
      const list: {
        cmd_id: string;
        status: string;
        error?: string | null;
        result?: Record<string, unknown> | null;
      }[] = Array.isArray(res.data?.commands) ? res.data.commands : [];
      const cmd = list.find((c) => c.cmd_id === cmdId);
      if (!cmd) continue;
      if (cmd.status === "executed" || cmd.status === "failed") {
        return { status: cmd.status, error: cmd.error ?? null, result: cmd.result ?? null };
      }
      if (cmd.status !== last) {
        last = cmd.status;
        onProgress?.(cmd.status);
      }
    } catch {
      /* keep polling */
    }
  }
  return { status: "timeout" };
}

/** Human-readable message from an axios error. */
export function apiErrorMessage(e: unknown, fallback = "Request failed"): string {
  const err = e as {
    response?: { data?: { error?: string; message?: string; detail?: string } };
    message?: string;
  };
  return (
    err.response?.data?.error ||
    err.response?.data?.message ||
    err.response?.data?.detail ||
    err.message ||
    fallback
  );
}

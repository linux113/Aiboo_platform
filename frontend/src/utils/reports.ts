// Helpers shared by the Executive, Alerts and Reports screens.
import api, { apiErrorMessage } from "./api";

export type ReportType = "risk" | "compliance" | "executive";
export type ReportFormat = "pdf" | "csv" | "json";

export const browserTz = (): string => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
};

// Downloads a report through the API (sends the login token) and saves it.
export async function downloadReport(type: ReportType, format: ReportFormat, days: number): Promise<void> {
  try {
    const res = await api.get(`/reports/${type}`, {
      params: { format, days, tz: browserTz() },
      responseType: "blob",
      timeout: 60000,
    });
    const stamp = new Date().toISOString().slice(0, 10);
    const blob = format === "json"
      ? new Blob([await (res.data as Blob).text()], { type: "application/json" })
      : (res.data as Blob);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aiboo-${type}-report-${stamp}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  } catch (e: any) {
    // error bodies come back as a Blob because of responseType: "blob"
    const data = e?.response?.data;
    if (data instanceof Blob) {
      try {
        const j = JSON.parse(await data.text());
        throw new Error(j.error || j.message || "Report failed");
      } catch (inner: any) {
        if (inner instanceof Error && inner.message) throw inner;
      }
    }
    throw new Error(apiErrorMessage(e, "Report download failed"));
  }
}

export const fmtMinutes = (m: number | null | undefined): string => {
  if (m === null || m === undefined) return "n/a";
  if (m < 60) return `${Math.round(m)} min`;
  if (m < 1440) return `${(m / 60).toFixed(1)} h`;
  return `${(m / 1440).toFixed(1)} days`;
};

export const timeAgo = (iso?: string): string => {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} days ago`;
};

export const SEV_HEX: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

export const PATTERN_LABEL = (p?: string): string =>
  (p || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

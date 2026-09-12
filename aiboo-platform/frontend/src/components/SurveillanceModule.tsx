import { useState } from "react";
import { cn } from "../utils/cn";
import api, { authH, API, CV_URL } from "../utils/api";
import { sevCls, detIcon } from "../utils/helpers";
import CamTile from "./CamTile";
import type { Camera, Detection } from "../types";

export default function SurveillanceModule({
  cameras,
  detections,
  onCamsChange,
}: {
  cameras: Camera[];
  detections: Detection[];
  onCamsChange: (c: Camera[]) => void;
}) {
  const [grid, setGrid] = useState<4 | 8 | 16>(8);
  const [fullCam, setFullCam] = useState<Camera | null>(null);
  const [addModal, setAddModal] = useState(false);
  const [cfgCam, setCfgCam] = useState<Camera | null>(null);
  const [nc, setNc] = useState({
    name: "",
    streamUrl: "",
    location: "",
    zone: "Perimeter",
    type: "ip" as string,
  });
  const [addingCam, setAddingCam] = useState(false);
  const [addError, setAddError] = useState("");
  const [deleteError, setDeleteError] = useState("");
  const [toggleError, setToggleError] = useState("");
  const critAlerts = detections
    .filter((d) => d.type.includes("weapon") || d.type.includes("watchlist"))
    .slice(0, 2);

  const regCV = async (cam: Camera) => {
    try {
      await api.post(`${CV_URL}/cameras`, {
        cameraId: cam._id,
        name: cam.name,
        streamUrl: cam.streamUrl,
        location: cam.location,
      });
    } catch {
      /* CV registration is optional */
    }
  };

  const addCam = async () => {
    if (!nc.name || !nc.streamUrl) return;
    setAddingCam(true);
    try {
      const r = await api.post(`${API}/cameras`, nc, authH());
      onCamsChange([r.data, ...cameras]);
      await regCV(r.data);
      setAddModal(false);
      setNc({ name: "", streamUrl: "", location: "", zone: "Perimeter", type: "ip" });
    } catch {
      setAddError("Failed to add camera.");
    } finally {
      setAddingCam(false);
    }
  };

  const deleteCam = async (id: string) => {
    try {
      await api.delete(`${API}/cameras/${id}`, authH());
      try {
        await api.delete(`${CV_URL}/cameras/${id}`);
      } catch {
        /* ignore CV delete failure */
      }
      onCamsChange(cameras.filter((c) => c._id !== id));
      setCfgCam(null);
    } catch {
      setDeleteError("Delete failed.");
    }
  };

  const toggleCam = async (cam: Camera) => {
    try {
      const r = await api.patch(
        `${API}/cameras/${cam._id}/toggle`,
        { enabled: !cam.enabled },
        authH()
      );
      onCamsChange(cameras.map((c) => (c._id === cam._id ? r.data : c)));
      setCfgCam(null);
    } catch {
      setToggleError("Toggle failed.");
    }
  };

  return (
    <div className="flex flex-col gap-3">
      {critAlerts.length > 0 && (
        <div className="flex items-center gap-3 rounded-xl border border-red-500/60 bg-red-500/8 px-4 py-2.5 shadow-[0_0_20px_rgba(239,68,68,0.15)]">
          <span className="text-lg flex-shrink-0">🚨</span>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-bold text-red-300">
              CRITICAL ALERT — IMMEDIATE RESPONSE REQUIRED
            </div>
            <div className="text-[11px] text-red-400 truncate">
              {critAlerts[0].label} · {critAlerts[0].cameraName} ·{" "}
              {critAlerts[0].confidence}%
            </div>
          </div>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
          Grid:
        </span>
        {([4, 8, 16] as const).map((n) => (
          <button
            key={n}
            onClick={() => setGrid(n)}
            className={cn(
              "rounded-lg border px-3 py-1 text-xs font-medium transition",
              grid === n
                ? "border-cyan-500/60 bg-cyan-500/10 text-cyan-200"
                : "border-slate-700 text-slate-400 hover:text-slate-200"
            )}
          >
            {n}
          </button>
        ))}
        <button
          onClick={() => setAddModal(true)}
          className="ml-auto flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 px-4 py-1.5 text-xs font-bold text-slate-950 hover:from-cyan-400 hover:to-emerald-400 transition shadow-lg active:scale-95"
        >
          + Add Camera
        </button>
      </div>
      <div
        className={cn(
          "grid gap-2",
          grid === 4
            ? "grid-cols-2"
            : grid === 8
              ? "grid-cols-2 md:grid-cols-4"
              : "grid-cols-2 md:grid-cols-4 xl:grid-cols-8"
        )}
      >
        {cameras.slice(0, grid).map((cam) => (
          <CamTile
            key={cam._id}
            cam={cam}
            dets={detections}
            onClick={() => setFullCam(cam)}
            onCfg={() => setCfgCam(cam)}
          />
        ))}
        {Array.from({ length: Math.max(0, grid - cameras.length) }).map(
          (_, i) => (
            <div
              key={i}
              onClick={() => setAddModal(true)}
              className="aspect-video rounded-lg border border-dashed border-slate-700/40 bg-slate-950/30 flex items-center justify-center cursor-pointer hover:border-cyan-500/40 transition"
            >
              <span className="text-[9px] text-slate-700">+ Camera</span>
            </div>
          )
        )}
      </div>
      <div className="rounded-xl border border-slate-800/80 bg-slate-950/80 p-3">
        <div className="mb-2 flex items-center justify-between">
          <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-slate-500">
            Live Detection Log · YOLOv8+DeepSORT
          </div>
          <span className="text-[10px] text-slate-500">
            {detections.length} events
          </span>
        </div>
        <div className="space-y-1 max-h-44 overflow-auto pr-1">
          {detections.length === 0 && (
            <p className="py-3 text-center text-[11px] text-slate-600">
              Start CV service + add cameras for live detections
            </p>
          )}
          {detections.slice(0, 20).map((d) => (
            <div
              key={d._id}
              className={cn(
                "flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs",
                d.type.includes("weapon")
                  ? "border-red-500/50 bg-red-500/5"
                  : "border-slate-800 bg-slate-900/40"
              )}
            >
              <span className="flex-shrink-0">{detIcon(d.type)}</span>
              <span
                className={cn(
                  "rounded-full px-1.5 py-0.5 text-[9px] font-medium ring-1 flex-shrink-0",
                  sevCls(d.severity)
                )}
              >
                {d.severity.toUpperCase()}
              </span>
              <span className="font-medium text-slate-200 flex-shrink-0 max-w-[120px] truncate">
                {d.label}
              </span>
              <span className="text-slate-400 truncate flex-1">
                {d.cameraName}
              </span>
              <span className="text-slate-500 flex-shrink-0">
                {new Date(d.timestamp).toLocaleTimeString()}
              </span>
              <span className="text-slate-600 flex-shrink-0">
                {d.confidence}%
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Add Camera Modal */}
      {addModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-950 p-6 shadow-2xl mx-4">
            <div className="mb-5 flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100">Add Camera</h3>
              <button
                onClick={() => setAddModal(false)}
                className="text-slate-500 hover:text-slate-200 text-xl"
              >
                ✕
              </button>
            </div>
            <div className="space-y-3.5">
              {[
                { l: "Camera Name", k: "name", p: "e.g. Gate 1 – North" },
                { l: "Stream URL", k: "streamUrl", p: "http://192.168.x.x:8080/video" },
                { l: "Location", k: "location", p: "e.g. North Perimeter" },
              ].map((f) => (
                <div key={f.k}>
                  <label className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400 mb-1.5">
                    {f.l}
                  </label>
                  <input
                    value={(nc as Record<string, string>)[f.k]}
                    onChange={(e) =>
                      setNc((p) => ({ ...p, [f.k]: e.target.value }))
                    }
                    placeholder={f.p}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                  />
                </div>
              ))}
              <div className="grid grid-cols-2 gap-3">
                {[
                  {
                    l: "Zone",
                    k: "zone",
                    o: ["Perimeter", "Interior", "Exterior", "Secure"],
                  },
                  {
                    l: "Type",
                    k: "type",
                    o: ["ip", "rtsp", "mobile", "usb"],
                  },
                ].map((f) => (
                  <div key={f.k}>
                    <label className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400 mb-1.5">
                      {f.l}
                    </label>
                    <select
                      value={(nc as Record<string, string>)[f.k]}
                      onChange={(e) =>
                        setNc((p) => ({ ...p, [f.k]: e.target.value }))
                      }
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
                    >
                      {f.o.map((o) => (
                        <option key={o}>{o}</option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
              <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 text-[11px] text-cyan-300/70 space-y-1">
                <div>
                  📱 <strong>IP Webcam:</strong> Install app → Start Server →{" "}
                  <code>http://192.168.x.x:8080/video</code>
                </div>
              </div>
              {addError && (
                <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
                  {addError}
                </div>
              )}
              <div className="flex gap-2 pt-1">
                <button
                  onClick={() => { setAddModal(false); setAddError(""); }}
                  className="flex-1 rounded-lg border border-slate-700 py-2 text-sm text-slate-400 hover:bg-slate-800 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={addCam}
                  disabled={addingCam || !nc.name || !nc.streamUrl}
                  className="flex-1 rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 py-2 text-sm font-bold text-slate-950 hover:from-cyan-400 hover:to-emerald-400 transition disabled:opacity-50"
                >
                  {addingCam ? "Adding..." : "Add Camera"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Config Camera Modal */}
      {cfgCam && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-950 p-5 shadow-2xl mx-4">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100 truncate">
                {cfgCam.name}
              </h3>
              <button
                onClick={() => { setCfgCam(null); setDeleteError(""); setToggleError(""); }}
                className="text-slate-500 hover:text-slate-200 text-xl flex-shrink-0"
              >
                ✕
              </button>
            </div>
            <div className="space-y-3">
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 space-y-1.5 text-xs text-slate-400">
                {[
                  ["Status", cfgCam.status],
                  ["Type", (cfgCam.type ?? "ip").toUpperCase()],
                  ["Zone", cfgCam.zone],
                  ["Enabled", cfgCam.enabled ? "Yes" : "No"],
                  ["URL", cfgCam.streamUrl],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2">
                    <span>{k}</span>
                    <span className="text-slate-200 truncate max-w-[180px]">
                      {String(v)}
                    </span>
                  </div>
                ))}
              </div>
              {(deleteError || toggleError) && (
                <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
                  {deleteError || toggleError}
                </div>
              )}
              <div className="flex gap-2">
                <button
                  onClick={() => toggleCam(cfgCam)}
                  className="flex-1 rounded-lg border border-amber-500/40 bg-amber-500/10 py-2 text-xs text-amber-300 hover:bg-amber-500/20 transition"
                >
                  {cfgCam.enabled ? "Disable" : "Enable"}
                </button>
                <button
                  onClick={() => deleteCam(cfgCam._id)}
                  className="flex-1 rounded-lg border border-red-500/40 bg-red-500/10 py-2 text-xs text-red-300 hover:bg-red-500/20 transition"
                >
                  Delete
                </button>
              </div>
              <button
                onClick={() => { setCfgCam(null); setDeleteError(""); setToggleError(""); }}
                className="w-full rounded-lg border border-slate-700 py-2 text-xs text-slate-400 hover:bg-slate-800 transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Full Camera View Modal */}
      {fullCam && (
        <div className="fixed inset-0 z-50 bg-black flex flex-col">
          <div className="flex items-center justify-between bg-slate-950/95 px-4 py-2 border-b border-slate-800 backdrop-blur flex-shrink-0">
            <div className="flex items-center gap-3 min-w-0">
              <span className="text-sm font-bold text-slate-100 truncate">
                {fullCam.name}
              </span>
              <span className="text-xs text-slate-500 hidden sm:block">
                {fullCam.location}
              </span>
              <span
                className={cn(
                  "rounded-full px-2 py-0.5 text-xs font-medium flex-shrink-0",
                  fullCam.status === "online"
                    ? "bg-emerald-500/20 text-emerald-300"
                    : "bg-red-500/20 text-red-300"
                )}
              >
                {fullCam.status}
              </span>
            </div>
            <button
              onClick={() => setFullCam(null)}
              className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:bg-slate-800 flex-shrink-0"
            >
              ✕ Exit
            </button>
          </div>
          <div className="flex-1 relative overflow-hidden bg-slate-950">
            {fullCam.status !== "offline" ? (
              <img
                src={`${CV_URL}/cameras/${fullCam._id}/stream`}
                alt={fullCam.name}
                className="w-full h-full object-contain"
                onError={(e) => {
                  (e.target as HTMLImageElement).src = fullCam.streamUrl;
                }}
              />
            ) : (
              <div className="flex h-full items-center justify-center flex-col gap-3">
                <svg
                  className="h-16 w-16 text-slate-700"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1}
                    d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
                  />
                </svg>
                <p className="text-slate-500">Camera Offline</p>
              </div>
            )}
            {detections
              .filter((d) => d.cameraId === fullCam._id)
              .slice(0, 4)
              .map((det, i) => (
                <div
                  key={det._id}
                  className={cn(
                    "absolute border-2 rounded px-2 py-1 text-xs backdrop-blur",
                    det.type.includes("weapon")
                      ? "border-red-400 bg-red-500/40 text-red-100"
                      : "border-cyan-400/70 bg-cyan-500/25 text-cyan-100"
                  )}
                  style={{
                    top: `${12 + i * 16}%`,
                    left: `${8 + i * 14}%`,
                  }}
                >
                  {detIcon(det.type)} {det.label} ({det.confidence}%)
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

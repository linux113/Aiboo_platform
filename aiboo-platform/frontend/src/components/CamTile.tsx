import { useState, useEffect } from "react";
import { cn } from "../utils/cn";
import { CV_URL } from "../utils/api";
import type { Camera, Detection } from "../types";

export default function CamTile({
  cam,
  dets,
  onClick,
  onCfg,
}: {
  cam: Camera;
  dets: Detection[];
  onClick: () => void;
  onCfg: () => void;
}) {
  const [err, setErr] = useState(false);
  const [retry, setRetry] = useState(0);
  const camDets = dets.filter((d) => d.cameraId === cam._id).slice(0, 2);
  const isCrit = camDets.some(
    (d) => d.type.includes("weapon") || d.type.includes("watchlist")
  );
  const offline = cam.status === "offline" || !cam.enabled;

  useEffect(() => {
    if (err && !offline) {
      const t = setTimeout(() => setRetry((p) => p + 1), 5000);
      return () => clearTimeout(t);
    }
  }, [err, retry, offline]);

  useEffect(() => {
    setErr(false);
  }, [cam._id]);

  return (
    <div
      className={cn(
        "relative aspect-video overflow-hidden rounded-lg border cursor-pointer group transition-all",
        isCrit
          ? "border-red-500/70 shadow-[0_0_18px_rgba(239,68,68,0.4)]"
          : "border-slate-800 hover:border-cyan-500/40"
      )}
    >
      {!offline && !err ? (
        <img
          key={retry}
          src={`${CV_URL}/cameras/${cam._id}/stream`}
          alt={cam.name}
          className="absolute inset-0 h-full w-full object-cover"
          onError={() => setErr(true)}
        />
      ) : offline ? (
        <div className="absolute inset-0 bg-slate-900 flex flex-col items-center justify-center gap-1">
          <svg
            className="h-5 w-5 text-slate-600"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
            />
          </svg>
          <span className="text-[8px] text-slate-600">NO SIGNAL</span>
        </div>
      ) : (
        <img
          className="absolute inset-0 h-full w-full object-cover bg-slate-900"
          src={cam.streamUrl}
          alt={cam.name}
          onError={() => setErr(true)}
        />
      )}
      {!offline && (
        <div className="absolute inset-0 bg-gradient-to-b from-black/30 via-transparent to-black/55 pointer-events-none" />
      )}
      {camDets.map((d, i) => (
        <div
          key={d._id}
          className={cn(
            "absolute border rounded text-[6px] px-0.5 pointer-events-none",
            d.type.includes("weapon")
              ? "border-red-400 bg-red-500/30 text-red-100"
              : "border-cyan-400/60 bg-cyan-500/15 text-cyan-100"
          )}
          style={{
            top: `${18 + i * 25}%`,
            left: `${10 + i * 22}%`,
            width: "36%",
            height: "22%",
          }}
        >
          {d.label.substring(0, 12)}
        </div>
      ))}
      <div className="absolute inset-x-0 top-0 flex items-center justify-between p-1.5 z-10">
        <span className="rounded bg-black/60 px-1.5 py-0.5 text-[7px] text-slate-200 backdrop-blur truncate max-w-[65%]">
          {cam.name}
        </span>
        <span
          className={cn(
            "rounded-full px-1.5 py-0.5 text-[7px] font-semibold",
            isCrit
              ? "bg-red-500 text-white animate-pulse"
              : offline
                ? "bg-slate-600/80 text-slate-300"
                : "bg-emerald-500/80 text-white"
          )}
        >
          {isCrit ? "⚠ ALERT" : offline ? "◉ OFFLINE" : "● LIVE"}
        </span>
      </div>
      <div className="absolute inset-x-0 bottom-0 flex items-center justify-between p-1.5 z-10">
        <span className="text-[6px] text-slate-400/70">{cam.location}</span>
        <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition">
          <button
            onClick={(e) => {
              e.stopPropagation();
              onClick();
            }}
            className="rounded bg-black/70 p-1 text-slate-300 hover:text-cyan-300 backdrop-blur"
          >
            <svg
              className="h-3 w-3"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5v-4m0 4h-4m4 0l-5-5"
              />
            </svg>
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              onCfg();
            }}
            className="rounded bg-black/70 p-1 text-slate-300 hover:text-amber-300 backdrop-blur"
          >
            <svg
              className="h-3 w-3"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
              />
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
              />
            </svg>
          </button>
        </div>
      </div>
      {isCrit && (
        <div className="absolute inset-0 border-2 border-red-500/80 rounded-lg pointer-events-none" />
      )}
    </div>
  );
}

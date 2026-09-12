import { useState, useEffect, useRef } from "react";
import { cn } from "../utils/cn";
import type { Notification } from "../types";

export default function NotificationPanel({
  notifications,
  onRead,
  onClear,
}: {
  notifications: Notification[];
  onRead: (id: string) => void;
  onClear: () => void;
}) {
  const unread = notifications.filter((n) => !n.read).length;
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node))
        setOpen(false);
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);

  const iconFor = (type: string) =>
    type === "critical" ? "🚨" : type === "warning" ? "⚠️" : "ℹ️";

  const borderFor = (type: string) =>
    type === "critical"
      ? "border-red-500/50 bg-red-500/5"
      : type === "warning"
        ? "border-amber-500/40 bg-amber-500/5"
        : "border-slate-700 bg-slate-900/60";

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="relative flex h-8 w-8 items-center justify-center rounded-full border border-slate-800 bg-slate-900/80 text-slate-400 hover:text-slate-100 transition"
      >
        <svg
          className="h-4 w-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
          />
        </svg>
        {unread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[8px] font-bold text-white ring-2 ring-[#020617] animate-pulse">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-10 z-50 w-80 rounded-2xl border border-slate-800 bg-slate-950/98 shadow-2xl backdrop-blur overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
            <div>
              <div className="text-sm font-semibold text-slate-100">
                Notifications
              </div>
              <div className="text-[10px] text-slate-500">
                {unread} unread · {notifications.length} total
              </div>
            </div>
            <button
              onClick={onClear}
              className="text-[11px] text-cyan-400 hover:text-cyan-200 transition"
            >
              Clear all
            </button>
          </div>
          <div className="max-h-96 overflow-auto divide-y divide-slate-800/50">
            {notifications.length === 0 && (
              <div className="py-8 text-center text-sm text-slate-600">
                No notifications
              </div>
            )}
            {notifications.map((n) => (
              <div
                key={n.id}
                onClick={() => onRead(n.id)}
                className={cn(
                  "flex items-start gap-3 px-4 py-3 cursor-pointer hover:bg-slate-900/50 transition border-l-2",
                  n.read ? "border-transparent" : "border-cyan-500",
                  borderFor(n.type)
                )}
              >
                <span className="text-base flex-shrink-0 mt-0.5">
                  {iconFor(n.type)}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-semibold text-slate-200">
                    {n.title}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">
                    {n.body}
                  </div>
                  <div className="text-[10px] text-slate-600 mt-1">
                    {new Date(n.timestamp).toLocaleTimeString()}
                  </div>
                </div>
                {!n.read && (
                  <div className="h-2 w-2 rounded-full bg-cyan-400 flex-shrink-0 mt-1" />
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

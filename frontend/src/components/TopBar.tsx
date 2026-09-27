import { useState, useEffect, useRef } from "react";
import { cn } from "../utils/cn";
import { initials } from "../utils/helpers";
import NotificationPanel from "./NotificationPanel";
import type { Notification, NavId, SearchResult } from "../types";

const NAV: { id: NavId; label: string; icon: string }[] = [
  { id: "dashboard", label: "Dashboard", icon: "⌘" },
  { id: "surveillance", label: "Surveillance", icon: "👁" },
  { id: "intelligence", label: "Intelligence", icon: "🧠" },
  { id: "agent", label: "Agent Console", icon: "🤖" },
  { id: "settings", label: "Settings", icon: "⚙" },
];

export default function TopBar({
  active,
  setActive,
  notifications,
  onReadNotif,
  onClearNotifs,
  onLogout,
  userName,
  searchState,
  onSearchNav,
}: {
  active: NavId;
  setActive: (n: NavId) => void;
  notifications: Notification[];
  onReadNotif: (id: string) => void;
  onClearNotifs: () => void;
  onLogout: () => void;
  userName: string;
  searchState: {
    q: string;
    setQ: (v: string) => void;
    results: SearchResult[];
  };
  onSearchNav: (nav: NavId) => void;
}) {
  const [menu, setMenu] = useState(false);
  const [logoFallback, setLogoFallback] = useState(false);
  const { q, setQ, results } = searchState;
  const searchRef = useRef<HTMLDivElement>(null);
  const [searchFocus, setSearchFocus] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node))
        setSearchFocus(false);
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);

  const handleSearchChange = (value: string) => {
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setQ(value);
    }, 300);
  };

  const onLogoError = () => setLogoFallback(true);

  return (
    <header className="flex h-14 items-center border-b border-slate-800/80 bg-[#020617]/95 px-4 backdrop-blur z-50 relative flex-shrink-0 gap-2">
      <div className="flex items-center gap-2 flex-shrink-0">
        <div className="flex h-7 w-7 items-center justify-center overflow-hidden rounded-md ring-1 ring-cyan-400/40 bg-cyan-500/10">
          {logoFallback ? (
            <span className="text-[13px] font-bold text-cyan-300">Ai</span>
          ) : (
            <img
              src="/logo.png"
              alt=""
              className="h-full w-full object-cover"
              onError={onLogoError}
            />
          )}
        </div>
        <div className="leading-tight hidden sm:block">
          <div className="text-[9px] uppercase tracking-[0.2em] text-slate-500">
            Xenthives.AI
          </div>
          <div className="text-[13px] font-semibold text-slate-100">
            AiBoO SOC
          </div>
        </div>
      </div>

      <nav className="hidden md:flex items-center gap-0.5 ml-3">
        {NAV.map((n) => (
          <button
            key={n.id}
            onClick={() => setActive(n.id)}
            className={cn(
              "px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all",
              active === n.id
                ? "bg-cyan-500/12 text-cyan-200 ring-1 ring-cyan-500/35"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
            )}
          >
            {n.label}
          </button>
        ))}
      </nav>

      <div
        className="hidden lg:block relative flex-1 max-w-xs ml-2"
        ref={searchRef}
      >
        <div className="flex items-center gap-2 rounded-full border border-slate-800 bg-slate-950/70 px-3 py-1.5 text-xs focus-within:border-cyan-500/40 transition">
          <svg
            className="h-3.5 w-3.5 text-slate-500 flex-shrink-0"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <circle cx="11" cy="11" r="6" />
            <path d="m16 16 4 4" />
          </svg>
          <input
            className="flex-1 bg-transparent text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none"
            placeholder="Search threats, cameras, findings…"
            onChange={(e) => handleSearchChange(e.target.value)}
            defaultValue={q}
            onFocus={() => setSearchFocus(true)}
          />
          {q && (
            <button
              onClick={() => {
                setQ("");
                handleSearchChange("");
              }}
              className="text-slate-500 hover:text-slate-300 text-xs"
            >
              ✕
            </button>
          )}
        </div>
        {searchFocus && results.length > 0 && (
          <div className="absolute top-10 left-0 right-0 z-50 rounded-xl border border-slate-800 bg-slate-950/98 shadow-2xl backdrop-blur overflow-hidden">
            <div className="px-3 py-1.5 text-[10px] text-slate-500 border-b border-slate-800/60">
              {results.length} results for "{q}"
            </div>
            {results.map((r, i) => (
              <button
                key={i}
                onClick={() => {
                  onSearchNav(r.nav);
                  setQ("");
                  setSearchFocus(false);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-2 text-left hover:bg-slate-900/60 transition border-b border-slate-800/30 last:border-0"
              >
                <span className="text-sm flex-shrink-0">
                  {r.type === "threat"
                    ? "⚡"
                    : r.type === "camera"
                      ? "📷"
                      : r.type === "detection"
                        ? "👁️"
                        : "🤖"}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-slate-200 truncate">
                    {r.title}
                  </div>
                  <div className="text-[10px] text-slate-500 truncate">
                    {r.sub}
                  </div>
                </div>
                {r.severity && (
                  <span
                    className={cn(
                      "rounded-full px-1.5 py-0.5 text-[9px] font-medium ring-1 flex-shrink-0",
                      r.severity === "critical"
                        ? "bg-red-500/10 text-red-400 ring-red-500/40"
                        : r.severity === "high"
                          ? "bg-amber-500/10 text-amber-300 ring-amber-400/40"
                          : r.severity === "medium"
                            ? "bg-cyan-500/10 text-cyan-300 ring-cyan-400/40"
                            : "bg-emerald-500/10 text-emerald-300 ring-emerald-400/40"
                    )}
                  >
                    {r.severity}
                  </span>
                )}
                <span className="text-[9px] text-slate-600 capitalize flex-shrink-0">
                  {r.type}
                </span>
              </button>
            ))}
          </div>
        )}
        {searchFocus && q.length >= 2 && results.length === 0 && (
          <div className="absolute top-10 left-0 right-0 z-50 rounded-xl border border-slate-800 bg-slate-950/98 shadow-xl backdrop-blur px-4 py-3 text-[11px] text-slate-500">
            No results for "{q}"
          </div>
        )}
      </div>

      <div className="ml-auto flex items-center gap-2">
        <div className="hidden sm:flex items-center gap-1 text-[10px] text-slate-500">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.9)]" />
          Live
        </div>
        <NotificationPanel
          notifications={notifications}
          onRead={onReadNotif}
          onClear={onClearNotifs}
        />
        <button
          onClick={onLogout}
          className="rounded-lg border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-[11px] font-medium text-red-300 hover:bg-red-500/20 transition"
        >
          Logout
        </button>
        <div
          className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-emerald-400 text-[11px] font-bold text-slate-950 cursor-pointer flex-shrink-0"
          title={userName}
        >
          {initials(userName)}
        </div>
        <button
          className="md:hidden flex h-8 w-8 items-center justify-center rounded-lg border border-slate-700 text-slate-400"
          onClick={() => setMenu((o) => !o)}
        >
          ☰
        </button>
      </div>
      {menu && (
        <div className="md:hidden absolute top-14 left-0 right-0 z-50 border-b border-slate-800 bg-[#020617]/98 backdrop-blur">
          {NAV.map((n) => (
            <button
              key={n.id}
              onClick={() => {
                setActive(n.id);
                setMenu(false);
              }}
              className={cn(
                "block w-full text-left px-5 py-3 text-sm border-b border-slate-800/50",
                active === n.id
                  ? "text-cyan-300"
                  : "text-slate-300 hover:bg-slate-900/60"
              )}
            >
              {n.label}
            </button>
          ))}
        </div>
      )}
    </header>
  );
}

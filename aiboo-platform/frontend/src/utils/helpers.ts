export const sevCls = (s: string) =>
  s === "critical"
    ? "bg-red-500/10 text-red-400 ring-red-500/40"
    : s === "high"
      ? "bg-amber-500/10 text-amber-300 ring-amber-400/40"
      : s === "medium"
        ? "bg-cyan-500/10 text-cyan-300 ring-cyan-400/40"
        : "bg-emerald-500/10 text-emerald-300 ring-emerald-400/40";

export const detIcon = (t: string) =>
  t.includes("weapon_gun")
    ? "🔫"
    : t.includes("weapon_knife")
      ? "🔪"
      : t.includes("watchlist")
        ? "🚨"
        : t.includes("face_unknown")
          ? "👤"
          : t.includes("crowd")
            ? "👥"
            : t.includes("behavior")
              ? "⚠️"
              : t.includes("vehicle")
                ? "🚗"
                : "👁️";

export const threatIcon = (t: string) =>
  t.includes("network")
    ? "🌐"
    : t.includes("physical")
      ? "🏢"
      : t.includes("identity")
        ? "👤"
        : t.includes("insider")
          ? "🕵️"
          : t.includes("anomal")
            ? "⚠️"
            : t.includes("correl")
              ? "🔗"
              : "⚡";

export const verdictCls = (v: string) =>
  v === "block"
    ? "text-red-300 bg-red-500/10 border-red-500/40"
    : v === "escalate"
      ? "text-amber-300 bg-amber-500/10 border-amber-500/40"
      : v === "hold"
        ? "text-cyan-300 bg-cyan-500/10 border-cyan-500/40"
        : "text-emerald-300 bg-emerald-500/10 border-emerald-500/40";

export const initials = (name: string) =>
  name
    .split(" ")
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .substring(0, 2) || "AK";

import { useState, useEffect } from "react";
import { cn } from "../utils/cn";
import api, { authH, API } from "../utils/api";
import { initials } from "../utils/helpers";

const SECTIONS = [
  { k: "profile" as const, label: "Profile", icon: "👤", desc: "Name, photo, details" },
  { k: "alerts" as const, label: "Alert Configuration", icon: "🔔", desc: "Detection & response alerts" },
  { k: "voice" as const, label: "Voice & Sound", icon: "🎙️", desc: "Audio & AI voice settings" },
  { k: "system" as const, label: "Service URLs", icon: "🔗", desc: "Backend & API configuration" },
  { k: "security" as const, label: "Security", icon: "🔒", desc: "Access & audit logs" },
];

interface ModalConfig {
  open: boolean;
  title: string;
  message: string;
}

export default function SettingsModule({
  userName,
  userEmail,
  userRole,
}: {
  userName: string;
  userEmail: string;
  userRole: string;
}) {
  const [section, setSection] = useState<"profile" | "alerts" | "voice" | "system" | "security">("profile");
  const [profile, setProfile] = useState({
    name: userName || "",
    email: userEmail || "",
    role: userRole || "",
    phone: "",
    org: "",
    bio: "",
  });
  const [alerts, setAlerts] = useState({
    weaponAlert: true,
    watchlistAlert: true,
    crowdAlert: false,
    behaviorAlert: true,
    autoEscalate: true,
    soundAlerts: true,
    voice: true,
  });
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const [urls, setUrls] = useState({
    apiUrl: "http://localhost:4000",
    cvUrl: "http://localhost:5050",
    agentUrl: "http://localhost:8001",
  });
  const [modal, setModal] = useState<ModalConfig>({ open: false, title: "", message: "" });

  useEffect(() => {
    const stored = localStorage.getItem("aiboo_settings_alerts");
    if (stored) {
      try {
        setAlerts(JSON.parse(stored));
      } catch {
        /* ignore */
      }
    }
    const storedUrls = localStorage.getItem("aiboo_settings_urls");
    if (storedUrls) {
      try {
        setUrls(JSON.parse(storedUrls));
      } catch {
        /* ignore */
      }
    }
  }, []);

  const toggleAlert = (k: keyof typeof alerts) => {
    const next = { ...alerts, [k]: !alerts[k] };
    setAlerts(next);
    localStorage.setItem("aiboo_settings_alerts", JSON.stringify(next));
    saveToBackend("alerts", next);
  };

  const saveToBackend = async (section: string, data: unknown) => {
    try {
      await api.post(`${API}/settings/${section}`, data, authH());
    } catch {
      /* settings save to backend is best-effort */
    }
  };

  const save = async () => {
    setSaving(true);
    try {
      await api.put(`${API}/settings/profile`, profile, authH());
      localStorage.setItem("aiboo_settings_urls", JSON.stringify(urls));
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      // Save locally at least
      localStorage.setItem("aiboo_settings_urls", JSON.stringify(urls));
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } finally {
      setSaving(false);
    }
  };

  const showComingSoon = (title: string) => {
    setModal({
      open: true,
      title,
      message: "This feature is coming soon. Stay tuned for updates.",
    });
  };

  return (
    <div className="flex gap-4 h-full">
      <div className="w-56 flex-shrink-0 flex flex-col gap-3">
        <div className="rounded-2xl border border-slate-800/80 bg-slate-950/80 p-4 flex flex-col items-center text-center">
          <div className="relative mb-3">
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-emerald-400 text-2xl font-black text-slate-950 shadow-[0_0_20px_rgba(34,211,238,0.4)]">
              {initials(profile.name)}
            </div>
            <div className="absolute bottom-0 right-0 h-4 w-4 rounded-full bg-emerald-400 border-2 border-slate-950 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
          </div>
          <div className="text-sm font-bold text-slate-100">{profile.name}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            {profile.role}
          </div>
          <div className="mt-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-0.5 text-[10px] text-emerald-300">
            ● Online · Shift Active
          </div>
        </div>
        <div className="rounded-2xl border border-slate-800/80 bg-slate-950/80 overflow-hidden">
          {SECTIONS.map((s) => (
            <button
              key={s.k}
              onClick={() => setSection(s.k)}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 text-left transition border-b border-slate-800/50 last:border-0",
                section === s.k
                  ? "bg-cyan-500/8 text-cyan-200"
                  : "text-slate-400 hover:bg-slate-900/60 hover:text-slate-200"
              )}
            >
              <span className="text-lg flex-shrink-0">{s.icon}</span>
              <div className="min-w-0">
                <div className="text-xs font-semibold truncate">{s.label}</div>
                <div className="text-[10px] opacity-60 truncate">{s.desc}</div>
              </div>
              {section === s.k && (
                <div className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400 flex-shrink-0" />
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 min-w-0">
        {section === "profile" && (
          <div className="rounded-2xl border border-slate-800/80 bg-slate-950/80 overflow-hidden">
            <div
              className="h-24 bg-gradient-to-r from-cyan-500/20 via-slate-900 to-emerald-500/20 relative"
            >
              <div
                className="absolute inset-0 opacity-30"
                style={{
                  backgroundImage:
                    "repeating-linear-gradient(45deg,rgba(34,211,238,0.1) 0,rgba(34,211,238,0.1) 1px,transparent 0,transparent 50%)",
                  backgroundSize: "10px 10px",
                }}
              />
            </div>
            <div className="px-6 pb-6">
              <div className="flex items-end gap-4 -mt-8 mb-5">
                <div className="flex h-20 w-20 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500 to-emerald-400 text-3xl font-black text-slate-950 shadow-[0_0_30px_rgba(34,211,238,0.5)] ring-4 ring-slate-950">
                  {initials(profile.name)}
                </div>
                <div className="mb-2">
                  <div className="text-lg font-bold text-slate-100">
                    {profile.name}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {profile.org}
                  </div>
                </div>
                <button
                  onClick={save}
                  disabled={saving}
                  className="ml-auto mb-2 rounded-lg bg-gradient-to-r from-cyan-500 to-emerald-500 px-4 py-1.5 text-xs font-bold text-slate-950 hover:from-cyan-400 hover:to-emerald-400 transition active:scale-95 disabled:opacity-50"
                >
                  {saving ? "Saving..." : saved ? "✓ Saved" : "Save Changes"}
                </button>
              </div>
              <div className="grid grid-cols-2 gap-4">
                {[
                  { l: "Full Name", k: "name" },
                  { l: "Email", k: "email" },
                  { l: "Phone", k: "phone" },
                  { l: "Organisation", k: "org" },
                  { l: "Role", k: "role" },
                  { l: "Bio", k: "bio" },
                ].map((f) => (
                  <div key={f.k} className={f.k === "bio" ? "col-span-2" : ""}>
                    <label className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 mb-1.5">
                      {f.l}
                    </label>
                    <input
                      value={(profile as Record<string, string>)[f.k]}
                      onChange={(e) =>
                        setProfile((p) => ({ ...p, [f.k]: e.target.value }))
                      }
                      className="w-full rounded-xl border border-slate-800 bg-slate-900/60 px-3.5 py-2.5 text-sm text-slate-100 focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/20 transition"
                    />
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {section === "alerts" && (
          <div className="rounded-2xl border border-slate-800/80 bg-slate-950/80 p-6 space-y-5">
            <div className="text-sm font-bold text-slate-200 mb-4">
              Alert Configuration
            </div>
            {[
              { k: "weaponAlert" as const, l: "Weapon Detection Alerts", d: "Gun/knife detections trigger immediate alert", icon: "🔫" },
              { k: "watchlistAlert" as const, l: "Watchlist Match Alerts", d: "Face recognition watchlist hits", icon: "🚨" },
              { k: "crowdAlert" as const, l: "Crowd Density Alerts", d: "Crowd density threshold exceeded", icon: "👥" },
              { k: "behaviorAlert" as const, l: "Behavior Anomaly Alerts", d: "Suspicious behavioral patterns", icon: "⚠️" },
              { k: "autoEscalate" as const, l: "Auto-Escalate Critical", d: "Automatically escalate critical detections", icon: "⚡" },
            ].map(({ k, l, d, icon }) => (
              <div
                key={k}
                className="flex items-center justify-between py-3 border-b border-slate-800/50 last:border-0"
              >
                <div className="flex items-center gap-3">
                  <span className="text-xl">{icon}</span>
                  <div>
                    <div className="text-sm text-slate-200">{l}</div>
                    <div className="text-[11px] text-slate-500">{d}</div>
                  </div>
                </div>
                <button
                  onClick={() => toggleAlert(k)}
                  className={cn(
                    "relative h-6 w-11 rounded-full transition-colors duration-200 flex-shrink-0",
                    alerts[k] ? "bg-cyan-500" : "bg-slate-700"
                  )}
                >
                  <div
                    className={cn(
                      "absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform duration-200",
                      alerts[k] ? "translate-x-5" : "translate-x-0.5"
                    )}
                  />
                </button>
              </div>
            ))}
          </div>
        )}

        {section === "voice" && (
          <div className="rounded-2xl border border-slate-800/80 bg-slate-950/80 p-6 space-y-5">
            <div className="text-sm font-bold text-slate-200 mb-4">
              Voice & Sound Settings
            </div>
            {[
              { k: "soundAlerts" as const, l: "Sound Alerts", d: "Play audio notification on critical events", icon: "🔔" },
              { k: "voice" as const, l: "Voice Assistant", d: "AiBoO Jarvis responds to you in voice", icon: "🎙️" },
            ].map(({ k, l, d, icon }) => (
              <div
                key={k}
                className="flex items-center justify-between py-3 border-b border-slate-800/50 last:border-0"
              >
                <div className="flex items-center gap-3">
                  <span className="text-xl">{icon}</span>
                  <div>
                    <div className="text-sm text-slate-200">{l}</div>
                    <div className="text-[11px] text-slate-500">{d}</div>
                  </div>
                </div>
                <button
                  onClick={() => toggleAlert(k)}
                  className={cn(
                    "relative h-6 w-11 rounded-full transition-colors duration-200",
                    alerts[k] ? "bg-cyan-500" : "bg-slate-700"
                  )}
                >
                  <div
                    className={cn(
                      "absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform duration-200",
                      alerts[k] ? "translate-x-5" : "translate-x-0.5"
                    )}
                  />
                </button>
              </div>
            ))}
            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="text-xs text-slate-400 mb-2">Voice test</div>
              <button
                onClick={() => {
                  const u = new SpeechSynthesisUtterance(
                    "AiBoO Jarvis online. All systems operational. Tri-gate pipeline active."
                  );
                  window.speechSynthesis.speak(u);
                }}
                className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-xs text-cyan-300 hover:bg-cyan-500/20 transition active:scale-95"
              >
                🔊 Test Voice
              </button>
            </div>
          </div>
        )}

        {section === "system" && (
          <div className="rounded-2xl border border-slate-800/80 bg-slate-950/80 p-6 space-y-4">
            <div className="text-sm font-bold text-slate-200 mb-4">
              Service URLs
            </div>
            {[
              { l: "Node Backend", k: "apiUrl", ph: "http://localhost:4000", icon: "🖥️" },
              { l: "CV Service (Flask+YOLOv8)", k: "cvUrl", ph: "http://localhost:5050", icon: "🎥" },
              { l: "Agent Service (FastAPI)", k: "agentUrl", ph: "http://localhost:8001", icon: "🤖" },
            ].map((f) => (
              <div key={f.k}>
                <label className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400 mb-2">
                  <span>{f.icon}</span>
                  {f.l}
                </label>
                <input
                  value={(urls as Record<string, string>)[f.k]}
                  onChange={(e) =>
                    setUrls((p) => ({ ...p, [f.k]: e.target.value }))
                  }
                  className="w-full rounded-xl border border-slate-800 bg-slate-900/60 px-3.5 py-2.5 text-sm text-slate-100 font-mono focus:border-cyan-500/50 focus:outline-none"
                />
              </div>
            ))}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2 text-[11px] text-slate-400">
              {[
                ["Platform", "AiBoO v2.0"],
                ["AI Engine", "YOLOv8n + DeepSORT"],
                ["Agent Pipeline", "Tri-Gate + 4 Agents"],
                ["Gates", "Perimeter · Behavioural · Adaptive"],
                ["Correlation", "Multi-domain pattern engine"],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between">
                  <span>{k}</span>
                  <span className="text-slate-200">{v}</span>
                </div>
              ))}
            </div>
            <button
              onClick={save}
              disabled={saving}
              className="w-full rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 py-2.5 text-sm font-bold text-slate-950 hover:from-cyan-400 hover:to-emerald-400 transition shadow-lg active:scale-95 disabled:opacity-50"
            >
              {saving ? "Saving..." : saved ? "✓ Saved" : "Save Settings"}
            </button>
          </div>
        )}

        {section === "security" && (
          <div className="rounded-2xl border border-slate-800/80 bg-slate-950/80 p-6 space-y-4">
            <div className="text-sm font-bold text-slate-200 mb-4">
              Security & Access
            </div>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Change Password", icon: "🔑", color: "border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10" },
                { label: "Enable 2FA", icon: "📱", color: "border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10" },
                { label: "View Audit Log", icon: "📋", color: "border-slate-600 text-slate-300 hover:bg-slate-800" },
                { label: "Revoke Sessions", icon: "🚪", color: "border-red-500/30 text-red-300 hover:bg-red-500/10" },
              ].map(({ label, icon, color }) => (
                <button
                  key={label}
                  onClick={() => showComingSoon(label)}
                  className={cn(
                    "flex items-center gap-3 rounded-xl border px-4 py-3 text-sm font-medium transition active:scale-95",
                    color
                  )}
                >
                  <span>{icon}</span>
                  {label}
                </button>
              ))}
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="text-xs text-slate-400 font-semibold mb-3">
                Recent Activity
              </div>
              {[].length === 0 ? (
                <p className="py-4 text-center text-[11px] text-slate-600">No recent activity</p>
              ) : null}
            </div>
          </div>
        )}
      </div>

      {/* Coming Soon Modal */}
      {modal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-950 p-6 shadow-2xl mx-4">
            <div className="text-center">
              <div className="text-4xl mb-4">🚧</div>
              <h3 className="text-lg font-bold text-slate-100 mb-2">
                {modal.title}
              </h3>
              <p className="text-sm text-slate-400 mb-6">{modal.message}</p>
              <button
                onClick={() => setModal({ open: false, title: "", message: "" })}
                className="rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 px-6 py-2 text-sm font-bold text-slate-950 hover:from-cyan-400 hover:to-emerald-400 transition"
              >
                Got it
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

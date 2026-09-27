import { useState, useRef, useCallback } from "react";
import { cn } from "./utils/cn";
import api, { API } from "./utils/api";

type Mode = "login" | "register";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function Login({
  onLogin,
}: {
  onLogin: (token: string) => void;
}) {
  const [mode, setMode] = useState<Mode>("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [role, setRole] = useState("analyst");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [logoFallback, setLogoFallback] = useState(false);
  const cooldownRef = useRef(false);

  const reset = () => {
    setError("");
    setName("");
    setEmail("");
    setPassword("");
    setConfirm("");
  };

  const validateEmail = useCallback((e: string) => EMAIL_REGEX.test(e), []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!email.trim()) return setError("Email is required.");
    if (!validateEmail(email)) return setError("Please enter a valid email address.");

    if (mode === "register") {
      if (!name.trim()) return setError("Full name is required.");
      if (password.length < 6)
        return setError("Password must be at least 6 characters.");
      if (password !== confirm) return setError("Passwords do not match.");
    } else {
      if (!password) return setError("Password is required.");
    }

    setLoading(true);
    try {
      const res = await api.post(
        mode === "login" ? "/auth/login" : "/auth/register",
        mode === "login"
          ? { email, password }
          : { name, email, password, role }
      );
      const { token } = res.data;
      if (!token) return setError("No token received.");
      if (token === "undefined")
        return setError("Invalid token received from server.");
      onLogin(token);
    } catch (err: unknown) {
      const e = err as {
        response?: { data?: { message?: string } };
        request?: unknown;
        message?: string;
      };
      const msg =
        e.response?.data?.message ||
        (e.request
          ? `Cannot connect to backend on ${API.replace("/api", "")}.`
          : "Unexpected error.");
      setError(msg);

      if (!cooldownRef.current) {
        cooldownRef.current = true;
        setTimeout(() => {
          cooldownRef.current = false;
        }, 2000);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex bg-[#020617] overflow-hidden">
      <div className="hidden lg:flex lg:w-[55%] relative overflow-hidden flex-col">
        <div className="absolute inset-0">
          <svg
            className="w-full h-full"
            viewBox="0 0 900 700"
            preserveAspectRatio="xMidYMid slice"
            xmlns="http://www.w3.org/2000/svg"
          >
            <defs>
              <radialGradient id="bg" cx="50%" cy="40%" r="70%">
                <stop offset="0%" stopColor="#0a1628" />
                <stop offset="100%" stopColor="#020617" />
              </radialGradient>
              <linearGradient id="screen1" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#0e2a3a" />
                <stop offset="100%" stopColor="#061420" />
              </linearGradient>
              <linearGradient id="glowLine" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="transparent" />
                <stop offset="50%" stopColor="#22d3ee" stopOpacity="0.8" />
                <stop offset="100%" stopColor="transparent" />
              </linearGradient>
              <filter id="glow">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <filter id="softglow">
                <feGaussianBlur stdDeviation="8" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            <rect width="900" height="700" fill="url(#bg)" />

            <g opacity="0.04">
              {Array.from({ length: 20 }).map((_, i) => (
                <line
                  key={`h${i}`}
                  x1="0"
                  y1={i * 35}
                  x2="900"
                  y2={i * 35}
                  stroke="#22d3ee"
                  strokeWidth="0.5"
                />
              ))}
              {Array.from({ length: 26 }).map((_, i) => (
                <line
                  key={`v${i}`}
                  x1={i * 36}
                  y1="0"
                  x2={i * 36}
                  y2="700"
                  stroke="#22d3ee"
                  strokeWidth="0.5"
                />
              ))}
            </g>

            <rect
              x="80"
              y="120"
              width="740"
              height="400"
              rx="8"
              fill="#050d1a"
              stroke="#1e3a4a"
              strokeWidth="1.5"
            />

            {[
              {
                x: 100,
                y: 140,
                w: 220,
                h: 145,
                color: "#0a1f2e",
                accent: "#22d3ee",
                label: "CAM-01 · Gate North",
              },
              {
                x: 335,
                y: 140,
                w: 220,
                h: 145,
                color: "#1a0a0a",
                accent: "#ef4444",
                label: "CAM-02 · ALERT",
              },
              {
                x: 570,
                y: 140,
                w: 220,
                h: 145,
                color: "#0a1f2e",
                accent: "#22d3ee",
                label: "CAM-03 · Parking",
              },
              {
                x: 100,
                y: 300,
                w: 220,
                h: 145,
                color: "#0a1f2e",
                accent: "#10b981",
                label: "CAM-04 · Lobby",
              },
              {
                x: 335,
                y: 300,
                w: 220,
                h: 145,
                color: "#0a1f2e",
                accent: "#22d3ee",
                label: "CAM-05 · Server Room",
              },
              {
                x: 570,
                y: 300,
                w: 220,
                h: 145,
                color: "#0d1a0a",
                accent: "#10b981",
                label: "CAM-06 · Perimeter",
              },
            ].map((s, i) => (
              <g key={i}>
                <rect
                  x={s.x}
                  y={s.y}
                  width={s.w}
                  height={s.h}
                  rx="3"
                  fill={s.color}
                  stroke={s.accent}
                  strokeWidth={i === 1 ? "2" : "0.8"}
                  strokeOpacity={i === 1 ? "0.9" : "0.4"}
                />
                {Array.from({ length: 8 }).map((_, j) => (
                  <line
                    key={j}
                    x1={s.x}
                    y1={s.y + j * (s.h / 8)}
                    x2={s.x + s.w}
                    y2={s.y + j * (s.h / 8)}
                    stroke={s.accent}
                    strokeWidth="0.3"
                    strokeOpacity="0.12"
                  />
                ))}
                <rect
                  x={s.x}
                  y={s.y}
                  width={s.w}
                  height="18"
                  fill="black"
                  fillOpacity="0.6"
                  rx="3"
                />
                <text
                  x={s.x + 8}
                  y={s.y + 12}
                  fill={s.accent}
                  fontSize="9"
                  fontFamily="monospace"
                  opacity="0.9"
                >
                  {s.label}
                </text>
                <circle
                  cx={s.x + s.w - 12}
                  cy={s.y + 9}
                  r="4"
                  fill={i === 1 ? "#ef4444" : "#10b981"}
                  filter="url(#glow)"
                  opacity="0.9"
                />
                {i === 1 && (
                  <>
                    <rect
                      x={s.x + 60}
                      y={s.y + 40}
                      width="80"
                      height="90"
                      fill="none"
                      stroke="#ef4444"
                      strokeWidth="2"
                      strokeDasharray="4"
                    />
                    <text
                      x={s.x + 62}
                      y={s.y + 36}
                      fill="#ef4444"
                      fontSize="8"
                      fontFamily="monospace"
                    >
                      WEAPON DETECTED
                    </text>
                    <rect
                      x={s.x + 155}
                      y={s.y + 55}
                      width="50"
                      height="70"
                      fill="none"
                      stroke="#f59e0b"
                      strokeWidth="1.5"
                      strokeDasharray="3"
                    />
                    <text
                      x={s.x + 157}
                      y={s.y + 51}
                      fill="#f59e0b"
                      fontSize="7"
                      fontFamily="monospace"
                    >
                      PERSON
                    </text>
                  </>
                )}
                {i !== 1 && i !== 4 && (
                  <ellipse
                    cx={s.x + s.w / 2}
                    cy={s.y + s.h * 0.55}
                    rx="12"
                    ry="25"
                    fill={s.accent}
                    fillOpacity="0.1"
                    stroke={s.accent}
                    strokeWidth="0.8"
                    strokeOpacity="0.3"
                  />
                )}
              </g>
            ))}

            <ellipse
              cx="450"
              cy="590"
              rx="340"
              ry="55"
              fill="#060f1c"
              stroke="#1e3a4a"
              strokeWidth="1.5"
            />
            <rect
              x="310"
              y="560"
              width="280"
              height="30"
              rx="4"
              fill="#0a1628"
              stroke="#1e3a4a"
              strokeWidth="1"
            />
            {Array.from({ length: 28 }).map((_, i) => (
              <rect
                key={i}
                x={318 + i * 9.5}
                y={563}
                width="8"
                height="8"
                rx="1"
                fill="#0f2035"
                stroke="#1e3a4a"
                strokeWidth="0.5"
              />
            ))}
            <rect
              x="120"
              y="510"
              width="130"
              height="80"
              rx="4"
              fill="#050d1a"
              stroke="#1e3a4a"
              strokeWidth="1"
            />
            <rect
              x="130"
              y="518"
              width="110"
              height="65"
              rx="2"
              fill="#061420"
            />
            <text
              x="145"
              y="540"
              fill="#22d3ee"
              fontSize="8"
              fontFamily="monospace"
              opacity="0.7"
            >
              THREAT ANALYSIS
            </text>
            <rect
              x="650"
              y="510"
              width="130"
              height="80"
              rx="4"
              fill="#050d1a"
              stroke="#1e3a4a"
              strokeWidth="1"
            />
            <rect
              x="660"
              y="518"
              width="110"
              height="65"
              rx="2"
              fill="#061420"
            />
            <text
              x="675"
              y="540"
              fill="#10b981"
              fontSize="8"
              fontFamily="monospace"
              opacity="0.7"
            >
              IDENTITY RISK
            </text>

            <rect
              x="80"
              y="516"
              width="740"
              height="1.5"
              fill="url(#glowLine)"
              opacity="0.6"
            />
            <rect
              x="80"
              y="119"
              width="740"
              height="1.5"
              fill="url(#glowLine)"
              opacity="0.5"
            />

            <path
              d="M 200 60 Q 450 20 700 60"
              fill="none"
              stroke="#22d3ee"
              strokeWidth="1"
              strokeOpacity="0.3"
              strokeDasharray="6 4"
            />
            <circle
              cx="450"
              cy="22"
              r="4"
              fill="#22d3ee"
              opacity="0.5"
              filter="url(#softglow)"
            />
            <text
              x="360"
              y="18"
              fill="#22d3ee"
              fontSize="11"
              fontFamily="monospace"
              opacity="0.5"
            >
              AiBoO SECURITY OPERATIONS CENTER
            </text>

            {[
              [80, 120],
              [820, 120],
              [80, 520],
              [820, 520],
            ].map(([cx, cy], i) => {
              const dx = i % 2 === 0 ? 1 : -1,
                dy = i < 2 ? 1 : -1;
              return (
                <g key={i}>
                  <line
                    x1={cx}
                    y1={cy}
                    x2={cx + dx * 20}
                    y2={cy}
                    stroke="#22d3ee"
                    strokeWidth="1.5"
                    opacity="0.6"
                  />
                  <line
                    x1={cx}
                    y1={cy}
                    x2={cx}
                    y2={cy + dy * 20}
                    stroke="#22d3ee"
                    strokeWidth="1.5"
                    opacity="0.6"
                  />
                </g>
              );
            })}

            <ellipse
              cx="445"
              cy="212"
              rx="130"
              ry="90"
              fill="#ef4444"
              fillOpacity="0.04"
              filter="url(#softglow)"
            />

            <rect
              x="80"
              y="530"
              width="740"
              height="20"
              fill="#061420"
              fillOpacity="0.5"
            />
            <text
              x="100"
              y="543"
              fill="#22d3ee"
              fontSize="9"
              fontFamily="monospace"
              opacity="0.6"
            >
              ● LIVE | 8 CAMERAS | AI DETECTION ACTIVE | THREAT LEVEL:
              ELEVATED
            </text>
            <text
              x="700"
              y="543"
              fill="#ef4444"
              fontSize="9"
              fontFamily="monospace"
              opacity="0.8"
            >
              ⚠ 2 ALERTS
            </text>
          </svg>
        </div>

        <div className="absolute inset-0 bg-gradient-to-r from-transparent to-[#020617]/60" />
        <div className="absolute inset-0 bg-gradient-to-t from-[#020617] via-transparent to-transparent" />

        <div className="absolute bottom-10 left-10 right-10">
          <div className="text-[10px] font-semibold uppercase tracking-[0.35em] text-cyan-400/60 mb-2">
            Xenthives.AI Technologies
          </div>
          <h2 className="text-2xl font-black text-slate-50 leading-tight mb-2">
            AI-Driven Cyber-Physical
            <br />
            Security Operations
          </h2>
          <p className="text-sm text-slate-400 max-w-xs">
            YOLOv8 · DeepSORT · OpenCV · Real-time threat detection across all
            camera zones
          </p>
          <div className="mt-4 flex items-center gap-4 text-[11px] text-slate-500">
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              End-to-end encrypted
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
              24/7 monitoring
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
              Real-time alerts
            </span>
          </div>
        </div>
      </div>

      <div className="flex flex-1 flex-col items-center justify-center px-8 py-10 relative">
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute top-0 right-0 h-[400px] w-[400px] rounded-full bg-cyan-600/5 blur-[120px]" />
          <div className="absolute bottom-0 left-0 h-[300px] w-[300px] rounded-full bg-emerald-600/5 blur-[100px]" />
          <div
            className="absolute inset-0 opacity-[0.018]"
            style={{
              backgroundImage:
                "linear-gradient(rgba(34,211,238,0.6) 1px,transparent 1px),linear-gradient(90deg,rgba(34,211,238,0.6) 1px,transparent 1px)",
              backgroundSize: "40px 40px",
            }}
          />
        </div>

        <div className="relative z-10 w-full max-w-sm">
          <div className="flex flex-col items-center mb-7">
            <div className="relative mb-4">
              <div className="absolute inset-0 rounded-2xl bg-cyan-400/10 blur-lg" />
              <div className="relative flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-400/20 bg-gradient-to-br from-slate-900 to-slate-950 shadow-[0_0_25px_rgba(34,211,238,0.12)]">
                {logoFallback ? (
                  <span className="text-xl font-black bg-gradient-to-br from-cyan-300 to-emerald-300 bg-clip-text text-transparent">
                    Ai
                  </span>
                ) : (
                  <img
                    src="/logo.png"
                    alt="AiBoO"
                    className="h-full w-full object-cover rounded-2xl"
                    onError={() => setLogoFallback(true)}
                  />
                )}
              </div>
            </div>
            <h1 className="text-lg font-bold text-slate-50">AiBoO Platform</h1>
            <p className="text-[11px] text-slate-500">
              Authorized access only
            </p>
          </div>

          <div className="flex rounded-xl border border-slate-800 bg-slate-900/50 p-1 mb-5">
            {(["login", "register"] as Mode[]).map((m) => (
              <button
                key={m}
                onClick={() => {
                  setMode(m);
                  reset();
                }}
                className={cn(
                  "flex-1 rounded-lg py-2 text-xs font-semibold transition-all",
                  mode === m
                    ? "bg-gradient-to-r from-cyan-500/15 to-emerald-500/15 text-cyan-200 ring-1 ring-cyan-500/25"
                    : "text-slate-500 hover:text-slate-300"
                )}
              >
                {m === "login" ? "Sign In" : "Create Account"}
              </button>
            ))}
          </div>

          <div className="rounded-2xl border border-slate-800/70 bg-slate-950/90 p-5 shadow-2xl backdrop-blur-md">
            {error && (
              <div className="mb-4 flex items-start gap-2 rounded-xl border border-red-500/30 bg-red-500/8 px-3 py-2.5">
                <svg
                  className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-red-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
                <p className="text-xs text-red-300">{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-3.5">
              {mode === "register" && (
                <div>
                  <label className="block text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 mb-1.5">
                    Full Name
                  </label>
                  <input
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="John Smith"
                    type="text"
                    required
                    disabled={loading}
                    className="w-full rounded-lg border border-slate-700/60 bg-slate-900/70 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/25 disabled:opacity-50 transition"
                  />
                </div>
              )}

              <div>
                <label className="block text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 mb-1.5">
                  Email Address
                </label>
                <input
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@xenthives.ai"
                  type="email"
                  required
                  disabled={loading}
                  className="w-full rounded-lg border border-slate-700/60 bg-slate-900/70 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/25 disabled:opacity-50 transition"
                />
              </div>

              <div>
                <label className="block text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPw ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={
                      mode === "register"
                        ? "Min. 6 characters"
                        : "Enter your password"
                    }
                    required
                    disabled={loading}
                    className="w-full rounded-lg border border-slate-700/60 bg-slate-900/70 px-3.5 py-2.5 pr-10 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/25 disabled:opacity-50 transition"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
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
                        d={
                          showPw
                            ? "M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88"
                            : "M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                        }
                      />
                    </svg>
                  </button>
                </div>
              </div>

              {mode === "register" && (
                <>
                  <div>
                    <label className="block text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 mb-1.5">
                      Confirm Password
                    </label>
                    <input
                      type="password"
                      value={confirm}
                      onChange={(e) => setConfirm(e.target.value)}
                      placeholder="Re-enter password"
                      required
                      disabled={loading}
                      className="w-full rounded-lg border border-slate-700/60 bg-slate-900/70 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/25 disabled:opacity-50 transition"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 mb-1.5">
                      Access Role
                    </label>
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        { v: "admin", l: "Admin", d: "Full access" },
                        { v: "analyst", l: "Analyst", d: "SOC operator" },
                        { v: "viewer", l: "Viewer", d: "Read only" },
                      ].map((r) => (
                        <button
                          key={r.v}
                          type="button"
                          onClick={() => setRole(r.v)}
                          className={cn(
                            "rounded-lg border px-2 py-2 text-center transition",
                            role === r.v
                              ? "border-cyan-500/50 bg-cyan-500/10 text-cyan-200"
                              : "border-slate-700/50 text-slate-500 hover:border-slate-600 hover:text-slate-300"
                          )}
                        >
                          <div className="text-xs font-semibold">{r.l}</div>
                          <div className="text-[9px] opacity-60">{r.d}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                </>
              )}

              <button
                type="submit"
                disabled={loading || cooldownRef.current}
                className="w-full rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 py-2.5 text-sm font-bold text-slate-950 shadow-lg hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-60 transition mt-1"
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <svg
                      className="h-4 w-4 animate-spin"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                      />
                    </svg>
                    {mode === "login"
                      ? "Authenticating…"
                      : "Creating Account…"}
                  </span>
                ) : mode === "login" ? (
                  "Authenticate & Enter"
                ) : (
                  "Create Secure Account"
                )}
              </button>
            </form>

            <p className="mt-4 text-center text-[11px] text-slate-500">
              {mode === "login"
                ? "New operator? "
                : "Already have access? "}
              <button
                onClick={() => {
                  setMode(mode === "login" ? "register" : "login");
                  reset();
                }}
                className="text-cyan-400 hover:text-cyan-300 font-semibold"
              >
                {mode === "login" ? "Request Access →" : "Sign In →"}
              </button>
            </p>
          </div>

          <div className="mt-4 flex justify-center gap-3 text-[10px] text-slate-700">
            <span className="flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500/50" />
              Encrypted
            </span>
            <span>·</span>
            <span>Access logged</span>
            <span>·</span>
            <span>v2.0</span>
          </div>
        </div>
      </div>
    </div>
  );
}

import { useEffect, useMemo, useState } from "react";
import api, { API } from "../utils/api";

type Credential = {
  _id: string;
  endpointId: string;
  label?: string;
  platform: string;
  status: "active" | "revoked";
  createdAt: string;
  lastSeenAt?: string | null;
};
type Issued = { id: string; endpointId: string; platform: "windows" | "linux"; token: string };

const configuredServer = API.replace(/\/api\/?$/, "");
const defaultServer = !configuredServer || /^(https?:\/\/)?(localhost|127\.0\.0\.1)(:\d+)?$/i.test(configuredServer)
  ? "http://<server-ip>:4000"
  : configuredServer;

async function copyText(text: string) {
  if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text);
}

export default function AgentEnrollment({ isAdmin }: { isAdmin: boolean }) {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [endpointId, setEndpointId] = useState("");
  const [label, setLabel] = useState("");
  const [platform, setPlatform] = useState<"windows" | "linux">("windows");
  const [serverUrl, setServerUrl] = useState(defaultServer);
  const [issued, setIssued] = useState<Issued | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = async () => {
    const { data } = await api.get("/agent-credentials");
    setCredentials(data?.credentials || []);
    setLoading(false);
  };
  useEffect(() => { load().catch((err) => { setError(err?.response?.data?.message || "Could not load endpoint credentials."); setLoading(false); }); }, []);

  const installCommand = useMemo(() => {
    if (!issued) return "";
    let url = "http://<server-ip>:4000";
    try {
      const parsed = new URL(serverUrl.trim());
      if (parsed.protocol === "http:" && !parsed.username && !parsed.password) url = parsed.origin;
    } catch { /* keep the safe placeholder until a valid server address is entered */ }
    if (issued.platform === "linux") return `./install.sh --url "${url}" --name "${issued.endpointId}"`;
    return `.\\configure.ps1 -EndpointName "${issued.endpointId}"`;
  }, [issued, serverUrl]);

  const issue = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(""); setNotice(""); setBusy(true);
    try {
      const { data } = await api.post("/agent-credentials", { endpointId, label, platform });
      setIssued({ id: data.credential.id, endpointId: data.credential.endpointId, platform, token: data.credential.token });
      setShowForm(false);
      setEndpointId(""); setLabel("");
      await load();
    } catch (err: any) {
      setError(err?.response?.data?.message || "Could not issue an endpoint key.");
    } finally { setBusy(false); }
  };

  const revoke = async (credential: Credential) => {
    if (!window.confirm(`Revoke the key for ${credential.endpointId}? This endpoint will stop authenticating.`)) return;
    setBusy(true); setError(""); setNotice("");
    try {
      await api.delete(`/agent-credentials/${credential._id}`);
      setNotice(`Key for ${credential.endpointId} revoked.`);
      await load();
    } catch (err: any) {
      setError(err?.response?.data?.message || "Could not revoke that key.");
    } finally { setBusy(false); }
  };

  const copy = async (text: string, message: string) => {
    try { await copyText(text); setNotice(message); }
    catch { setNotice("Clipboard access is blocked here. Select and copy the text manually."); }
  };

  return <section className="mb-4 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h3 className="text-sm font-semibold text-slate-100">Agent enrollment keys</h3><p className="mt-1 text-[11px] text-slate-500">One revocable key per endpoint. Plaintext is shown once at creation and is never listed again.</p></div>
      {isAdmin && <button onClick={() => { setIssued(null); setShowForm((v) => !v); setError(""); }} className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20">{showForm ? "Cancel" : "＋ Enroll endpoint"}</button>}
    </div>

    {error && <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 p-2.5 text-xs text-red-200">{error}</div>}
    {notice && <div className="mt-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-200">{notice}</div>}

    {issued && <div className="mt-4 space-y-3 rounded-xl border border-amber-400/40 bg-amber-400/5 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2"><div className="text-sm font-semibold text-amber-100">Copy this endpoint key now</div><button onClick={() => setIssued(null)} className="text-xs text-slate-400 hover:text-white">Dismiss</button></div>
      <p className="text-[11px] leading-5 text-slate-400">This secret cannot be recovered from AiBoO. Store it in the endpoint's protected configuration; do not send it in email or chat.</p>
      <div className="flex gap-2"><input readOnly value={issued.token} className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-cyan-200" aria-label="One-time endpoint key"/><button onClick={() => copy(issued.token, "Endpoint key copied.")} className="rounded-lg border border-slate-700 px-3 text-xs text-slate-200">Copy key</button></div>
      <label className="block text-[10px] uppercase tracking-wider text-slate-500">Agent-reachable backend address (plain HTTP as configured)
        <input value={serverUrl} onChange={(e) => setServerUrl(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200" placeholder="http://server-ip:4000" />
      </label>
      <div className="text-[10px] text-slate-400">{issued.platform === "linux" ? "On the endpoint, from the extracted linux-agent folder, run the command below. The installer will prompt for the key; paste it there." : "On the Windows endpoint, run the setup script below. The endpoint ID is included; the script asks for the backend address and then the key at a hidden prompt."}</div>
      <div className="flex gap-2"><input readOnly value={installCommand} className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200" aria-label="Agent setup command"/><button onClick={() => copy(installCommand, "Setup command copied.")} className="rounded-lg border border-slate-700 px-3 text-xs text-slate-200">Copy command</button></div>
    </div>}

    {showForm && isAdmin && <form onSubmit={issue} className="mt-4 grid gap-3 rounded-xl border border-slate-800 bg-slate-900/40 p-3 sm:grid-cols-2">
      <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Endpoint ID
        <input value={endpointId} onChange={(e) => setEndpointId(e.target.value)} required minLength={1} maxLength={160} pattern="[A-Za-z0-9_.:@-]+" placeholder="e.g. finance-laptop-01" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white" />
      </label>
      <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Label (optional)
        <input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={160} placeholder="Finance laptop" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white" />
      </label>
      <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Operating system
        <select value={platform} onChange={(e) => setPlatform(e.target.value as "windows" | "linux")} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white"><option value="windows">Windows</option><option value="linux">Linux</option></select>
      </label>
      <div className="flex items-end"><button disabled={busy} className="w-full rounded-lg bg-cyan-400 px-3 py-2 text-xs font-bold text-slate-950 disabled:opacity-50">{busy ? "Creating…" : "Create one-time key"}</button></div>
    </form>}

    {loading ? <div className="mt-3 text-xs text-slate-600">Loading keys…</div> : credentials.length > 0 && <div className="mt-4 divide-y divide-slate-800 rounded-lg border border-slate-800">
      {credentials.map((credential) => <div key={credential._id} className="flex flex-wrap items-center justify-between gap-3 px-3 py-2.5">
        <div className="min-w-0"><div className="truncate text-xs font-medium text-slate-200">{credential.label || credential.endpointId}<span className="ml-2 text-[10px] font-normal text-slate-500">{credential.platform}</span></div><div className="mt-0.5 text-[10px] text-slate-600">{credential.endpointId} · {credential.lastSeenAt ? `last heartbeat ${new Date(credential.lastSeenAt).toLocaleString()}` : `created ${new Date(credential.createdAt).toLocaleDateString()}`}</div></div>
        <div className="flex items-center gap-2"><span className={`rounded-full px-2 py-1 text-[9px] uppercase ${credential.status === "active" ? "bg-emerald-500/10 text-emerald-300" : "bg-slate-800 text-slate-500"}`}>{credential.status}</span>{isAdmin && credential.status === "active" && <button disabled={busy} onClick={() => revoke(credential)} className="rounded border border-red-500/30 px-2 py-1 text-[10px] text-red-300 disabled:opacity-50">Revoke</button>}</div>
      </div>)}
    </div>}
  </section>;
}

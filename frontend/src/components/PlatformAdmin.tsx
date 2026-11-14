import { useEffect, useState } from "react";
import api from "../utils/api";

type Plan = {
  code: string;
  name: string;
  description: string;
  monthlyAmountPaise: number | null;
  yearlyAmountPaise: number | null;
  limits: { endpoints: number | null; users: number | null };
  enabled: boolean;
};

const toRupees = (paise: number | null) => paise == null ? "" : String(paise / 100);
const toPaise = (rupees: string) => rupees.trim() === "" ? null : Math.round(Number(rupees) * 100);

export default function PlatformAdmin({ name, onLogout }: { name: string; onLogout: () => void }) {
  const [plans, setPlans] = useState<Plan[]>([]);
  const [drafts, setDrafts] = useState<Record<string, { monthly: string; yearly: string }>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = async () => {
    const { data } = await api.get("/platform/plans");
    const rows = data?.plans || [];
    setPlans(rows);
    setDrafts(Object.fromEntries(rows.map((plan: Plan) => [plan.code, {
      monthly: toRupees(plan.monthlyAmountPaise), yearly: toRupees(plan.yearlyAmountPaise),
    }])));
    setLoading(false);
  };

  useEffect(() => { load().catch((err) => { setError(err?.response?.data?.message || "Could not load plans."); setLoading(false); }); }, []);

  const save = async (plan: Plan) => {
    setSaving(plan.code); setError(""); setNotice("");
    try {
      const draft = drafts[plan.code];
      const monthly = toPaise(draft.monthly);
      const yearly = toPaise(draft.yearly);
      if ([monthly, yearly].some((n) => n !== null && (!Number.isSafeInteger(n) || n < 100))) throw new Error("Enter a valid price of at least ₹1, or leave the field blank.");
      await api.put(`/platform/plans/${plan.code}/pricing`, { monthly, yearly });
      setNotice(`${plan.name} prices saved.`);
      await load();
    } catch (err: any) {
      setError(err?.message || err?.response?.data?.message || "Could not save pricing.");
    } finally { setSaving(""); }
  };

  return <div className="min-h-screen bg-[#020617] px-4 py-8 text-slate-100 sm:px-8">
    <header className="mx-auto flex max-w-5xl items-center justify-between gap-4 border-b border-slate-800 pb-5">
      <div><p className="text-[10px] uppercase tracking-[0.22em] text-cyan-400">AiBoO Platform</p><h1 className="mt-1 text-2xl font-semibold">Super Admin</h1><p className="mt-1 text-xs text-slate-500">Signed in as {name}. This view contains platform controls only.</p></div>
      <button onClick={onLogout} className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs font-semibold text-red-200">Log out</button>
    </header>
    <main className="mx-auto max-w-5xl py-6">
      <div className="mb-5"><h2 className="text-lg font-semibold">Subscription plan pricing</h2><p className="mt-1 text-xs text-slate-400">Set INR prices in rupees. Blank means custom quote / unavailable for online checkout. Prices are stored in paise.</p></div>
      {error && <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{error}</div>}
      {notice && <div className="mb-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200">{notice}</div>}
      {loading ? <p className="text-sm text-slate-500">Loading plan settings…</p> : <div className="grid gap-4 md:grid-cols-3">
        {plans.map((plan) => <section key={plan.code} className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
          <div className="flex items-center justify-between"><h3 className="font-semibold">{plan.name}</h3><span className="rounded-full bg-slate-800 px-2 py-1 text-[9px] uppercase tracking-wide text-slate-400">{plan.code}</span></div>
          <p className="mt-2 min-h-10 text-xs leading-5 text-slate-400">{plan.description}</p>
          <div className="mt-3 text-[11px] text-slate-300">{plan.limits.endpoints ?? "Custom"} endpoints · {plan.limits.users ?? "custom"} users</div>
          <label className="mt-4 block text-[10px] uppercase tracking-wider text-slate-500">Monthly price · ₹
            <input inputMode="decimal" value={drafts[plan.code]?.monthly ?? ""} onChange={(e) => setDrafts((d) => ({ ...d, [plan.code]: { ...d[plan.code], monthly: e.target.value } }))} placeholder="Custom" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-cyan-500" />
          </label>
          <label className="mt-3 block text-[10px] uppercase tracking-wider text-slate-500">Yearly price · ₹
            <input inputMode="decimal" value={drafts[plan.code]?.yearly ?? ""} onChange={(e) => setDrafts((d) => ({ ...d, [plan.code]: { ...d[plan.code], yearly: e.target.value } }))} placeholder="Custom" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-cyan-500" />
          </label>
          <button disabled={saving === plan.code} onClick={() => save(plan)} className="mt-4 w-full rounded-lg bg-cyan-400 px-3 py-2 text-xs font-bold text-slate-950 disabled:opacity-50">{saving === plan.code ? "Saving…" : "Save prices"}</button>
        </section>)}
      </div>}
    </main>
  </div>;
}

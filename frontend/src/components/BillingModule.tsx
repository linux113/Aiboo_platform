import { useEffect, useMemo, useState } from "react";
import api from "../utils/api";

type Plan = {
  code: "basic" | "business" | "enterprise";
  name: string;
  description: string;
  currency: "INR";
  monthlyAmountPaise: number | null;
  yearlyAmountPaise: number | null;
  limits: { endpoints: number | null; users: number | null };
  features: { reports?: boolean; playbooks?: boolean; responseActions?: boolean; customIntegrations?: boolean };
  customPricing?: boolean;
};
type Checkout = { keyId: string; orderId: string; amount: number; currency: string; plan?: string; billingCycle: "monthly" | "yearly" };
type Overview = {
  organization: { name: string; billingEmail: string; status: string };
  subscription: null | { status: string; plan?: { name: string; code: string; limits?: Plan["limits"] }; billingCycle: string; currentPeriodEnd?: string; daysRemaining: number | null };
  pendingCheckout: null | { plan?: { name: string; code: string }; billingCycle: "monthly" | "yearly"; orderId: string | null; amount: number; currency: string; keyId: string };
  access: boolean;
  isLegacy: boolean;
};

const money = (paise: number | null | undefined) => paise == null
  ? "Custom pricing"
  : new Intl.NumberFormat("en-IN", { style: "currency", currency: "INR", maximumFractionDigits: 0 }).format(paise / 100);

async function loadCheckoutScript() {
  if ((window as any).Razorpay) return;
  await new Promise<void>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>('script[data-razorpay-checkout="true"]');
    if (existing) {
      existing.addEventListener("load", () => resolve(), { once: true });
      existing.addEventListener("error", () => reject(new Error("Could not load Razorpay checkout.")), { once: true });
      if ((window as any).Razorpay) resolve();
      return;
    }
    const script = document.createElement("script");
    const configuredCheckoutUrl = String(import.meta.env.VITE_RAZORPAY_CHECKOUT_SCRIPT_URL || "").trim();
    const checkoutUrl = configuredCheckoutUrl || "https://checkout.razorpay.com/v1/checkout.js";
    if (new URL(checkoutUrl).protocol !== "https:") throw new Error("Razorpay checkout must load over HTTPS.");
    script.src = checkoutUrl;
    script.async = true;
    script.dataset.razorpayCheckout = "true";
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Could not load Razorpay checkout."));
    document.body.appendChild(script);
  });
}

export default function BillingModule({
  onClose,
  isAdmin,
  onUpdated,
}: {
  onClose: () => void;
  isAdmin: boolean;
  onUpdated?: (overview: Overview) => void;
}) {
  const [plans, setPlans] = useState<Plan[]>([]);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [cycle, setCycle] = useState<"monthly" | "yearly">("monthly");
  const [selected, setSelected] = useState("basic");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const refresh = async () => {
    const [planResult, overviewResult] = await Promise.all([
      api.get("/billing/plans"),
      api.get("/billing"),
    ]);
    setPlans(planResult.data?.plans || []);
    setOverview(overviewResult.data);
    onUpdated?.(overviewResult.data);
    if (overviewResult.data?.subscription?.plan?.code) setSelected(overviewResult.data.subscription.plan.code);
    else if (overviewResult.data?.pendingCheckout?.plan?.code) setSelected(overviewResult.data.pendingCheckout.plan.code);
  };

  useEffect(() => {
    refresh().catch((err) => setError(err?.response?.data?.message || "Could not load billing information."));
  }, []);

  const selectedPlan = useMemo(() => plans.find((plan) => plan.code === selected), [plans, selected]);

  const pay = async (checkout: Checkout) => {
    setBusy(true);
    setError("");
    try {
      await loadCheckoutScript();
      const Razorpay = (window as any).Razorpay;
      const instance = new Razorpay({
        key: checkout.keyId,
        amount: checkout.amount,
        currency: checkout.currency,
        name: "AiBoO",
        description: `${checkout.plan || selectedPlan?.name || "Subscription"} · ${checkout.billingCycle}`,
        order_id: checkout.orderId,
        prefill: { email: overview?.organization?.billingEmail || "" },
        theme: { color: "#22d3ee" },
        handler: async (response: { razorpay_order_id: string; razorpay_payment_id: string; razorpay_signature: string }) => {
          try {
            await api.post("/billing/verify", response);
            setNotice("Payment confirmed. Your company workspace is active.");
            await refresh();
            setBusy(false);
          } catch (err: any) {
            setBusy(false);
            setError(err?.response?.data?.message || "Payment was received but could not be verified yet. Refresh shortly or contact support.");
          }
        },
        modal: { ondismiss: () => setBusy(false) },
      });
      instance.on("payment.failed", (event: any) => {
        setBusy(false);
        setError(event?.error?.description || "Payment failed. You can retry from Billing.");
      });
      instance.open();
    } catch (err: any) {
      setBusy(false);
      setError(err?.message || "Could not start payment.");
    }
  };

  const startCheckout = async () => {
    if (!selectedPlan) return;
    setBusy(true);
    setError("");
    try {
      const { data } = await api.post("/billing/checkout", { planCode: selected, billingCycle: cycle });
      await pay(data);
    } catch (err: any) {
      setBusy(false);
      setError(err?.response?.data?.message || "Could not create the payment order.");
    }
  };

  const continuePending = async () => {
    const pending = overview?.pendingCheckout;
    if (!pending?.orderId || !pending.keyId) return;
    await pay({
      keyId: pending.keyId,
      orderId: pending.orderId,
      amount: pending.amount,
      currency: pending.currency,
      plan: pending.plan?.name,
      billingCycle: pending.billingCycle,
    });
  };

  const endDate = overview?.subscription?.currentPeriodEnd
    ? new Date(overview.subscription.currentPeriodEnd).toLocaleDateString("en-IN", { year: "numeric", month: "long", day: "numeric" })
    : "—";

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/75 p-3 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Billing">
      <section className="max-h-[92vh] w-full max-w-4xl overflow-auto rounded-2xl border border-slate-700 bg-slate-950 shadow-2xl">
        <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-slate-800 bg-slate-950/95 px-5 py-4 backdrop-blur">
          <div>
            <p className="text-[10px] uppercase tracking-[0.2em] text-cyan-400">Workspace billing</p>
            <h2 className="mt-1 text-xl font-semibold text-white">{overview?.organization?.name || "Billing"}</h2>
          </div>
          <button onClick={onClose} className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-900" aria-label="Close billing">Close</button>
        </header>
        <div className="space-y-5 p-5">
          {error && <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">{error}</div>}
          {notice && <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm text-emerald-200">{notice}</div>}
          {overview?.isLegacy ? (
            <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4 text-sm text-slate-300">This internal legacy workspace is not billed.</div>
          ) : (
            <>
              <div className={`rounded-xl border p-4 ${overview?.access ? "border-emerald-500/30 bg-emerald-500/5" : "border-amber-500/40 bg-amber-500/10"}`}>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-slate-400">Current access</div>
                    <div className="mt-1 font-semibold text-white">
                      {overview?.subscription?.status === "active" && overview.access ? "Active" : overview?.subscription ? "Expired — renewal required" : "Awaiting first payment"}
                      {overview?.subscription?.plan?.name ? ` · ${overview.subscription.plan.name}` : ""}
                    </div>
                    <div className="mt-1 text-xs text-slate-400">{overview?.access ? `Current paid period ends ${endDate}` : "Dashboard data and agent activity remain restricted until payment is confirmed."}</div>
                  </div>
                  {overview?.subscription?.daysRemaining !== null && overview?.subscription?.daysRemaining !== undefined && overview.subscription.daysRemaining >= 0 && overview.subscription.daysRemaining <= 7 && (
                    <span className="rounded-full border border-amber-400/40 bg-amber-400/10 px-3 py-1 text-xs font-medium text-amber-200">{overview.subscription.daysRemaining} day{overview.subscription.daysRemaining === 1 ? "" : "s"} left</span>
                  )}
                </div>
              </div>

              {overview?.pendingCheckout?.orderId && (
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-4">
                  <div className="text-sm text-slate-200">A payment was started for {overview.pendingCheckout.plan?.name || "your plan"} ({overview.pendingCheckout.billingCycle}).</div>
                  <button disabled={!isAdmin || busy} onClick={continuePending} className="rounded-lg bg-cyan-400 px-4 py-2 text-xs font-bold text-slate-950 disabled:opacity-50">Continue payment · {money(overview.pendingCheckout.amount)}</button>
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="font-semibold text-white">Choose a plan or renew</h3>
                  <p className="mt-1 text-xs text-slate-400">Paid access begins only after Razorpay confirms capture.</p>
                </div>
                <div className="flex rounded-lg border border-slate-700 bg-slate-900 p-1 text-xs">
                  {(["monthly", "yearly"] as const).map((item) => <button key={item} onClick={() => setCycle(item)} className={`rounded-md px-3 py-1.5 capitalize ${cycle === item ? "bg-cyan-500/20 text-cyan-200" : "text-slate-400"}`}>{item}</button>)}
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-3">
                {plans.map((plan) => {
                  const amount = cycle === "monthly" ? plan.monthlyAmountPaise : plan.yearlyAmountPaise;
                  const active = selected === plan.code;
                  return <button key={plan.code} onClick={() => setSelected(plan.code)} className={`rounded-xl border p-4 text-left transition ${active ? "border-cyan-400/70 bg-cyan-400/10 ring-1 ring-cyan-400/30" : "border-slate-800 bg-slate-900/40 hover:border-slate-600"}`}>
                    <div className="flex items-center justify-between"><span className="font-semibold text-white">{plan.name}</span>{active && <span className="text-[10px] text-cyan-300">SELECTED</span>}</div>
                    <div className="mt-3 text-xl font-bold text-cyan-200">{money(amount)}<span className="ml-1 text-[10px] font-normal text-slate-500">{amount == null ? "" : `/${cycle === "monthly" ? "mo" : "yr"}`}</span></div>
                    <p className="mt-2 min-h-10 text-xs leading-5 text-slate-400">{plan.description}</p>
                    <p className="mt-3 text-[11px] text-slate-300">{plan.limits?.endpoints == null ? "Custom endpoints" : `${plan.limits.endpoints} endpoints`} · {plan.limits?.users == null ? "custom users" : `${plan.limits.users} users`}</p>
                    <p className="mt-2 text-[10px] text-slate-500">{plan.features?.reports ? "Monitoring · alerts · reports" : "Core monitoring"}{plan.features?.playbooks ? " · playbooks" : ""}{plan.features?.responseActions ? " · response actions" : ""}</p>
                  </button>;
                })}
              </div>
              {!isAdmin && <p className="text-xs text-slate-500">Ask your company administrator to change or renew the subscription.</p>}
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4">
                <p className="max-w-xl text-[10px] leading-4 text-slate-500">Payments are processed by Razorpay. The platform does not store card details. Razorpay checkout may require HTTPS in some production environments; the app will not silently change your plain-HTTP hosting preference.</p>
                <button disabled={!isAdmin || busy || !selectedPlan || (cycle === "monthly" ? selectedPlan?.monthlyAmountPaise == null : selectedPlan?.yearlyAmountPaise == null)} onClick={startCheckout} className="rounded-lg bg-cyan-400 px-5 py-2.5 text-sm font-bold text-slate-950 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40">{busy ? "Waiting for payment…" : `Pay ${selectedPlan ? money(cycle === "monthly" ? selectedPlan.monthlyAmountPaise : selectedPlan.yearlyAmountPaise) : ""}`}</button>
              </div>
            </>
          )}
        </div>
      </section>
    </div>
  );
}

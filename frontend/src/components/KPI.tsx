import { cn } from "../utils/cn";

export default function KPI({
  label,
  value,
  sub,
  red,
  amber,
  cyan,
}: {
  label: string;
  value: string | number;
  sub?: string;
  red?: boolean;
  amber?: boolean;
  cyan?: boolean;
}) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-xl border bg-gradient-to-br from-slate-950 to-slate-950/70 px-4 py-3",
        red
          ? "border-red-500/25"
          : amber
            ? "border-amber-500/20"
            : cyan
              ? "border-cyan-500/20"
              : "border-slate-800/80"
      )}
    >
      {red && (
        <div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-transparent via-red-500 to-transparent" />
      )}
      {cyan && (
        <div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-transparent via-cyan-500 to-transparent" />
      )}
      <div className="text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500">
        {label}
      </div>
      <div
        className={cn(
          "mt-1 text-2xl font-semibold",
          red
            ? "text-red-300"
            : amber
              ? "text-amber-300"
              : cyan
                ? "text-cyan-300"
                : "text-slate-50"
        )}
      >
        {value}
      </div>
      {sub && <div className="text-[11px] text-slate-500">{sub}</div>}
    </div>
  );
}

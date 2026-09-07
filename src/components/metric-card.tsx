import { cn } from "@/lib/utils";

export function MetricCard({ label, value, detail, tone = "neutral" }: { label: string; value: string | number; detail: string; tone?: "neutral" | "safe" | "warning" | "critical" }) {
  const tones = { neutral: "text-foreground", safe: "text-safe", warning: "text-warning", critical: "text-critical" };
  return (
    <div className="min-w-0 bg-card p-5">
      <dt className="hud-label">{label}</dt>
      <dd className={cn("data mt-4 text-3xl font-bold tracking-[-.04em]", tones[tone])}>{value}</dd>
      <p className="mt-2 text-xs leading-5 text-muted-foreground">{detail}</p>
    </div>
  );
}

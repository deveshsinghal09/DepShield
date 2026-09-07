import { Activity, BadgeCheck, Crosshair, Gauge, ShieldCheck, TrendingDown } from "lucide-react";
import type { Scan } from "@/lib/types";
import { cn } from "@/lib/utils";

type Metric = {
  label: string;
  value: string;
  detail: string;
  tone: string;
  icon: typeof ShieldCheck;
  hook?: "context-risk" | "confidence-score";
  state?: "assessed" | "provisional" | "unavailable";
};

function clamp(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function contextualRisk(scan: Scan) {
  if (scan.contextualRisk !== undefined) return { value: clamp(scan.contextualRisk), provisional: false };
  const risk = Math.max(0, ...scan.items.map(item => item.contextual?.finalPriority ?? item.risk));
  return { value: clamp(risk), provisional: true };
}

function confidence(scan: Scan) {
  if (scan.confidence !== undefined) return clamp(scan.confidence);
  const assessed = scan.items.map(item => item.contextual?.confidence).filter((value): value is number => value !== undefined);
  return assessed.length ? clamp(assessed.reduce((sum, value) => sum + value, 0) / assessed.length) : null;
}

function reachableCritical(scan: Scan) {
  if (scan.reachableCritical !== undefined) return scan.reachableCritical;
  if (!scan.items.some(item => item.reachability)) return null;
  return scan.items.filter(item => item.reachability?.status === "REACHABLE" && item.vulnerabilities.some(vulnerability => vulnerability.severity === "critical")).length;
}

function fixableRisk(scan: Scan) {
  if (scan.fixableRiskPercent !== undefined) return clamp(scan.fixableRiskPercent);
  const vulnerable = scan.items.filter(item => item.vulnerabilities.length > 0);
  const totalRisk = vulnerable.reduce((sum, item) => sum + item.risk, 0);
  if (!totalRisk) return 100;
  const addressableRisk = vulnerable.reduce((sum, item) => {
    const fixableShare = item.vulnerabilities.filter(vulnerability => Boolean(vulnerability.fixedVersion)).length / item.vulnerabilities.length;
    return sum + item.risk * fixableShare;
  }, 0);
  return clamp(addressableRisk / totalRisk * 100);
}

function scoreTone(score: number) {
  return score >= 80 ? "text-safe" : score >= 60 ? "text-warning" : "text-destructive";
}

function riskTone(risk: number) {
  return risk >= 80 ? "text-destructive" : risk >= 50 ? "text-warning" : "text-safe";
}

export function CommandCenterMetrics({ scan, previousScan, className }: { scan: Scan; previousScan?: Scan; className?: string }) {
  const context = contextualRisk(scan), confidenceValue = confidence(scan), reachable = reachableCritical(scan), fixable = fixableRisk(scan);
  const currentRisk = scan.contextualRisk ?? 100 - scan.score;
  const previousRisk = previousScan ? previousScan.contextualRisk ?? 100 - previousScan.score : null;
  const riskChange = previousRisk === null ? null : Math.round(currentRisk - previousRisk);
  const metrics: Metric[] = [
    { label: "Project security score", value: `${scan.score}`, detail: `Grade ${scan.grade} · higher is better`, tone: scoreTone(scan.score), icon: ShieldCheck, state: "assessed" },
    { label: "Contextual risk", value: `${context.value}`, detail: context.provisional ? "Legacy peak risk · rescan for v2 context" : "DepShield contextual score · lower is better", tone: riskTone(context.value), icon: Gauge, hook: "context-risk", state: context.provisional ? "provisional" : "assessed" },
    { label: "Reachable critical CVEs", value: reachable === null ? "—" : `${reachable}`, detail: reachable === null ? "Not assessed in this scan" : "Static evidence · not proof of exploitability", tone: reachable === null ? "text-muted-foreground" : reachable > 0 ? "text-destructive" : "text-safe", icon: Crosshair, state: reachable === null ? "unavailable" : "assessed" },
    { label: "Fixable risk", value: `${fixable}%`, detail: scan.fixableRiskPercent === undefined ? "Estimated from reported advisory fixes" : "Risk with a reported remediation target", tone: fixable >= 70 ? "text-safe" : fixable >= 35 ? "text-warning" : "text-destructive", icon: BadgeCheck, state: scan.fixableRiskPercent === undefined ? "provisional" : "assessed" },
    { label: "Risk change", value: riskChange === null ? "—" : `${riskChange > 0 ? "+" : ""}${riskChange}`, detail: riskChange === null ? "Select a previous scan to compare" : riskChange < 0 ? "Risk decreased since baseline" : riskChange > 0 ? "Risk increased since baseline" : "No risk movement", tone: riskChange === null ? "text-muted-foreground" : riskChange <= 0 ? "text-safe" : "text-destructive", icon: TrendingDown, state: riskChange === null ? "unavailable" : "assessed" },
    { label: "Confidence", value: confidenceValue === null ? "—" : `${confidenceValue}%`, detail: confidenceValue === null ? "Not assessed in this scan" : "Evidence completeness · not risk severity", tone: confidenceValue === null ? "text-muted-foreground" : confidenceValue >= 75 ? "text-foreground" : "text-warning", icon: Activity, hook: "confidence-score", state: confidenceValue === null ? "unavailable" : "assessed" },
  ];

  return <dl className={cn("surface surface-outline grid gap-px bg-border sm:grid-cols-2 xl:grid-cols-6", className)} data-ui="command-center-metrics">
    {metrics.map(({ label, value, detail, tone, icon: Icon, hook, state }) => <div key={label} className="min-w-0 bg-card p-4 lg:p-5" data-ui={hook} data-state={state}>
      <dt className="flex items-center gap-2 text-xs font-medium text-muted-foreground"><Icon aria-hidden="true" size={14}/>{label}</dt>
      <dd className={cn("data mt-3 text-2xl font-bold tracking-[-.03em]", tone)}>{value}</dd>
      <p className="mt-1.5 text-xs leading-5 text-muted-foreground">{detail}</p>
    </div>)}
  </dl>;
}

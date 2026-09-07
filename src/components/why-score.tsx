import { ChevronDown, Minus, TrendingDown, TrendingUp } from "lucide-react";
import type { Dependency, RiskFactor } from "@/lib/types";

function fallbackFactors(dependency: Dependency): RiskFactor[] {
  const highestCvss = Math.max(0, ...dependency.vulnerabilities.map(vulnerability => vulnerability.cvss));
  const completeFix = dependency.vulnerabilities.length > 0 && dependency.vulnerabilities.every(vulnerability => Boolean(vulnerability.fixedVersion));
  const additionalCves = Math.min(10, Math.max(0, dependency.vulnerabilities.length - 1) * 2);
  return [
    { id: "legacy-cvss", label: "Highest CVSS", value: highestCvss.toFixed(1), contribution: Math.round(highestCvss * 10), direction: "increase", evidence: "Highest available CVSS among merged advisories." },
    { id: "legacy-relationship", label: "Dependency relationship", value: dependency.direct ? "Direct" : "Transitive", contribution: dependency.direct ? 5 : 0, direction: dependency.direct ? "increase" : "neutral", evidence: dependency.direct ? "Declared directly in the project manifest." : "Introduced through a parent package." },
    { id: "legacy-fix", label: "Fix availability", value: completeFix ? "Complete reported fix" : "No complete reported fix", contribution: completeFix ? -5 : 5, direction: completeFix ? "decrease" : "increase", evidence: completeFix ? "Every merged advisory reports a fixed version." : "At least one advisory has no reported fixed version." },
    { id: "legacy-cves", label: "Additional CVEs", value: `${Math.max(0, dependency.vulnerabilities.length - 1)}`, contribution: additionalCves, direction: additionalCves ? "increase" : "neutral", evidence: "Adds two points per advisory after the first, capped at ten." },
  ];
}

function contribution(value: number) {
  return `${value > 0 ? "+" : ""}${value}`;
}

export function WhyScore({ dependency, defaultOpen = false }: { dependency: Dependency; defaultOpen?: boolean }) {
  const contextual = dependency.contextual, factors = contextual?.factors ?? fallbackFactors(dependency), score = contextual?.finalPriority ?? dependency.risk;
  return <details className="group surface surface-outline" open={defaultOpen} data-ui="why-score" data-model={contextual?.model ?? "legacy-risk-v1"}>
    <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-4 marker:hidden">
      <span><b className="text-sm">Why this score?</b><span className="mt-1 block text-xs text-muted-foreground">{contextual ? "DepShield contextual priority" : "Legacy dependency risk"} · {score}/100</span></span>
      <ChevronDown aria-hidden="true" className="shrink-0 text-muted-foreground transition-transform group-open:rotate-180" size={17}/>
    </summary>
    <div className="border-t">
      <ol>{factors.map(factor => {
        const Icon = factor.direction === "increase" ? TrendingUp : factor.direction === "decrease" ? TrendingDown : Minus;
        const tone = factor.direction === "increase" ? "text-destructive" : factor.direction === "decrease" ? "text-safe" : "text-muted-foreground";
        return <li key={factor.id} className="grid gap-2 border-b px-5 py-4 last:border-0 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
          <div><div className="flex flex-wrap items-center gap-2"><Icon aria-hidden="true" className={tone} size={14}/><b className="text-xs">{factor.label}</b><span className="data text-xs text-muted-foreground">{factor.value}</span></div><p className="mt-1.5 text-xs leading-5 text-muted-foreground">{factor.evidence}</p></div>
          <span className={`data text-sm font-bold ${tone}`} aria-label={`${factor.contribution} point contribution`}>{contribution(factor.contribution)}</span>
        </li>;
      })}</ol>
      <p className="border-t px-5 py-3 text-xs leading-5 text-muted-foreground">{contextual ? contextual.model : "Legacy scores use CVSS, relationship, fix availability, and CVE count."} DepShield scores are explainable project heuristics, not industry standards.</p>
    </div>
  </details>;
}

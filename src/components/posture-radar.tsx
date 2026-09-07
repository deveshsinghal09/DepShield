"use client";

import { Radar, RadarChart, PolarAngleAxis, PolarGrid, PolarRadiusAxis, ResponsiveContainer, Tooltip } from "recharts";
import { Activity, Info } from "lucide-react";
import type { Scan } from "@/lib/types";

const categories = [
  { key: "dependencyHygiene", short: "Hygiene", label: "Dependency Hygiene", explanation: "Healthy dependency inventory and vulnerable-package density." },
  { key: "knownVulnerabilityRisk", short: "Known risk", label: "Known Vulnerability Risk", explanation: "Posture after accounting for currently identified vulnerabilities." },
  { key: "reachabilityExposure", short: "Exposure", label: "Reachability Exposure", explanation: "Observed reachability and internet-exposure posture." },
  { key: "patchability", short: "Patchability", label: "Patchability", explanation: "Availability of reported fixed versions for identified findings." },
  { key: "supplyChainComplexity", short: "Complexity", label: "Supply Chain Complexity", explanation: "Depth, parent count, and dependency-graph complexity." },
  { key: "remediationReadiness", short: "Readiness", label: "Remediation Readiness", explanation: "Expected ability to reduce risk with practical upgrades." },
] as const;

export function PostureRadar({ scan }: { scan: Scan }) {
  if (!scan.posture) return <section className="surface surface-outline" data-ui="posture-radar" data-state="unavailable">
    <header className="flex items-start justify-between gap-4 border-b px-5 py-4">
      <div><h2 className="text-sm font-bold">Security posture radar</h2><p className="mt-1 text-xs text-muted-foreground">Six explainable posture dimensions</p></div><Activity aria-hidden="true" className="text-muted-foreground" size={17}/>
    </header>
    <div className="flex min-h-64 items-center gap-3 p-6 text-sm text-muted-foreground"><Info aria-hidden="true" className="shrink-0 text-warning" size={18}/><p>Contextual posture was not assessed for this legacy scan. Run a new scan to generate the six-axis model.</p></div>
  </section>;

  const data = categories.map(category => ({ ...category, value: Math.max(0, Math.min(100, Math.round(scan.posture![category.key]))) }));
  return <section className="surface surface-outline" data-ui="posture-radar" data-state="assessed">
    <header className="flex items-start justify-between gap-4 border-b px-5 py-4">
      <div><h2 className="text-sm font-bold">Security posture radar</h2><p className="mt-1 text-xs text-muted-foreground">Higher values indicate stronger posture; formulas remain DepShield-specific.</p></div><Activity aria-hidden="true" className="text-primary" size={17}/>
    </header>
    <div className="grid gap-2 p-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(260px,.9fr)] lg:items-center">
      <div className="h-80 min-w-0" aria-hidden="true">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart data={data} outerRadius="70%">
            <PolarGrid stroke="var(--border)"/>
            <PolarAngleAxis dataKey="short" tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}/>
            <PolarRadiusAxis angle={90} domain={[0, 100]} tickCount={5} tick={{ fill: "var(--muted-foreground)", fontSize: 10 }}/>
            <Tooltip contentStyle={{ background: "var(--secondary)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--foreground)" }} formatter={(value) => [`${Number(value)}/100`, "Posture"]}/>
            <Radar dataKey="value" stroke="var(--primary)" strokeWidth={2} fill="var(--primary)" fillOpacity={0.16}/>
          </RadarChart>
        </ResponsiveContainer>
      </div>
      <div className="scrollbar overflow-x-auto">
        <table className="w-full text-left text-xs">
          <caption className="sr-only">Accessible security posture radar values and explanations</caption>
          <thead><tr className="border-b text-muted-foreground"><th className="px-3 py-2 font-medium">Dimension</th><th className="px-3 py-2 text-right font-medium">Score</th></tr></thead>
          <tbody>{data.map(item => <tr key={item.key} className="border-b last:border-0"><td className="px-3 py-3"><b className="font-semibold text-foreground">{item.label}</b><span className="mt-1 block leading-5 text-muted-foreground">{item.explanation}</span></td><td className="data px-3 py-3 text-right align-top font-bold">{item.value}</td></tr>)}</tbody>
        </table>
      </div>
    </div>
  </section>;
}

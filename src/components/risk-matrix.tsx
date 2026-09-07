"use client";

import Link from "next/link";
import { ReferenceLine, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis } from "recharts";
import { ArrowUpRight } from "lucide-react";
import type { Dependency, Scan } from "@/lib/types";

type MatrixPoint = { name: string; version: string; path: string; risk: number; difficulty: number; source: "Contextual" | "Legacy"; quadrant: string };
type MatrixTooltipProps = { active?: boolean; payload?: ReadonlyArray<{ payload?: MatrixPoint }> };

function versionParts(version: string) {
  return version.replace(/^[^0-9]*/, "").split(/[.-]/).slice(0, 3).map(value => Number(value) || 0);
}

function legacyDifficulty(dependency: Dependency) {
  if (dependency.recommendation === "no-fix") return 95;
  if (dependency.recommendation === "partial-fix") return 72;
  if (!dependency.direct) return 58;
  const current = versionParts(dependency.version), target = versionParts(dependency.latest);
  if (target[0] > current[0]) return 78;
  if (target[1] > current[1]) return 42;
  return dependency.latest === dependency.version ? 88 : 20;
}

function quadrant(risk: number, difficulty: number) {
  if (risk >= 50 && difficulty < 50) return "Fix first";
  if (risk >= 50) return "Plan carefully";
  if (difficulty < 50) return "Quick win";
  return "Lower priority";
}

function href(scanId: string, point: MatrixPoint) {
  const query = new URLSearchParams({ scan: scanId, version: point.version, path: point.path });
  return `/dependencies/${encodeURIComponent(point.name)}?${query}`;
}

function MatrixTooltip({ active, payload }: MatrixTooltipProps) {
  const point = payload?.[0]?.payload;
  if (!active || !point) return null;
  return <div className="surface surface-outline max-w-56 p-3 text-xs"><b>{point.name}@{point.version}</b><dl className="data mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-muted-foreground"><dt>Risk</dt><dd className="text-right text-foreground">{point.risk}</dd><dt>Difficulty</dt><dd className="text-right text-foreground">{point.difficulty}</dd></dl><p className="mt-2 text-primary">{point.quadrant}</p></div>;
}

export function RiskMatrix({ scan, limit = 30 }: { scan: Scan; limit?: number }) {
  const allPoints: MatrixPoint[] = scan.items.filter(item => item.vulnerabilities.length > 0 || item.risk > 0).map(item => {
    const risk = item.contextual?.finalPriority ?? item.risk;
    const difficulty = item.contextual?.remediationDifficulty ?? item.compatibility?.score ?? legacyDifficulty(item);
    return { name: item.name, version: item.version, path: item.path, risk, difficulty, source: item.contextual ? "Contextual" as const : "Legacy" as const, quadrant: quadrant(risk, difficulty) };
  }).toSorted((a, b) => b.risk - a.risk || a.difficulty - b.difficulty);
  const points = allPoints.slice(0, limit);

  return <section className="surface surface-outline" data-ui="risk-matrix" data-state={points.length ? "ready" : "empty"}>
    <header className="flex flex-col justify-between gap-3 border-b px-5 py-4 sm:flex-row sm:items-start">
      <div><h2 className="text-sm font-bold">Risk vs remediation difficulty</h2><p className="mt-1 text-xs text-muted-foreground">Prioritize high-impact work without hiding estimated upgrade effort.</p></div>
      <span className="data text-xs text-muted-foreground">{points.length} of {allPoints.length} plotted</span>
    </header>
    {points.length ? <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,.8fr)]">
      <div className="relative h-96 min-w-0" aria-hidden="true">
        <span className="pointer-events-none absolute left-14 top-3 z-10 text-xs font-semibold text-warning">Fix first</span>
        <span className="pointer-events-none absolute right-3 top-3 z-10 text-xs font-semibold text-destructive">Plan carefully</span>
        <span className="pointer-events-none absolute bottom-9 left-14 z-10 text-xs text-safe">Quick win</span>
        <span className="pointer-events-none absolute bottom-9 right-3 z-10 text-xs text-muted-foreground">Lower priority</span>
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 22, right: 12, bottom: 12, left: 0 }}>
            <XAxis type="number" dataKey="difficulty" name="Difficulty" domain={[0, 100]} tickLine={false} axisLine={false} tick={{ fill: "var(--muted-foreground)", fontSize: 11 }} label={{ value: "Remediation difficulty →", position: "insideBottom", offset: -4, fill: "var(--muted-foreground)", fontSize: 11 }}/>
            <YAxis type="number" dataKey="risk" name="Risk" domain={[0, 100]} tickLine={false} axisLine={false} tick={{ fill: "var(--muted-foreground)", fontSize: 11 }} label={{ value: "Security risk →", angle: -90, position: "insideLeft", fill: "var(--muted-foreground)", fontSize: 11 }}/>
            <ZAxis range={[70, 70]}/>
            <ReferenceLine x={50} stroke="var(--border)" strokeDasharray="4 4"/>
            <ReferenceLine y={50} stroke="var(--border)" strokeDasharray="4 4"/>
            <Tooltip cursor={{ stroke: "var(--border)", strokeDasharray: "3 3" }} content={<MatrixTooltip/>}/>
            <Scatter data={points} fill="var(--primary)" stroke="var(--background)" strokeWidth={1.5}/>
          </ScatterChart>
        </ResponsiveContainer>
      </div>
      <div className="scrollbar max-h-96 overflow-auto">
        <table className="w-full min-w-80 text-left text-xs">
          <caption className="sr-only">Accessible risk and remediation difficulty matrix values</caption>
          <thead className="sticky top-0 bg-card"><tr className="border-b text-muted-foreground"><th className="px-3 py-2 font-medium">Dependency</th><th className="px-3 py-2 text-right font-medium">Risk</th><th className="px-3 py-2 text-right font-medium">Effort</th></tr></thead>
          <tbody>{points.map(point => <tr key={`${point.name}@${point.version}-${point.path}`} className="border-b last:border-0"><td className="px-3 py-3"><Link className="inline-flex items-center gap-1 font-semibold hover:text-primary" href={href(scan.id, point)}>{point.name}<ArrowUpRight aria-hidden="true" size={12}/></Link><span className="data mt-1 block text-muted-foreground">{point.quadrant} · {point.source}</span></td><td className="data px-3 py-3 text-right align-top font-bold">{point.risk}</td><td className="data px-3 py-3 text-right align-top font-bold">{point.difficulty}</td></tr>)}</tbody>
        </table>
      </div>
    </div> : <div className="grid min-h-64 place-items-center p-8 text-center"><div><b>No remediation candidates</b><p className="mt-1 text-sm text-muted-foreground">This scan has no dependencies with identified risk.</p></div></div>}
    <p className="border-t px-5 py-3 text-xs leading-5 text-muted-foreground">Difficulty is an estimated DepShield score. Legacy scans use version distance and remediation status until contextual analysis is available.</p>
  </section>;
}

"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { ArrowRight, Beaker, BrainCircuit, CheckCircle2, LoaderCircle, TriangleAlert } from "lucide-react";
import type { Scan } from "@/lib/types";
import { requestFixExplanation } from "@/lib/analyst-events";
import type { RemediationSimulation } from "@/lib/remediation-sandbox";
import { generateUpgradePlan } from "@/lib/remediation";
import { useFeatureFlags } from "@/components/feature-flags-provider";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

export function RemediationLab({ scan }: { scan: Scan }) {
  const { remediationSandbox } = useFeatureFlags();
  const plan = useMemo(() => generateUpgradePlan(scan.items), [scan]);
  const actionable = plan.filter((item) => item.targetVersion);
  const [generated, setGenerated] = useState(false);
  const [selected, setSelected] = useState(actionable[0]?.dependency.path ?? "");
  const selectedPlan = actionable.find((item) => item.dependency.path === selected) ?? actionable[0];
  const [target, setTarget] = useState(selectedPlan?.targetVersion ?? "");
  const [simulation, setSimulation] = useState<RemediationSimulation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function selectPath(path: string) {
    setSelected(path);
    const item = actionable.find((value) => value.dependency.path === path);
    setTarget(item?.targetVersion ?? "");
    setSimulation(null);
    setError(null);
  }

  async function simulate() {
    if (!remediationSandbox || !selectedPlan || !target.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/simulate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          scanId: scan.id,
          dependencyName: selectedPlan.dependency.name,
          installedVersion: selectedPlan.dependency.version,
          dependencyPath: selectedPlan.dependency.path,
          targetVersion: target.trim(),
        }),
      });
      const body = await response.json().catch(() => null) as { data?: RemediationSimulation; error?: { message?: string } } | null;
      if (!response.ok || !body?.data) throw new Error(body?.error?.message ?? "The simulation could not be completed.");
      setSimulation(body.data);
    } catch (value) {
      setError(value instanceof Error ? value.message : "The simulation could not be completed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="surface surface-outline" data-ui="upgrade-plan">
        <div className="flex flex-col justify-between gap-4 border-b p-5 sm:flex-row sm:items-center">
          <div><h2 className="font-bold">Evidence-grounded remediation planner</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">Deterministic plan: highest contextual risk and lowest estimated effort first. Reported fixes still require an actual upgrade and rescan.</p></div>
          <Button onClick={() => setGenerated(true)} disabled={generated}><CheckCircle2 size={15} />{generated ? "Plan generated" : "Generate Remediation Plan"}</Button>
        </div>
        {generated ? (
          plan.length ? <div className="scrollbar overflow-x-auto"><table className="w-full min-w-[900px] text-left text-sm"><thead><tr className="border-b bg-secondary/50 text-xs text-muted-foreground"><th className="px-5 py-3 font-medium">Priority</th><th className="px-4 py-3 font-medium">Dependency</th><th className="px-4 py-3 font-medium">Action</th><th className="px-4 py-3 font-medium">CVEs resolved</th><th className="px-4 py-3 font-medium">Expected reduction</th><th className="px-4 py-3 font-medium">Compatibility</th></tr></thead><tbody>{plan.map((item, index) => <tr key={`${item.dependency.path}-${index}`} className="border-b last:border-0"><td className="data px-5 py-4 text-muted-foreground">{String(index + 1).padStart(2, "0")}</td><td className="px-4 py-4"><Link href={`/dependencies/${encodeURIComponent(item.dependency.name)}?scan=${scan.id}&version=${item.dependency.version}&path=${encodeURIComponent(item.dependency.path)}`} className="font-semibold hover:text-primary">{item.dependency.name}</Link><span className="data mt-1 block text-xs text-muted-foreground">{item.dependency.version}{item.targetVersion ? ` → ${item.targetVersion}` : ""}</span><button type="button" data-ui="explain-fix" onClick={() => requestFixExplanation({ name: item.dependency.name, version: item.dependency.version, targetVersion: item.targetVersion ?? undefined })} className="mt-2 inline-flex items-center gap-1.5 text-xs font-semibold text-primary hover:text-foreground"><BrainCircuit size={13} />Explain this fix</button></td><td className="px-4 py-4"><Badge tone={item.classification === "NO FIX" ? "critical" : item.classification === "MAJOR UPGRADE" ? "medium" : "neutral"}>{item.classification ?? item.label}</Badge></td><td className="data px-4 py-4 text-xs">{item.cvesResolved?.length ?? 0}<span className="text-muted-foreground"> / {item.dependency.vulnerabilities.length}</span></td><td className="data px-4 py-4 font-semibold text-safe">−{item.expectedRiskReduction ?? 0}</td><td className="px-4 py-4 text-xs"><span className="font-semibold">{item.compatibility?.level ?? "UNKNOWN"}</span><span className="mt-1 block text-muted-foreground">Estimated, verify with tests</span></td></tr>)}</tbody></table></div> : <p className="p-6 text-sm text-muted-foreground">No vulnerable dependency requires remediation.</p>
        ) : <div className="flex items-center gap-3 p-6 text-sm text-muted-foreground"><ArrowRight className="shrink-0 text-primary" size={17} />Generate the ordered plan to see expected risk reduction, resolved CVEs, parent constraints, and compatibility estimates.</div>}
      </section>

      <section className="surface surface-outline" data-ui="remediation-sandbox">
        <p
          className={`border-b px-5 py-3 text-xs leading-5 ${remediationSandbox ? "bg-warning/5 text-warning" : "bg-secondary/60 text-muted-foreground"}`}
          data-ui={remediationSandbox ? "sandbox-estimate-notice" : "sandbox-disabled"}
        >
          {remediationSandbox
            ? "Advisory-based estimate only: no target package is resolved, installed, or rescanned in this sandbox."
            : "What-if simulation is disabled for this deployment. The deterministic upgrade plan above remains available."}
        </p>
        <div className="border-b p-5"><div className="flex items-center gap-3"><span className="grid size-9 place-items-center rounded-sm bg-primary/10 text-primary"><Beaker size={17} /></span><div><h2 className="font-bold">Remediation Sandbox</h2><p className="mt-1 text-xs text-muted-foreground">What-if simulation only. No package is installed and no project file is modified.</p></div></div></div>
        {selectedPlan ? <div className="grid gap-6 p-5 xl:grid-cols-[minmax(0,1fr)_minmax(480px,1.3fr)]"><div><label className="text-xs text-muted-foreground">Dependency instance<select value={selectedPlan.dependency.path} onChange={(event) => selectPath(event.target.value)} disabled={!remediationSandbox} className="mt-2 h-10 w-full rounded-sm border bg-background px-3 text-sm text-foreground disabled:cursor-not-allowed disabled:opacity-60">{actionable.map((item) => <option key={item.dependency.path} value={item.dependency.path}>{item.dependency.name}@{item.dependency.version} · {item.classification}</option>)}</select></label><label className="mt-4 block text-xs text-muted-foreground">Simulated target<input value={target} onChange={(event) => setTarget(event.target.value)} disabled={!remediationSandbox} className="data mt-2 h-10 w-full rounded-sm border bg-background px-3 text-sm text-foreground disabled:cursor-not-allowed disabled:opacity-60" /></label><Button className="mt-4 w-full" onClick={simulate} disabled={!remediationSandbox || loading}>{loading ? <LoaderCircle className="animate-spin" size={15} /> : <Beaker size={15} />}{loading ? "Simulating…" : remediationSandbox ? "What If I Upgrade?" : "Simulation disabled"}</Button><div className="mt-5 rounded-sm bg-secondary/60 p-4 text-xs leading-5 text-muted-foreground"><b className="text-foreground">Estimated compatibility risk: {selectedPlan.compatibility?.level ?? "UNKNOWN"}</b><p className="mt-2">{selectedPlan.compatibility?.reasons[0] ?? "Insufficient version evidence for a compatibility estimate."}</p></div>{error ? <div role="alert" className="mt-4 flex gap-2 rounded-sm bg-destructive/10 p-3 text-xs text-destructive ring-1 ring-destructive/30"><TriangleAlert className="shrink-0" size={15} />{error}</div> : null}</div>{simulation ? <SimulationResult value={simulation} /> : <div className="grid min-h-72 place-items-center rounded-[2px] bg-background p-6 text-center ring-1 ring-border"><div><Beaker className="mx-auto text-muted-foreground" /><p className="mt-3 font-semibold">{remediationSandbox ? "No simulated state yet" : "Simulation unavailable"}</p><p className="mt-2 max-w-sm text-xs leading-5 text-muted-foreground">{remediationSandbox ? "Choose an exact advisory-reported target to estimate findings and posture while holding the dependency graph constant." : "Enable ENABLE_REMEDIATION_SANDBOX on a trusted deployment to use advisory-based what-if estimates."}</p></div></div>}</div> : <div className="p-8 text-sm text-muted-foreground">No dependency has an exact advisory-reported simulation target in this scan.</div>}
      </section>
    </div>
  );
}

function SimulationResult({ value }: { value: RemediationSimulation }) {
  return <div className="space-y-4"><div className="grid gap-px overflow-hidden rounded-[2px] bg-border sm:grid-cols-2"><Snapshot label="Current" score={value.before.securityScore} risk={value.before.dependencyRisk} critical={value.before.criticalFindings} /><Snapshot label="Simulated" score={value.after.securityScore} risk={value.after.dependencyRisk} critical={value.after.criticalFindings} improved /></div><div className="rounded-[2px] bg-background p-5 ring-1 ring-border"><h3 className="font-semibold">Estimated change</h3><dl className="mt-4 grid gap-4 sm:grid-cols-2"><Datum label="Security score" value={`${signed(value.delta.securityScoreChange)}`} /><Datum label="Dependency risk" value={`−${value.delta.dependencyRiskReduction}`} /><Datum label="Critical findings removed" value={String(value.delta.criticalFindingsRemoved)} /><Datum label="Vulnerable paths removed" value={String(value.delta.vulnerablePathsRemoved)} /></dl><div className="mt-5 border-t pt-4"><p className="text-xs font-semibold">CVEs removed</p><p className="data mt-2 text-xs leading-5 text-muted-foreground">{value.removedVulnerabilityIds.join(", ") || "None estimated as removed at this target"}</p></div><p className="mt-4 text-xs leading-5 text-warning">{value.uncertainty}</p></div></div>;
}

function Snapshot({ label, score, risk, critical, improved }: { label: string; score: number; risk: number; critical: number; improved?: boolean }) {
  return <div className="bg-card p-5"><span className="text-xs text-muted-foreground">{label}</span><div className="mt-2 flex items-baseline gap-2"><b className={`data text-4xl ${improved ? "text-safe" : "text-warning"}`}>{score}</b><span className="text-xs text-muted-foreground">/100</span></div><p className="data mt-4 text-xs text-muted-foreground">Risk {risk} · Critical {critical}</p></div>;
}
function Datum({ label, value }: { label: string; value: string }) { return <div><dt className="text-xs text-muted-foreground">{label}</dt><dd className="data mt-1 font-semibold text-safe">{value}</dd></div>; }
function signed(value: number) { return `${value >= 0 ? "+" : ""}${value}`; }

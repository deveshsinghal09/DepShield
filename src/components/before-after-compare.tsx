import { ArrowRight, Check, GitCompareArrows } from "lucide-react";
import type { Scan } from "@/lib/types";
import { compareScans, severityCounts } from "@/lib/scan-selectors";
import { createSecurityDiff } from "@/lib/security-diff";
import { GradeBadge } from "./grade-badge";

export function BeforeAfterCompare({ before, after }: { before: Scan; after: Scan }) {
  const comparison = compareScans(before, after);
  const diff = createSecurityDiff(before, after);
  const scoreChange = after.score - before.score;
  return (
    <section className="space-y-4" data-ui="before-after-compare">
      <div className="grid gap-px border bg-border md:grid-cols-[1fr_56px_1fr]">
        <Snapshot label="Before" scan={before} />
        <div className="hidden place-items-center bg-background text-primary md:grid"><GitCompareArrows size={20} /></div>
        <Snapshot label="After" scan={after} after />
      </div>
      <dl className="grid gap-px border bg-border sm:grid-cols-2 xl:grid-cols-4">
        <DeltaMetric label="CVEs removed" value={comparison.removed} positive={comparison.removed >= 0} />
        <DeltaMetric label="Dependencies upgraded" value={comparison.upgraded} positive />
        <DeltaMetric label="Risk reduction" value={`${comparison.riskReduction > 0 ? "+" : ""}${comparison.riskReduction}%`} positive={comparison.riskReduction >= 0} />
        <DeltaMetric label="Score change" value={`${scoreChange >= 0 ? "+" : ""}${scoreChange}`} positive={scoreChange >= 0} />
      </dl>
      <div className="surface surface-outline p-5">
        <div className="flex items-center justify-between gap-4 border-b pb-4"><div><span className="hud-label text-primary">{"// RESOLVED EVIDENCE"}</span><h3 className="mt-2 font-extrabold">CVE removal ledger</h3></div><span className="data text-xl font-bold text-safe">{diff.findings.removed.length}</span></div>
        {diff.findings.removed.length ? (
          <ul className="mt-4 grid gap-2 md:grid-cols-2">
            {diff.findings.removed.slice(0, 8).map((finding) => <li key={finding.key} className="flex items-center gap-3 border p-3"><Check size={14} className="shrink-0 text-safe"/><span className="data text-xs text-muted-foreground line-through">{finding.cveAlias ?? finding.vulnerabilityId}</span><span className="data ml-auto text-[10px] text-safe">RESOLVED</span></li>)}
          </ul>
        ) : <p className="mt-4 text-sm text-muted-foreground">No findings disappeared between these two scans.</p>}
      </div>
    </section>
  );
}

function Snapshot({ label, scan, after = false }: { label: string; scan: Scan; after?: boolean }) {
  const counts = severityCounts(scan);
  return (
    <div className="bg-card p-6">
      <div className="flex items-center justify-between gap-5"><div><span className={`hud-label ${after ? "text-primary" : ""}`}>{label} snapshot</span><h3 className="mt-2 text-lg font-extrabold">{scan.project}</h3></div><GradeBadge grade={scan.grade} /></div>
      <div className="mt-8 flex items-end gap-3"><b className={`data text-6xl font-black tracking-[-.04em] ${after ? "text-safe" : ""}`}>{scan.score}</b><span className="data mb-2 text-xs text-muted-foreground">/100</span></div>
      <dl className="mt-6 grid grid-cols-2 gap-px border bg-border sm:grid-cols-4">
        <MiniMetric label="Critical" value={counts.critical} tone="text-critical" />
        <MiniMetric label="High" value={counts.high} tone="text-high" />
        <MiniMetric label="Medium" value={counts.medium} tone="text-warning" />
        <MiniMetric label="Vulnerable" value={scan.vulnerable} tone="text-foreground" />
      </dl>
      <span className="data mt-4 flex items-center gap-2 text-[10px] text-muted-foreground">{formatTimestamp(scan.createdAt)} <ArrowRight size={11} /> {scan.id.slice(0, 10)}</span>
    </div>
  );
}

function MiniMetric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className="bg-background p-3"><dt className="hud-label">{label}</dt><dd className={`data mt-1 font-bold ${tone}`}>{value}</dd></div>;
}

function DeltaMetric({ label, value, positive }: { label: string; value: string | number; positive: boolean }) {
  return <div className="bg-card p-5"><dt className="hud-label">{label}</dt><dd className={`data mt-2 text-2xl font-bold ${positive ? "text-safe" : "text-critical"}`}>{value}</dd></div>;
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC", hour12: false }).format(new Date(value)) + " UTC";
}

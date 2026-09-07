import { AlertTriangle, ArrowRight, TrendingDown, TrendingUp } from "lucide-react";
import { BeforeAfterCompare } from "@/components/before-after-compare";
import { ComparisonChart } from "@/components/comparison-chart";
import { EmptyState, SavedScanUnavailable } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { SecurityDiffLedger } from "@/components/security-diff-ledger";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { resolveScanSelection } from "@/lib/scan-resolution";
import { severityCounts, validateScanComparison } from "@/lib/scan-selectors";
import type { Scan } from "@/lib/types";
import { getScan, listScans } from "@/server/db";

export const dynamic = "force-dynamic";

export default async function Comparison({ searchParams }: { searchParams: Promise<{ before?: string; after?: string }> }) {
  const params = await searchParams;
  const scans = listScans();
  const beforeResolution = resolveScanSelection(scans, params.before, { lookup: getScan, fallback: (items) => items[1] });
  const afterResolution = resolveScanSelection(scans, params.after, { lookup: getScan, fallback: (items) => items[0] });
  if (beforeResolution.status === "missing") return <><PageHeader title="Before vs After" description="Compare two persisted scans and quantify remediation impact." /><SavedScanUnavailable scanId={beforeResolution.requestedId} recoveryHref="/comparison" /></>;
  if (afterResolution.status === "missing") return <><PageHeader title="Before vs After" description="Compare two persisted scans and quantify remediation impact." /><SavedScanUnavailable scanId={afterResolution.requestedId} recoveryHref="/comparison" /></>;
  const before = beforeResolution.scan;
  const after = afterResolution.scan;
  if (!before || !after) return <><PageHeader title="Before vs After" description="Compare two persisted scans and quantify remediation impact." /><EmptyState title="Two scans required" description="Run at least two project scans to compare security posture before and after remediation." /></>;
  const validation = validateScanComparison(before, after);
  if (!validation.valid) {
    return <><PageHeader title="Before vs After" description="Compare two persisted scans and quantify remediation impact." /><section className="space-y-6" data-ui="before-after"><ComparisonForm scans={scans} before={before} after={after} /><div className="surface surface-outline flex gap-3 border-warning p-4 text-sm" data-ui="comparison-rejected"><AlertTriangle className="shrink-0 text-warning" size={18} /><p><b>Comparison rejected.</b> {validation.message} Choose an earlier snapshot from the same project before calculating remediation impact.</p></div></section></>;
  }
  const regression = after.score < before.score;
  return (
    <>
      <PageHeader title="Before vs After" description="Compare two persisted scans and quantify remediation impact." />
      <section className="space-y-6" data-ui="before-after">
        <ComparisonForm scans={scans} before={before} after={after} />
        <BeforeAfterCompare before={before} after={after} />
        <SecurityDiffLedger before={before} after={after} />
        <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
          <Card><CardHeader><div><CardTitle>Severity movement</CardTitle><p className="mt-1 text-xs text-muted-foreground">Finding counts in each selected scan</p></div></CardHeader><CardContent><ComparisonChart before={severityCounts(before)} after={severityCounts(after)} /></CardContent></Card>
          <Card><CardHeader><CardTitle>Posture delta</CardTitle>{regression ? <TrendingUp className="text-destructive" size={18} /> : <TrendingDown className="text-safe" size={18} />}</CardHeader><CardContent><DeltaList before={before} after={after} /></CardContent></Card>
        </div>
      </section>
    </>
  );
}

function ComparisonForm({ scans, before, after }: { scans: Scan[]; before: Scan; after: Scan }) {
  return <form className="surface surface-outline grid gap-4 p-4 md:grid-cols-[1fr_auto_1fr_auto]"><SelectScan label="Before scan" name="before" scans={scans} value={before.id} /><span className="hidden items-end pb-2 text-muted-foreground md:flex"><ArrowRight size={18} /></span><SelectScan label="After scan" name="after" scans={scans} value={after.id} /><Button className="self-end" type="submit">Compare scans</Button></form>;
}

function SelectScan({ label, name, scans, value }: { label: string; name: string; scans: Scan[]; value: string }) {
  return <label><span className="hud-label mb-2 block">{label}</span><select name={name} defaultValue={value} className="h-10 w-full rounded-[2px] border bg-background px-3 text-sm">{scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.project} · {formatTimestamp(scan.createdAt)} · {scan.score}/{scan.grade}</option>)}</select></label>;
}

function DeltaList({ before, after }: { before: Scan; after: Scan }) {
  const a = severityCounts(before);
  const b = severityCounts(after);
  return <dl className="space-y-4"><Delta label="Critical" before={a.critical} after={b.critical} /><Delta label="High" before={a.high} after={b.high} /><Delta label="Medium" before={a.medium} after={b.medium} /><Delta label="Vulnerable dependencies" before={before.vulnerable} after={after.vulnerable} /></dl>;
}

function Delta({ label, before, after }: { label: string; before: number; after: number }) {
  const change = after - before;
  return <div className="flex items-center justify-between border-b pb-3 last:border-0"><dt className="text-muted-foreground">{label}</dt><dd className={`data font-bold ${change <= 0 ? "text-safe" : "text-destructive"}`}>{before} → {after} ({change > 0 ? "+" : ""}{change})</dd></div>;
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC", hour12: false }).format(new Date(value));
}

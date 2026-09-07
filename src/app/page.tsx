import { CriticalAction } from "@/components/critical-action";
import { DependencyTable } from "@/components/dependency-table";
import { SavedScanUnavailable } from "@/components/empty-state";
import { LandingHero } from "@/components/landing-hero";
import { MetricStrip } from "@/components/metric-strip";
import { PageHeader } from "@/components/page-header";
import { RegressionAlerts } from "@/components/regression-alerts";
import { RemediationSummary } from "@/components/remediation-summary";
import { RiskChart } from "@/components/risk-chart";
import { ScanOverviewHeader } from "@/components/scan-overview-header";
import { SeverityChart } from "@/components/severity-chart";
import { SourceCoverage } from "@/components/source-coverage";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { topRisk } from "@/lib/scan-selectors";
import { resolveSavedScan } from "@/server/scan-resolution";

export const dynamic = "force-dynamic";

export default async function Dashboard({ searchParams }: { searchParams: Promise<{ scan?: string }> }) {
  const { scan: id } = await searchParams;
  const { scans, resolution } = resolveSavedScan(id, id === undefined ? () => null : undefined);
  if (resolution.status === "missing") {
    return <><PageHeader title="Security Command Center" description="Contextual dependency exposure, evidence quality, attack paths, and remediation leverage." /><SavedScanUnavailable scanId={resolution.requestedId} recoveryHref="/" /></>;
  }
  const scan = resolution.scan;
  if (!scan) return <LandingHero latestScan={scans[0] ?? null} />;
  const previous = scans.find((item) => item.project === scan.project && item.id !== scan.id && new Date(item.createdAt) < new Date(scan.createdAt));
  const risky = topRisk(scan, 10);

  return (
    <>
      <PageHeader
        title="Security Command Center"
        description="Your dependency risks, recent changes, and the upgrades to make next."
      />
      <div className="space-y-8">
        <ScanOverviewHeader scan={scan} />
        <MetricStrip scan={scan} />
        <SourceCoverage scan={scan} />

        <div className="grid gap-6 xl:grid-cols-[1.08fr_.92fr]">
          <CriticalAction scan={scan} />
          <RemediationSummary scan={scan} />
        </div>

        <section>
          <div className="grid gap-6">
            <Card>
              <CardHeader><div><CardTitle>Severity distribution</CardTitle><p className="mt-1 text-xs text-muted-foreground">All merged findings in this scan</p></div></CardHeader>
              <CardContent><SeverityChart scan={scan} /></CardContent>
            </Card>
          </div>
        </section>

        <div className="grid gap-6 xl:grid-cols-[1.25fr_.75fr]">
          <Card>
            <CardHeader><div><CardTitle>Risk over time</CardTitle><p className="mt-1 text-xs text-muted-foreground">Project security score across persisted snapshots</p></div><span className="data text-xl font-bold">{scan.score}</span></CardHeader>
            <CardContent><RiskChart scans={scans.filter((item) => item.project === scan.project)} /></CardContent>
          </Card>
          <RegressionAlerts scan={scan} previous={previous} />
        </div>

        <section>
          <SectionMarker index="04" label="Dependency evidence" detail="Highest contextual priority with reachability, confidence, and advisory-reported upgrade evidence." />
          <DependencyTable items={risky} compact scanId={scan.id} emptyMessage="No risky dependencies found in this scan." />
        </section>

      </div>
    </>
  );
}

function SectionMarker({ index, label, detail }: { index: string; label: string; detail: string }) {
  return <div className="mb-4 flex flex-col justify-between gap-2 border-b pb-4 sm:flex-row sm:items-end"><div><span className="hud-label text-primary">/{index} {"//"} {label}</span><h2 className="mt-2 text-lg font-extrabold tracking-[-.02em]">{label}</h2></div><p className="max-w-2xl text-xs leading-5 text-muted-foreground sm:text-right">{detail}</p></div>;
}

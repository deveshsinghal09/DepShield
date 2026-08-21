import { PageHeader } from "@/components/page-header";
import { EmptyState } from "@/components/empty-state";
import { SecurityScore } from "@/components/security-score";
import { MetricStrip } from "@/components/metric-strip";
import { SeverityChart } from "@/components/severity-chart";
import { RiskChart } from "@/components/risk-chart";
import { DependencyTable } from "@/components/dependency-table";
import { RemediationSummary } from "@/components/remediation-summary";
import { UpgradePlan } from "@/components/upgrade-plan";
import { SourceCoverage } from "@/components/source-coverage";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { listScans } from "@/server/db";
import { topRisk } from "@/lib/scan-selectors";

export const dynamic = "force-dynamic";

export default function Dashboard() {
  const scans = listScans();
  const scan = scans[0];
  if (!scan) return <><PageHeader title="Threat Ledger" description="Current dependency exposure, remediation leverage, and security posture from persisted scans."/><EmptyState/></>;
  const risky = topRisk(scan, 10);
  return <><PageHeader title="Threat Ledger" description="Current dependency exposure, remediation leverage, and security posture from persisted scans." action={<div className="data rounded-sm border bg-card px-3 py-2 text-xs text-muted-foreground">{new Date(scan.createdAt).toLocaleString()}</div>}/><div className="space-y-6"><SourceCoverage scan={scan}/><div className="grid gap-6 xl:grid-cols-[1.55fr_1fr]"><SecurityScore scan={scan}/><Card><CardHeader><div><CardTitle>Severity distribution</CardTitle><p className="mt-1 text-xs text-muted-foreground">All unique findings in this scan</p></div></CardHeader><CardContent><SeverityChart scan={scan}/></CardContent></Card></div><MetricStrip scan={scan}/><div className="grid gap-6 xl:grid-cols-[1fr_360px]"><div className="space-y-6"><Card><CardHeader><div><CardTitle>Risk trend</CardTitle><p className="mt-1 text-xs text-muted-foreground">Security score across persisted scans</p></div><span className="data text-xl font-bold">{scan.score}</span></CardHeader><CardContent><RiskChart scans={scans}/></CardContent></Card><div><div className="mb-3 flex items-end justify-between"><div><h2 className="font-bold">Top risky dependencies</h2><p className="mt-1 text-xs text-muted-foreground">Highest explainable risk scores</p></div></div><DependencyTable items={risky} compact scanId={scan.id} emptyMessage="No risky dependencies found in this scan."/></div></div><RemediationSummary scan={scan}/></div><UpgradePlan scan={scan}/></div></>;
}

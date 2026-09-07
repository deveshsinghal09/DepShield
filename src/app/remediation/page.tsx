import { EmptyState, SavedScanUnavailable } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { RemediationLab } from "@/components/remediation-lab";
import { getFeatureFlags } from "@/lib/feature-flags";
import { resolveSavedScan } from "@/server/scan-resolution";

export const dynamic = "force-dynamic";

export default async function RemediationPage({ searchParams }: { searchParams: Promise<{ scan?: string }> }) {
  const { scan: id } = await searchParams;
  const sandboxEnabled = getFeatureFlags().remediationSandbox;
  const { resolution } = resolveSavedScan(id);
  if (resolution.status === "missing") return <><PageHeader title="Remediation Lab" description="Prioritize upgrades, preview compatibility risk, and simulate posture changes without modifying the project." /><SavedScanUnavailable scanId={resolution.requestedId} recoveryHref="/remediation" /></>;
  const scan = resolution.scan;
  return <><PageHeader title="Remediation Lab" description={sandboxEnabled ? "Prioritize upgrades, preview compatibility risk, and simulate posture changes without modifying the project." : "Prioritize deterministic upgrade work; what-if simulation is disabled for this deployment."} action={scan ? <span className="data rounded-sm bg-card px-3 py-2 text-xs text-muted-foreground ring-1 ring-border">{scan.project} · {scan.score}/100</span> : undefined} />{scan ? <RemediationLab scan={scan} /> : <EmptyState />}</>;
}

import { EmptyState, SavedScanUnavailable } from "@/components/empty-state";
import { FeatureUnavailable } from "@/components/feature-unavailable";
import { PageHeader } from "@/components/page-header";
import { PolicyEngine } from "@/components/policy-engine";
import { getFeatureFlags } from "@/lib/feature-flags";
import { listSecurityPolicies } from "@/server/db";
import { resolveSavedScan } from "@/server/scan-resolution";

export const dynamic = "force-dynamic";

export default async function PoliciesPage({ searchParams }: { searchParams: Promise<{ scan?: string }> }) {
  const { scan: id } = await searchParams;
  if (!getFeatureFlags().policyEngine) {
    return <><PageHeader title="Policy Gate" description="Turn contextual dependency evidence into an explainable PASS, WARNING, or FAIL result for CI/CD." /><FeatureUnavailable feature="Policy Gate" description="Policy editing and CI threshold evaluation are not enabled on this deployment. Saved scan evidence remains available elsewhere in the console." flag="ENABLE_POLICY_ENGINE" /></>;
  }
  const { scans, resolution } = resolveSavedScan(id);
  if (resolution.status === "missing") return <><PageHeader title="Policy Gate" description="Turn contextual dependency evidence into an explainable PASS, WARNING, or FAIL result for CI/CD." /><SavedScanUnavailable scanId={resolution.requestedId} recoveryHref="/policies" /></>;
  const scan = resolution.scan;
  const previous = scan ? scans.find((item) => item.project === scan.project && item.id !== scan.id && new Date(item.createdAt) < new Date(scan.createdAt)) : undefined;
  const savedPolicy = listSecurityPolicies()[0];
  return <><PageHeader title="Policy Gate" description="Turn contextual dependency evidence into an explainable PASS, WARNING, or FAIL result for CI/CD." action={scan ? <span className="data rounded-sm bg-card px-3 py-2 text-xs text-muted-foreground ring-1 ring-border">Scan {scan.id.slice(0, 8)}</span> : undefined} />{scan ? <PolicyEngine scan={scan} previous={previous} initialPolicy={savedPolicy} /> : <EmptyState />}</>;
}

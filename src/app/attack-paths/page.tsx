import { AttackPathGraph } from "@/components/attack-path-graph";
import { EmptyState, SavedScanUnavailable } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { resolveSavedScan } from "@/server/scan-resolution";

export const dynamic = "force-dynamic";

export default async function AttackPathsPage({ searchParams }: { searchParams: Promise<{ scan?: string }> }) {
  const { scan: id } = await searchParams;
  const { resolution } = resolveSavedScan(id);
  if (resolution.status === "missing") return <><PageHeader title="Attack Paths" description="Trace conservative route-to-module-to-dependency evidence and inspect estimated blast radius." /><SavedScanUnavailable scanId={resolution.requestedId} recoveryHref="/attack-paths" /></>;
  const scan = resolution.scan;
  return (
    <>
      <PageHeader
        title="Attack Paths"
        description="Trace persisted, CVE-specific route and dependency evidence without overstating static reachability."
        action={scan ? (
          <span className="data rounded-sm bg-card px-3 py-2 text-xs text-muted-foreground ring-1 ring-border">
            {scan.attackPaths?.length ?? 0} persisted paths · {scan.sourceFilesAnalyzed ?? 0} source files
          </span>
        ) : undefined}
      />
      {scan ? (
        <AttackPathGraph attackPaths={scan.attackPaths ?? []} dependencies={scan.items} />
      ) : (
        <EmptyState />
      )}
    </>
  );
}

import { ScanIntake } from "@/components/scan-intake";
import { ScanStatusStrip } from "@/components/scan-status-strip";
import { buildScanIntakeSnapshot } from "@/lib/scan-intake-snapshot";
import { getScan, listScans } from "@/server/db";

export const dynamic = "force-dynamic";

export default async function ScanPage({ searchParams }: { searchParams: Promise<{ scan?: string }> }) {
  const { scan: requestedId } = await searchParams;
  const latest = (requestedId ? getScan(requestedId) : null) ?? listScans(1)[0] ?? null;
  const snapshot = buildScanIntakeSnapshot(latest);
  return (
    <div className="min-h-[calc(100dvh-3.5rem)] border-x" data-ui="scan-page">
      <ScanIntake latestScan={snapshot} />
      <ScanStatusStrip lastScanAt={latest?.createdAt} project={latest?.project} />
    </div>
  );
}

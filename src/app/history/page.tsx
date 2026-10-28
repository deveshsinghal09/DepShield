import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { ScanHistoryTable } from "@/components/scan-history-table";
import { listScans } from "@/server/db";

export const dynamic = "force-dynamic";

export default function History() {
  const scans = listScans();
  return (
    <>
      <PageHeader title="Scan History" description="Open a saved scan to review its findings and security score." />
      {scans.length ? <ScanHistoryTable scans={scans} /> : <EmptyState />}
    </>
  );
}

import { Download, FileJson2 } from "lucide-react";
import { EmptyState, SavedScanUnavailable } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { SecurityStory } from "@/components/security-story";
import { resolveSavedScan } from "@/server/scan-resolution";

export const dynamic = "force-dynamic";

export default async function StoryPage({ searchParams }: { searchParams: Promise<{ scan?: string }> }) {
  const { scan: id } = await searchParams;
  const { scans, resolution } = resolveSavedScan(id);
  if (resolution.status === "missing") return <><PageHeader title="Explain This Scan" description="A presentation-ready security story with observed, estimated, and unavailable evidence clearly separated." /><SavedScanUnavailable scanId={resolution.requestedId} recoveryHref="/story" /></>;
  const scan = resolution.scan;
  const previous = scan ? scans.find((item) => item.project === scan.project && item.id !== scan.id && new Date(item.createdAt) < new Date(scan.createdAt)) : undefined;
  const evidenceHref = scan ? `/api/scans/${scan.id}/evidence${previous ? `?before=${previous.id}` : ""}` : "#";
  return <><PageHeader title="Explain This Scan" description="A presentation-ready security story with observed, estimated, and unavailable evidence clearly separated." action={scan ? <div className="flex flex-wrap gap-2"><a href={`/api/scans/${scan.id}/sbom`} data-ui="sbom-export" className="inline-flex h-10 items-center gap-2 rounded-sm bg-card px-4 text-xs font-semibold ring-1 ring-border hover:bg-secondary"><FileJson2 size={14} />Export SBOM</a><a href={evidenceHref} data-ui="evidence-pack" className="inline-flex h-10 items-center gap-2 rounded-sm bg-primary px-4 text-xs font-semibold text-primary-foreground"><Download size={14} />Evidence Pack</a></div> : undefined} />{scan ? <SecurityStory scan={scan} previous={previous} /> : <EmptyState />}</>;
}

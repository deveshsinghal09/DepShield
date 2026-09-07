import { Braces, Users } from "lucide-react";
import type { Scan } from "@/lib/types";

export function ScanSummaries({ scan }: { scan: Scan }) {
  if (!scan.summary) return null;
  return <section className="surface surface-outline" data-ui="scan-summaries"><header className="flex items-center justify-between border-b px-5 py-4"><div><h2 className="text-sm font-bold">Explainable scan summary</h2><p className="mt-1 text-xs text-muted-foreground">Generated from stored evidence · {scan.summary.generatedBy}</p></div></header><div className="grid gap-px bg-border lg:grid-cols-2"><article className="bg-card p-5"><div className="flex items-center gap-2 text-primary"><Users size={15} /><h3 className="text-xs font-semibold">Executive summary</h3></div><p className="mt-3 text-sm leading-7 text-secondary-foreground">{scan.summary.executive}</p></article><article className="bg-card p-5"><div className="flex items-center gap-2 text-primary"><Braces size={15} /><h3 className="text-xs font-semibold">Developer summary</h3></div><p className="mt-3 text-sm leading-7 text-secondary-foreground">{scan.summary.developer}</p></article></div></section>;
}

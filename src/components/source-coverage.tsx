import { AlertTriangle, CheckCircle2 } from "lucide-react";
import type { Scan } from "@/lib/types";

export function scanIsIncomplete(scan: Scan) {
  return Boolean(scan.warnings?.length || scan.sourceStatus?.some(source => source.status !== "ok"));
}

export function SourceCoverage({ scan }: { scan: Scan }) {
  const incomplete = scanIsIncomplete(scan);
  const sources = scan.sourceStatus ?? [];
  return <section className={`surface surface-outline flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between ${incomplete ? "border-warning/35" : ""}`} data-ui="source-coverage"><div className="flex gap-3">{incomplete ? <AlertTriangle className="mt-0.5 shrink-0 text-warning" size={18}/> : <CheckCircle2 className="mt-0.5 shrink-0 text-safe" size={18}/>}<div><b className="text-sm">{incomplete ? "Scan coverage is incomplete" : "All vulnerability sources completed"}</b><p className="mt-1 text-xs leading-5 text-muted-foreground">{incomplete ? "Treat this score as provisional. One or more intelligence sources did not complete." : "npm audit and OSV evidence were available for this verdict."}</p></div></div><div className="flex flex-wrap gap-2">{sources.map(source=><span key={source.source} title={source.message??undefined} className={`data rounded-full border px-2.5 py-1 text-[11px] ${source.status==="ok"?"border-safe/25 text-safe":"border-warning/30 text-warning"}`}>{source.source} · {source.status}</span>)}{scan.warnings?.length?<span className="data rounded-full border border-warning/30 px-2.5 py-1 text-[11px] text-warning">{scan.warnings.length} warning{scan.warnings.length===1?"":"s"}</span>:null}</div></section>;
}

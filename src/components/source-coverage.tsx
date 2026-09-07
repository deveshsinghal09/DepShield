import { AlertTriangle, CheckCircle2 } from "lucide-react";
import type { Scan } from "@/lib/types";

const providerWarningCodes = new Set([
  "NPM_AUDIT_FAILED",
  "OSV_API_FAILED",
  "NVD_API_FAILED",
  "GITHUB_API_FAILED",
  "MISSING_CVSS",
]);

export function scanIsIncomplete(scan: Scan) {
  return Boolean(
    scan.sourceStatus?.some((source) => source.status === "failed" || source.status === "partial")
    || scan.warnings?.some((warning) =>
      providerWarningCodes.has(warning.code)
      || warning.code === "REACHABILITY_INCOMPLETE"
      || warning.code === "REACHABILITY_DISABLED"),
  );
}

export function SourceCoverage({ scan }: { scan: Scan }) {
  const sources = scan.sourceStatus ?? [];
  const providerIncomplete = sources.some((source) => source.status === "failed" || source.status === "partial")
    || Boolean(scan.warnings?.some((warning) => providerWarningCodes.has(warning.code)));
  const reachabilityIncomplete = Boolean(scan.warnings?.some((warning) =>
    warning.code === "REACHABILITY_INCOMPLETE" || warning.code === "REACHABILITY_DISABLED"));
  const incomplete = scanIsIncomplete(scan);
  const reachability = (scan.sourceFilesAnalyzed ?? 0) > 0;
  const explanation = providerIncomplete
    ? "Treat this verdict as provisional. One or more configured vulnerability sources failed or returned incomplete evidence."
    : reachabilityIncomplete
      ? "Vulnerability sources completed, but static source coverage is disabled or incomplete. UNKNOWN and NOT_OBSERVED never mean safe."
      : reachability
        ? `${scan.sourceFilesAnalyzed} source files were analyzed conservatively; NOT_OBSERVED never means safe.`
        : "npm audit and OSV completed. Source reachability remains UNKNOWN until a project-folder scan is supplied.";

  return (
    <section
      className={`surface surface-outline flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between ${incomplete ? "ring-warning/35" : ""}`}
      data-ui="source-coverage"
    >
      <div className="flex gap-3">
        {incomplete
          ? <AlertTriangle className="mt-0.5 shrink-0 text-warning" size={18} />
          : <CheckCircle2 className="mt-0.5 shrink-0 text-safe" size={18} />}
        <div>
          <b className="text-sm">{incomplete ? "Evidence coverage is partial" : reachability ? "Vulnerability and source evidence recorded" : "Vulnerability evidence recorded"}</b>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">{explanation}</p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        {sources.map((source) => (
          <span
            key={source.source}
            title={source.message ?? undefined}
            className={`data rounded-[2px] px-2.5 py-1 text-xs ring-1 ${source.status === "ok" ? "text-safe ring-safe/25" : source.status === "skipped" ? "text-muted-foreground ring-border" : "text-warning ring-warning/30"}`}
          >
            {source.source} · {source.status}
          </span>
        ))}
        {scan.warnings?.length ? (
          <span className="data rounded-[2px] px-2.5 py-1 text-xs text-warning ring-1 ring-warning/30">
            {scan.warnings.length} warning{scan.warnings.length === 1 ? "" : "s"}
          </span>
        ) : null}
      </div>
    </section>
  );
}

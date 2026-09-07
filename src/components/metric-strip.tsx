import type { Scan } from "@/lib/types";
import { severityCounts } from "@/lib/scan-selectors";
import { MetricCard } from "./metric-card";

export function MetricStrip({ scan }: { scan: Scan }) {
  const findings = scan.items.flatMap((item) => item.vulnerabilities);
  const direct = scan.items.filter((item) => item.direct).length;
  const transitive = Math.max(0, scan.dependencies - direct);
  const completeFix = scan.items.filter((item) => item.vulnerabilities.length > 0 && item.vulnerabilities.every((vulnerability) => Boolean(vulnerability.fixedVersion))).length;
  const measuredCvss = findings.filter((item) => item.cvssAvailable !== false);
  const averageCvss = measuredCvss.length ? measuredCvss.reduce((sum, item) => sum + item.cvss, 0) / measuredCvss.length : null;
  const counts = severityCounts(scan);

  return (
    <dl className="surface surface-outline grid gap-px bg-border sm:grid-cols-2 xl:grid-cols-4" data-ui="metric-strip">
      <MetricCard label="Active vulnerabilities" value={findings.length} detail={`${counts.critical} critical · ${counts.high} high`} tone={findings.length ? "critical" : "safe"} />
      <MetricCard label="Dependency relationship" value={`${direct} / ${transitive}`} detail="Direct / transitive packages" />
      <MetricCard label="Complete fix available" value={completeFix} detail={`${scan.vulnerable} vulnerable packages assessed`} tone={completeFix ? "safe" : scan.vulnerable ? "warning" : "safe"} />
      <MetricCard label="Average open CVSS" value={averageCvss === null ? "—" : averageCvss.toFixed(1)} detail={averageCvss === null ? "No reported CVSS evidence" : `${measuredCvss.length} scored findings`} tone={averageCvss === null ? "neutral" : averageCvss >= 7 ? "critical" : averageCvss >= 4 ? "warning" : "safe"} />
    </dl>
  );
}

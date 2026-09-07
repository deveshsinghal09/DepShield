import { cveCount, fixableCount, highestCvss, severityCounts, topRisk } from "./scan-selectors";
import type { Dependency, Scan, Severity } from "./types";

export type ScanIntakeLedgerItem = {
  name: string;
  version: string;
  direct: boolean;
  path: string;
  vulnerabilityCount: number;
  highestCvss: number;
  highestSeverity: Severity;
  hasFix: boolean;
};

export type ScanIntakeSnapshot = {
  id: string;
  createdAt: string;
  project: string;
  score: number;
  grade: string;
  dependencies: number;
  findings: number;
  fixable: number;
  counts: Record<Severity, number>;
  items: ScanIntakeLedgerItem[];
};

export function buildScanIntakeSnapshot(scan: Scan | null): ScanIntakeSnapshot | null {
  if (!scan) return null;
  return {
    id: scan.id,
    createdAt: scan.createdAt,
    project: scan.project,
    score: scan.score,
    grade: scan.grade,
    dependencies: scan.dependencies,
    findings: cveCount(scan),
    fixable: fixableCount(scan),
    counts: severityCounts(scan),
    items: topRisk(scan, 8).map((item) => ({
      name: item.name,
      version: item.version,
      direct: item.direct,
      path: item.path,
      vulnerabilityCount: item.vulnerabilities.length,
      highestCvss: highestCvss(item),
      highestSeverity: highestSeverity(item),
      hasFix: item.vulnerabilities.some((finding) => Boolean(finding.fixedVersion)),
    })),
  };
}

function highestSeverity(item: Dependency): Severity {
  const order: Severity[] = ["critical", "high", "medium", "low", "unknown"];
  return order.find((severity) => item.vulnerabilities.some((finding) => finding.severity === severity)) ?? "unknown";
}

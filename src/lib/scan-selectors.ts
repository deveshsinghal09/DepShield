import { compareExactVersions } from "./semver";
import type { Dependency, Scan, Severity } from "./types";

export const severityOrder: Severity[] = ["critical", "high", "medium", "low", "unknown"];

export type ScanComparisonValidation =
  | { valid: true }
  | { valid: false; code: "PROJECT_MISMATCH" | "REVERSE_CHRONOLOGY"; message: string };

export function validateScanComparison(before: Scan, after: Scan): ScanComparisonValidation {
  if (before.project !== after.project) {
    return { valid: false, code: "PROJECT_MISMATCH", message: "Comparison scans must belong to the same project." };
  }
  if (new Date(before.createdAt).getTime() > new Date(after.createdAt).getTime()) {
    return { valid: false, code: "REVERSE_CHRONOLOGY", message: "The before scan must not be newer than the after scan." };
  }
  return { valid: true };
}

export function severityCounts(scan: Scan) {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const item of scan.items) {
    for (const vulnerability of item.vulnerabilities) counts[vulnerability.severity]++;
  }
  return counts;
}

export function highCount(scan: Scan) {
  const counts = severityCounts(scan);
  return counts.critical + counts.high;
}

export function fixableCount(scan: Scan) {
  return scan.items.reduce((sum, item) => sum + item.vulnerabilities.filter((value) => Boolean(value.fixedVersion)).length, 0);
}

export function cveCount(scan: Scan) {
  return scan.items.reduce((sum, item) => sum + item.vulnerabilities.length, 0);
}

export function topRisk(scan: Scan, limit = 8) {
  return scan.items.filter((item) => item.risk > 0).toSorted((left, right) => right.risk - left.risk).slice(0, limit);
}

export function highestCvss(item: Dependency) {
  return Math.max(0, ...item.vulnerabilities.map((value) => value.cvss));
}

function stripNodeVersion(node: string) {
  const value = node.trim();
  const separator = value.lastIndexOf("@");
  if (separator <= 0) return value.toLowerCase();
  const suffix = value.slice(separator + 1);
  return /^(?:v?\d|unknown$|[<>=~^*])/i.test(suffix) ? value.slice(0, separator).toLowerCase() : value.toLowerCase();
}

/** Stable dependency-instance identity for paths whose nodes include versions. */
function dependencyUpgradeIdentity(dependency: Dependency) {
  const observedPaths = dependency.paths
    ?.map((path) => path.nodes.map(stripNodeVersion).join(" → "))
    .filter(Boolean)
    .toSorted();
  const path = observedPaths?.[0] ?? dependency.path.split("→").map(stripNodeVersion).join(" → ");
  return `${dependency.name.trim().toLowerCase()}|${path}`;
}

export function compareScans(before: Scan, after: Scan) {
  const validation = validateScanComparison(before, after);
  if (!validation.valid) throw new RangeError(validation.message);

  const beforeCounts = severityCounts(before);
  const afterCounts = severityCounts(after);
  const beforeCves = new Set(before.items.flatMap((item) => item.vulnerabilities.map((value) => value.cveAlias ?? value.id)));
  const afterCves = new Set(after.items.flatMap((item) => item.vulnerabilities.map((value) => value.cveAlias ?? value.id)));
  const removed = [...beforeCves].filter((id) => !afterCves.has(id)).length;
  const beforeVersions = new Map(before.items.map((item) => [dependencyUpgradeIdentity(item), item.version]));
  const upgraded = after.items.filter((item) => {
    const previous = beforeVersions.get(dependencyUpgradeIdentity(item));
    if (!previous) return false;
    const comparison = compareExactVersions(item.version, previous);
    return comparison !== null && comparison > 0;
  }).length;
  const beforeRisk = 100 - before.score;
  const afterRisk = 100 - after.score;
  const riskReduction = beforeRisk === 0
    ? (afterRisk === 0 ? 0 : -100)
    : Math.round(((beforeRisk - afterRisk) / beforeRisk) * 100);
  return { before: beforeCounts, after: afterCounts, removed, upgraded, riskReduction };
}

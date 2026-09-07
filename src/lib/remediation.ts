import type { Dependency, RemediationClassification, RemediationLabel, UpgradePlanItem } from "./types";

type Version = readonly [major: number, minor: number, patch: number];

function exactVersion(value: string): Version | null {
  const match = value.trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function compareVersion(left: string, right: string) {
  const a = exactVersion(left);
  const b = exactVersion(right);
  if (!a || !b) return null;
  for (let index = 0; index < 3; index++) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return 0;
}

function highestFixedTarget(dependency: Dependency) {
  return dependency.vulnerabilities
    .map((finding) => finding.fixedVersion)
    .filter((version): version is string => Boolean(version && exactVersion(version)))
    .toSorted((left, right) => compareVersion(left, right) ?? left.localeCompare(right))
    .at(-1) ?? null;
}

export function remediationLabel(dependency: Dependency): RemediationLabel | null {
  if (!dependency.vulnerabilities.length) return null;
  if (dependency.recommendation === "no-fix") return "No Fix Available";
  if (!dependency.direct) return "Update Parent Dependency";
  if (dependency.recommendation === "partial-fix") return "Manual Review";
  if (dependency.latest === dependency.version) return "No Fix Available";

  const current = exactVersion(dependency.version);
  const target = exactVersion(dependency.latest);
  if (!current || !target) return "Manual Review";
  if (target[0] > current[0]) return "Major Upgrade";
  if (target[1] > current[1]) return "Minor Upgrade";
  return "Safe Auto Fix";
}

const effort: Record<RemediationLabel, number> = {
  "Safe Auto Fix": 0,
  "Minor Upgrade": 1,
  "Update Parent Dependency": 2,
  "Major Upgrade": 3,
  "Manual Review": 4,
  "No Fix Available": 5,
};

const classification: Record<RemediationLabel, RemediationClassification> = {
  "Safe Auto Fix": "SAFE PATCH",
  "Minor Upgrade": "MINOR UPGRADE",
  "Update Parent Dependency": "UPDATE PARENT",
  "Major Upgrade": "MAJOR UPGRADE",
  "Manual Review": "MANUAL REVIEW",
  "No Fix Available": "NO FIX",
};

export function generateUpgradePlan(items: Dependency[]): UpgradePlanItem[] {
  return items.flatMap((dependency) => {
    const label = remediationLabel(dependency);
    if (!label) return [];

    const candidate = dependency.recommendation === "upgrade"
      ? dependency.latest
      : dependency.recommendation === "partial-fix"
        ? highestFixedTarget(dependency)
        : null;
    // A transitive child version is evidence for the parent-upgrade search, not
    // a safe package.json target for this application.
    const targetVersion = dependency.direct ? candidate : null;
    const cvesResolved = targetVersion
      ? dependency.vulnerabilities
        .filter((finding) => finding.fixedVersion && (compareVersion(finding.fixedVersion, targetVersion) ?? 1) <= 0)
        .map((finding) => finding.cveAlias ?? finding.id)
      : [];
    const remainingCves = dependency.vulnerabilities
      .map((finding) => finding.cveAlias ?? finding.id)
      .filter((id) => !cvesResolved.includes(id));
    const conflicts = [
      ...(!dependency.direct
        ? [`Resolve through ${dependency.parentPackages?.join(", ") || "the introducing parent dependency"}; the child version cannot be pinned safely in isolation.`]
        : []),
      ...(dependency.recommendation === "partial-fix"
        ? ["The candidate addresses only part of the finding set; review the remaining advisories before treating this dependency as remediated."]
        : []),
    ];

    return [{
      dependency,
      label,
      classification: classification[label],
      targetVersion,
      effort: effort[label],
      priority: dependency.risk * 10 - effort[label],
      expectedRiskReduction: targetVersion
        ? Math.round(dependency.risk * (cvesResolved.length / Math.max(1, dependency.vulnerabilities.length)))
        : 0,
      cvesResolved,
      remainingCves,
      conflicts,
      compatibility: dependency.compatibility,
    } satisfies UpgradePlanItem];
  }).toSorted((left, right) => right.priority - left.priority || left.dependency.name.localeCompare(right.dependency.name));
}

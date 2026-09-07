export type SemverChange = "none" | "patch" | "minor" | "major" | "downgrade" | "unknown";
export type CompatibilityRisk = "low" | "medium" | "high";
export type EstimateConfidence = "low" | "medium";

export type UpgradeImpactInput = {
  currentVersion: string;
  targetVersion: string;
  direct: boolean;
  importedApis?: string[];
  relatedRoutes?: string[];
};

export type UpgradeImpactEstimate = {
  score: number;
  risk: CompatibilityRisk;
  semverChange: SemverChange;
  confidence: EstimateConfidence;
  reasons: string[];
  testingFocus: string[];
  uncertainty: string;
};

type ParsedVersion = readonly [major: number, minor: number, patch: number];

function parseVersion(value: string): ParsedVersion | null {
  const match = value.trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function compareVersion(a: ParsedVersion, b: ParsedVersion) {
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return 0;
}

function semverChange(currentVersion: string, targetVersion: string): SemverChange {
  const current = parseVersion(currentVersion), target = parseVersion(targetVersion);
  if (!current || !target) return "unknown";
  const comparison = compareVersion(target, current);
  if (comparison < 0) return "downgrade";
  if (comparison === 0) return "none";
  if (target[0] !== current[0]) return "major";
  if (target[1] !== current[1]) return "minor";
  return "patch";
}

function uniqueEvidence(values: string[] | undefined) {
  return [...new Set((values ?? []).map(value => value.trim()).filter(Boolean))];
}

export function estimateUpgradeImpact(input: UpgradeImpactInput): UpgradeImpactEstimate {
  const change = semverChange(input.currentVersion, input.targetVersion);
  const importedApis = uniqueEvidence(input.importedApis), relatedRoutes = uniqueEvidence(input.relatedRoutes);
  const baseRisk: Record<SemverChange, number> = { none: 0, patch: 10, minor: 35, major: 70, downgrade: 80, unknown: 55 };
  let score = baseRisk[change];
  const reasons: string[] = [];

  if (change === "none") reasons.push("The target is the currently installed version, so no compatibility change is expected.");
  if (change === "patch") reasons.push("Patch-level upgrades usually preserve the public API, but behavior can still change.");
  if (change === "minor") reasons.push("A minor-version change can add behavior and deprecations while remaining semver-compatible.");
  if (change === "major") reasons.push("A major-version change indicates potential breaking API or runtime behavior changes.");
  if (change === "downgrade") reasons.push("The selected target is older than the installed version and may reintroduce removed behavior.");
  if (change === "unknown") reasons.push("The version change could not be classified from exact semantic versions.");

  if (change !== "none") {
    if (input.direct) {
      score += 8;
      reasons.push("The application directly depends on this package.");
    } else {
      reasons.push("The package is transitive, so compatibility is primarily controlled through its parent dependency.");
    }
    if (importedApis.length) {
      score += Math.min(15, importedApis.length * 2);
      reasons.push(`${importedApis.length} imported API${importedApis.length === 1 ? " was" : "s were"} observed in application code.`);
    }
    if (relatedRoutes.length) {
      score += Math.min(10, relatedRoutes.length * 2);
      reasons.push(`${relatedRoutes.length} related route${relatedRoutes.length === 1 ? " requires" : "s require"} regression testing.`);
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const risk: CompatibilityRisk = score >= 65 ? "high" : score >= 35 ? "medium" : "low";
  const completeUsageEvidence = input.importedApis !== undefined && input.relatedRoutes !== undefined;
  const confidence: EstimateConfidence = change !== "unknown" && completeUsageEvidence ? "medium" : "low";
  const testingFocus = [
    ...importedApis.map(api => `Verify calls to ${api}.`),
    ...relatedRoutes.map(route => `Exercise ${route}.`),
  ];
  if (!testingFocus.length) testingFocus.push("Run the package's existing unit and integration test coverage.");

  return {
    score,
    risk,
    semverChange: change,
    confidence,
    reasons,
    testingFocus,
    uncertainty: "Estimated compatibility risk based on semantic-version distance and observed application usage. Release notes, package resolution, and runtime behavior were not verified.",
  };
}

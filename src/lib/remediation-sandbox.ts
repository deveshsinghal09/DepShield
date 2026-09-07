import { estimateUpgradeImpact } from "./compatibility";
import { averageConfidence, calculatePosture, deterministicSummary, fixableRiskPercent } from "./posture";
import { dependencyRisk, grade, projectScore } from "./risk";
import { applyRiskPropagation } from "./risk-propagation";
import type { AttackPath, CompatibilityPreview, Dependency, Scan, Vulnerability } from "./types";

export type RemediationSimulationRequest = {
  dependencyName: string;
  targetVersion: string;
  dependencyPath?: string;
  installedVersion?: string;
};

export type SimulationSnapshot = {
  securityScore: number;
  dependencyRisk: number;
  criticalFindings: number;
  criticalDependencies: number;
  vulnerablePaths: number;
};

export type SimulatedScan = Scan & {
  simulated: true;
  sourceScanId: string;
  simulation: {
    dependencyName: string;
    fromVersion: string;
    targetVersion: string;
    removedVulnerabilityIds: string[];
    remainingVulnerabilityIds: string[];
  };
};

export type RemediationSimulation = {
  simulated: true;
  sourceScanId: string;
  dependencyName: string;
  fromVersion: string;
  targetVersion: string;
  removedVulnerabilityIds: string[];
  remainingVulnerabilityIds: string[];
  before: SimulationSnapshot;
  after: SimulationSnapshot;
  delta: {
    securityScoreChange: number;
    dependencyRiskReduction: number;
    criticalFindingsRemoved: number;
    criticalDependenciesReduced: number;
    vulnerablePathsRemoved: number;
  };
  confidence: "medium";
  assumptions: string[];
  uncertainty: string;
  scan: SimulatedScan;
};

type ParsedVersion = readonly [major: number, minor: number, patch: number];

function parseExactSemver(value: string): ParsedVersion | null {
  const match = value.trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function compareSemver(a: string, b: string): number | null {
  const left = parseExactSemver(a), right = parseExactSemver(b);
  if (!left || !right) return null;
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

function vulnerabilityId(vulnerability: Vulnerability) {
  return vulnerability.cveAlias ?? vulnerability.id;
}

function pathCount(dependency: Dependency) {
  const paths = dependency.paths?.map(path => path.display) ?? [dependency.path];
  return new Set(paths.filter(Boolean)).size;
}

function snapshot(items: Dependency[], dependency: Dependency, score: number, attackPaths?: AttackPath[]): SimulationSnapshot {
  return {
    securityScore: score,
    dependencyRisk: dependency.risk,
    criticalFindings: items.reduce((sum, item) => sum + item.vulnerabilities.filter(vulnerability => vulnerability.severity === "critical").length, 0),
    criticalDependencies: items.filter(item => item.vulnerabilities.some(vulnerability => vulnerability.severity === "critical")).length,
    vulnerablePaths: attackPaths
      ? attackPaths.length
      : items.reduce((sum, item) => sum + (item.vulnerabilities.length ? pathCount(item) : 0), 0),
  };
}

function recommendationFor(remaining: Vulnerability[]): Dependency["recommendation"] {
  if (!remaining.length) return "none";
  const reportedExactFixes = remaining.map(vulnerability => Boolean(vulnerability.fixedVersion && parseExactSemver(vulnerability.fixedVersion)));
  if (reportedExactFixes.every(Boolean)) return "upgrade";
  if (reportedExactFixes.some(Boolean)) return "partial-fix";
  return "no-fix";
}

function simulatedPath(value: string, dependency: Dependency, targetVersion: string) {
  return value.replaceAll(`${dependency.name}@${dependency.version}`, `${dependency.name}@${targetVersion}`);
}

export function simulateDependencyUpgrade(scan: Scan, request: RemediationSimulationRequest): RemediationSimulation {
  const dependency = scan.items.find(item => item.name === request.dependencyName
    && (!request.dependencyPath || item.path === request.dependencyPath)
    && (!request.installedVersion || item.version === request.installedVersion));
  if (!dependency) throw new Error(`Dependency ${request.dependencyName} was not found in scan ${scan.id}.`);
  if (!parseExactSemver(dependency.version)) throw new Error(`Installed version ${dependency.version} is not an exact semantic version.`);
  if (!parseExactSemver(request.targetVersion)) throw new Error(`Target version ${request.targetVersion} is not an exact semantic version.`);
  const direction = compareSemver(request.targetVersion, dependency.version);
  if (direction === null || direction <= 0) throw new Error(`Target version ${request.targetVersion} must be newer than ${dependency.version}.`);

  const removed = dependency.vulnerabilities.filter(vulnerability => {
    if (!vulnerability.fixedVersion) return false;
    const comparison = compareSemver(vulnerability.fixedVersion, request.targetVersion);
    return comparison !== null && comparison <= 0;
  });
  const removedKeys = new Set(removed.map(vulnerability => vulnerability.id));
  const remaining = dependency.vulnerabilities.filter(vulnerability => !removedKeys.has(vulnerability.id));
  const remainingHasReportedFix = remaining.length > 0 && remaining.every(vulnerability => Boolean(vulnerability.fixedVersion && parseExactSemver(vulnerability.fixedVersion)));
  const impact = estimateUpgradeImpact({
    currentVersion: dependency.version,
    targetVersion: request.targetVersion,
    direct: dependency.direct,
    importedApis: dependency.reachability?.observedFunctions ?? [],
    relatedRoutes: dependency.blastRadius?.routes ?? [],
  });
  const updatedDependency: Dependency = {
    ...dependency,
    version: request.targetVersion,
    path: simulatedPath(dependency.path, dependency, request.targetVersion),
    paths: dependency.paths?.map(path => ({
      nodes: path.nodes.map(node => simulatedPath(node, dependency, request.targetVersion)),
      display: simulatedPath(path.display, dependency, request.targetVersion),
    })),
    vulnerabilities: remaining,
    risk: dependencyRisk(Math.max(0, ...remaining.map(vulnerability => vulnerability.cvss)), dependency.direct, remainingHasReportedFix, remaining.length),
    latest: remaining.length ? dependency.latest : request.targetVersion,
    recommendation: recommendationFor(remaining),
    contextual: undefined,
    propagation: undefined,
    compatibility: {
      level: impact.risk.toUpperCase() as CompatibilityPreview["level"],
      score: impact.score,
      currentVersion: dependency.version,
      targetVersion: request.targetVersion,
      importedApis: dependency.reachability?.observedFunctions ?? [],
      reasons: [...impact.reasons, impact.uncertainty],
      suggestedTests: impact.testingFocus,
      estimated: true,
    },
  };
  const items = applyRiskPropagation(scan.items.map(item => item === dependency ? updatedDependency : item));
  const score = projectScore(items);
  const removedVulnerabilityIds = removed.map(vulnerabilityId), remainingVulnerabilityIds = remaining.map(vulnerabilityId);
  const removedPathFindings = new Set(removedVulnerabilityIds.map((value) => value.toUpperCase()));
  const simulatedAttackPaths = scan.attackPaths?.flatMap((attackPath) => {
    const selectedInstance = attackPath.dependencyName === dependency.name
      && attackPath.dependencyVersion === dependency.version
      && attackPath.dependencyPath === dependency.path;
    if (selectedInstance && removedPathFindings.has(attackPath.findingId.toUpperCase())) return [];
    if (!selectedInstance) return [attackPath];
    return [{
      ...attackPath,
      dependencyVersion: request.targetVersion,
      dependencyPath: simulatedPath(attackPath.dependencyPath, dependency, request.targetVersion),
      nodes: attackPath.nodes.map((node) => simulatedPath(node, dependency, request.targetVersion)),
      display: simulatedPath(attackPath.display, dependency, request.targetVersion),
    }];
  });
  const vulnerableItems = items.filter(item => item.vulnerabilities.length > 0);
  const topRisk = vulnerableItems.toSorted((left, right) => right.risk - left.risk).slice(0, 5);
  const simulatedScan: SimulatedScan = {
    ...scan,
    id: `simulation:${scan.id}:${dependency.name}@${request.targetVersion}`,
    score,
    grade: grade(score),
    vulnerable: items.filter(item => item.vulnerabilities.length > 0).length,
    critical: items.filter(item => item.vulnerabilities.some(vulnerability => vulnerability.severity === "critical")).length,
    items,
    attackPaths: simulatedAttackPaths,
    contextualRisk: topRisk.length
      ? Math.round(topRisk.reduce((sum, item) => sum + item.risk, 0) / topRisk.length)
      : 0,
    confidence: averageConfidence(items),
    reachableCritical: items.reduce((total, item) => total + (
      item.reachability?.status === "REACHABLE"
        ? item.vulnerabilities.filter(vulnerability => vulnerability.severity === "critical").length
        : 0
    ), 0),
    fixableRiskPercent: fixableRiskPercent(items),
    posture: calculatePosture(items, score),
    dependencyTree: scan.dependencyTree?.map(path => ({
      nodes: path.nodes.map(node => simulatedPath(node, dependency, request.targetVersion)),
      display: simulatedPath(path.display, dependency, request.targetVersion),
    })),
    simulated: true,
    sourceScanId: scan.id,
    simulation: {
      dependencyName: dependency.name,
      fromVersion: dependency.version,
      targetVersion: request.targetVersion,
      removedVulnerabilityIds,
      remainingVulnerabilityIds,
    },
  };
  simulatedScan.summary = deterministicSummary(simulatedScan);
  const before = snapshot(scan.items, dependency, scan.score, scan.attackPaths);
  const after = snapshot(items, updatedDependency, score, simulatedAttackPaths);
  return {
    simulated: true,
    sourceScanId: scan.id,
    dependencyName: dependency.name,
    fromVersion: dependency.version,
    targetVersion: request.targetVersion,
    removedVulnerabilityIds,
    remainingVulnerabilityIds,
    before,
    after,
    delta: {
      securityScoreChange: after.securityScore - before.securityScore,
      dependencyRiskReduction: before.dependencyRisk - after.dependencyRisk,
      criticalFindingsRemoved: before.criticalFindings - after.criticalFindings,
      criticalDependenciesReduced: before.criticalDependencies - after.criticalDependencies,
      vulnerablePathsRemoved: before.vulnerablePaths - after.vulnerablePaths,
    },
    confidence: "medium",
    assumptions: [
      "An advisory is estimated as removed only when its recorded exact fixed version is at or below the selected target.",
      "The dependency graph and application imports are held constant; no lockfile is resolved.",
      "No package is installed and no project file is modified.",
    ],
    uncertainty: "This is an advisory-based estimate, not a resolved npm install or target-version vulnerability scan. Transitive resolution, peer conflicts, release behavior, new advisories, and runtime compatibility require an actual upgrade and rescan.",
    scan: simulatedScan,
  };
}

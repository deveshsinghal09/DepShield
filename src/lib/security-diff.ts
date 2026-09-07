import type { AttackPath, AttackPathReachability, Dependency, Scan, Severity, Vulnerability } from "./types";

export const SECURITY_DIFF_VERSION = "depshield-diff-v1" as const;

export type FindingSnapshot = {
  key: string;
  dependencyKey: string;
  dependencyName: string;
  dependencyVersion: string;
  dependencyPath: string;
  vulnerabilityId: string;
  cveAlias: string | null;
  severity: Severity;
  cvss: number;
  cvssAvailable: boolean;
  vulnerableRange: string | null;
  fixedVersion: string | null;
  sources: string[];
  risk: number;
};

export type FindingFieldChange = {
  field: "dependencyVersion" | "severity" | "cvss" | "cvssAvailable" | "vulnerableRange" | "fixedVersion" | "sources" | "risk";
  before: string | number | boolean | null | string[];
  after: string | number | boolean | null | string[];
};

export type ChangedFinding = {
  key: string;
  before: FindingSnapshot;
  after: FindingSnapshot;
  changes: FindingFieldChange[];
};

export type DependencyVersionChange = {
  dependencyKey: string;
  name: string;
  path: string;
  beforeVersion: string;
  afterVersion: string;
  direction: "upgrade" | "downgrade" | "changed";
  beforeRisk: number;
  afterRisk: number;
};

export type AttackPathSnapshot = {
  key: string;
  id: string;
  nodes: string[];
  display: string;
  findingId: string;
  severity: Severity;
  reachability: AttackPathReachability;
  internetExposed: boolean;
};

export type SecurityDiffMetrics = {
  scoreBefore: number;
  scoreAfter: number;
  scoreChange: number;
  gradeBefore: string;
  gradeAfter: string;
  dependencyCountBefore: number;
  dependencyCountAfter: number;
  dependencyCountChange: number;
  findingCountBefore: number;
  findingCountAfter: number;
  criticalFindingsBefore: number;
  criticalFindingsAfter: number;
  reachableCriticalBefore: number;
  reachableCriticalAfter: number;
  reachableCriticalChange: number;
  attackPathCountBefore: number;
  attackPathCountAfter: number;
  attackPathChange: number;
};

export type SecurityDiff = {
  version: typeof SECURITY_DIFF_VERSION;
  beforeScanId: string;
  afterScanId: string;
  sameProject: boolean;
  findings: {
    removed: FindingSnapshot[];
    introduced: FindingSnapshot[];
    changed: ChangedFinding[];
    unchanged: number;
  };
  dependencies: {
    versionChanges: DependencyVersionChange[];
    upgraded: DependencyVersionChange[];
    downgraded: DependencyVersionChange[];
  };
  attackPaths: {
    removed: AttackPathSnapshot[];
    introduced: AttackPathSnapshot[];
    unchanged: number;
  };
  metrics: SecurityDiffMetrics;
};

export type SecurityAnomalyCode =
  | "DEPENDENCY_SURGE"
  | "CRITICAL_FINDING_INCREASE"
  | "SECURITY_SCORE_DROP"
  | "HIGH_RISK_DEPENDENCY_INTRODUCED"
  | "DEPENDENCY_GRAPH_EXPANSION"
  | "ATTACK_PATH_EXPANSION"
  | "RETURNED_FINDING";

export type SecurityAnomaly = {
  code: SecurityAnomalyCode;
  severity: "warning" | "critical";
  title: string;
  message: string;
  evidence: string[];
};

export type AnomalyThresholds = {
  dependencyIncreaseAbsolute: number;
  dependencyIncreaseRatio: number;
  criticalIncreaseAbsolute: number;
  securityScoreDrop: number;
  newDependencyRisk: number;
  graphIncreaseAbsolute: number;
  graphIncreaseRatio: number;
  attackPathIncreaseAbsolute: number;
};

export type AnomalyDetectionOptions = {
  history?: Scan[];
  thresholds?: Partial<AnomalyThresholds>;
};

const defaultThresholds: AnomalyThresholds = {
  dependencyIncreaseAbsolute: 5,
  dependencyIncreaseRatio: 0.25,
  criticalIncreaseAbsolute: 1,
  securityScoreDrop: 10,
  newDependencyRisk: 80,
  graphIncreaseAbsolute: 5,
  graphIncreaseRatio: 0.3,
  attackPathIncreaseAbsolute: 1,
};

function canonicalVulnerabilityId(vulnerability: Vulnerability) {
  return (vulnerability.cveAlias
    ?? vulnerability.aliases?.find(alias => alias.toUpperCase().startsWith("CVE-"))
    ?? vulnerability.aliases?.find(alias => alias.toUpperCase().startsWith("GHSA-"))
    ?? vulnerability.id).trim().toUpperCase();
}

function stripNodeVersion(node: string) {
  const value = node.trim();
  const separator = value.lastIndexOf("@");
  if (separator <= 0) return value.toLowerCase();
  const suffix = value.slice(separator + 1);
  return /^(?:v?\d|unknown$|[<>=~^*])/i.test(suffix) ? value.slice(0, separator).toLowerCase() : value.toLowerCase();
}

function representativePath(dependency: Dependency) {
  const paths = dependency.paths?.map(path => path.nodes.map(stripNodeVersion).join(" → ")).filter(Boolean).toSorted() ?? [];
  if (paths.length) return paths[0];
  return dependency.path.split("→").map(stripNodeVersion).join(" → ");
}

/** Stable across ordinary version upgrades because versions are removed from path nodes. */
export function dependencyDiffKey(dependency: Dependency) {
  return `${dependency.name.trim().toLowerCase()}|${representativePath(dependency)}`;
}

/** Finding identity includes the dependency instance path and canonical CVE/GHSA identifier. */
export function findingDiffKey(dependency: Dependency, vulnerability: Vulnerability) {
  return `${dependencyDiffKey(dependency)}|${canonicalVulnerabilityId(vulnerability)}`;
}

function coarseFindingKey(dependency: Dependency, vulnerability: Vulnerability) {
  return `${dependency.name.trim().toLowerCase()}|${canonicalVulnerabilityId(vulnerability)}`;
}

function sourceList(vulnerability: Vulnerability) {
  return [...new Set(vulnerability.sources ?? (vulnerability.source ? [vulnerability.source] : []))].toSorted();
}

function snapshot(dependency: Dependency, vulnerability: Vulnerability): FindingSnapshot {
  return {
    key: findingDiffKey(dependency, vulnerability),
    dependencyKey: dependencyDiffKey(dependency),
    dependencyName: dependency.name,
    dependencyVersion: dependency.version,
    dependencyPath: dependency.path,
    vulnerabilityId: canonicalVulnerabilityId(vulnerability),
    cveAlias: vulnerability.cveAlias ?? null,
    severity: vulnerability.severity,
    cvss: vulnerability.cvss,
    cvssAvailable: vulnerability.cvssAvailable !== false,
    vulnerableRange: vulnerability.vulnerableRange ?? null,
    fixedVersion: vulnerability.fixedVersion ?? null,
    sources: sourceList(vulnerability),
    risk: dependency.risk,
  };
}

function findingMap(scan: Scan) {
  const result = new Map<string, FindingSnapshot>();
  for (const dependency of scan.items) {
    for (const vulnerability of dependency.vulnerabilities) {
      const value = snapshot(dependency, vulnerability);
      if (!result.has(value.key)) result.set(value.key, value);
    }
  }
  return result;
}

function dependencyMap(scan: Scan) {
  return new Map(scan.items.map(dependency => [dependencyDiffKey(dependency), dependency]));
}

function sameArray(left: string[], right: string[]) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function findingChanges(before: FindingSnapshot, after: FindingSnapshot): FindingFieldChange[] {
  const changes: FindingFieldChange[] = [];
  const add = (field: FindingFieldChange["field"], previous: FindingFieldChange["before"], next: FindingFieldChange["after"]) => {
    if (Array.isArray(previous) && Array.isArray(next) ? !sameArray(previous, next) : previous !== next) {
      changes.push({ field, before: previous, after: next });
    }
  };
  add("dependencyVersion", before.dependencyVersion, after.dependencyVersion);
  add("severity", before.severity, after.severity);
  add("cvss", before.cvss, after.cvss);
  add("cvssAvailable", before.cvssAvailable, after.cvssAvailable);
  add("vulnerableRange", before.vulnerableRange, after.vulnerableRange);
  add("fixedVersion", before.fixedVersion, after.fixedVersion);
  add("sources", before.sources, after.sources);
  add("risk", before.risk, after.risk);
  return changes;
}

function parseVersion(value: string): number[] | null {
  const match = value.trim().replace(/^v/, "").match(/^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function versionDirection(before: string, after: string): DependencyVersionChange["direction"] {
  const left = parseVersion(before);
  const right = parseVersion(after);
  if (!left || !right) return "changed";
  for (let index = 0; index < 3; index++) {
    if (right[index] > left[index]) return "upgrade";
    if (right[index] < left[index]) return "downgrade";
  }
  return "changed";
}

function attackPathSnapshot(path: AttackPath): AttackPathSnapshot {
  const nodes = path.nodes.map(node => node.trim());
  return {
    key: path.id.trim(),
    id: path.id.trim(),
    nodes,
    display: path.display,
    findingId: path.findingId.trim().toUpperCase(),
    severity: path.severity,
    reachability: path.reachability,
    internetExposed: path.internetExposed,
  };
}

function attackPathMap(scan: Scan) {
  const result = new Map<string, AttackPathSnapshot>();
  for (const path of scan.attackPaths ?? []) {
    const value = attackPathSnapshot(path);
    if (!result.has(value.key)) result.set(value.key, value);
  }
  return result;
}

function securityScore(scan: Scan) {
  return scan.score;
}

function reachableCriticalCount(scan: Scan, attackPaths: Map<string, AttackPathSnapshot>) {
  const explicit = scan.reachableCritical;
  if (typeof explicit === "number" && Number.isFinite(explicit)) return Math.max(0, Math.floor(explicit));

  const findingIds = new Set<string>();
  for (const dependency of scan.items) {
    if (dependency.reachability?.status !== "REACHABLE") continue;
    for (const vulnerability of dependency.vulnerabilities) {
      if (vulnerability.severity === "critical") findingIds.add(coarseFindingKey(dependency, vulnerability));
    }
  }
  for (const path of attackPaths.values()) {
    if (path.reachability === "reachable" && path.severity === "critical") findingIds.add(path.findingId ?? path.key);
  }
  return findingIds.size;
}

/** Produces a structured, deterministic security diff without mutating either scan. */
export function createSecurityDiff(before: Scan, after: Scan): SecurityDiff {
  const beforeFindings = findingMap(before);
  const afterFindings = findingMap(after);
  const removed = [...beforeFindings.values()].filter(item => !afterFindings.has(item.key)).toSorted((a, b) => a.key.localeCompare(b.key));
  const introduced = [...afterFindings.values()].filter(item => !beforeFindings.has(item.key)).toSorted((a, b) => a.key.localeCompare(b.key));
  const changed: ChangedFinding[] = [];
  let unchanged = 0;
  for (const [key, previous] of beforeFindings) {
    const next = afterFindings.get(key);
    if (!next) continue;
    const changes = findingChanges(previous, next);
    if (changes.length) changed.push({ key, before: previous, after: next, changes });
    else unchanged++;
  }
  changed.sort((a, b) => a.key.localeCompare(b.key));

  const beforeDependencies = dependencyMap(before);
  const afterDependencies = dependencyMap(after);
  const versionChanges: DependencyVersionChange[] = [];
  for (const [key, previous] of beforeDependencies) {
    const next = afterDependencies.get(key);
    if (!next || previous.version === next.version) continue;
    versionChanges.push({
      dependencyKey: key,
      name: next.name,
      path: next.path,
      beforeVersion: previous.version,
      afterVersion: next.version,
      direction: versionDirection(previous.version, next.version),
      beforeRisk: previous.risk,
      afterRisk: next.risk,
    });
  }
  versionChanges.sort((a, b) => a.dependencyKey.localeCompare(b.dependencyKey));

  const beforePaths = attackPathMap(before);
  const afterPaths = attackPathMap(after);
  const removedPaths = [...beforePaths.values()].filter(item => !afterPaths.has(item.key)).toSorted((a, b) => a.key.localeCompare(b.key));
  const introducedPaths = [...afterPaths.values()].filter(item => !beforePaths.has(item.key)).toSorted((a, b) => a.key.localeCompare(b.key));
  const scoreBefore = securityScore(before);
  const scoreAfter = securityScore(after);
  const criticalBefore = [...beforeFindings.values()].filter(item => item.severity === "critical").length;
  const criticalAfter = [...afterFindings.values()].filter(item => item.severity === "critical").length;
  const reachableBefore = reachableCriticalCount(before, beforePaths);
  const reachableAfter = reachableCriticalCount(after, afterPaths);

  return {
    version: SECURITY_DIFF_VERSION,
    beforeScanId: before.id,
    afterScanId: after.id,
    sameProject: before.project === after.project,
    findings: { removed, introduced, changed, unchanged },
    dependencies: {
      versionChanges,
      upgraded: versionChanges.filter(item => item.direction === "upgrade"),
      downgraded: versionChanges.filter(item => item.direction === "downgrade"),
    },
    attackPaths: {
      removed: removedPaths,
      introduced: introducedPaths,
      unchanged: [...beforePaths.keys()].filter(key => afterPaths.has(key)).length,
    },
    metrics: {
      scoreBefore,
      scoreAfter,
      scoreChange: scoreAfter - scoreBefore,
      gradeBefore: before.grade,
      gradeAfter: after.grade,
      dependencyCountBefore: before.dependencies,
      dependencyCountAfter: after.dependencies,
      dependencyCountChange: after.dependencies - before.dependencies,
      findingCountBefore: beforeFindings.size,
      findingCountAfter: afterFindings.size,
      criticalFindingsBefore: criticalBefore,
      criticalFindingsAfter: criticalAfter,
      reachableCriticalBefore: reachableBefore,
      reachableCriticalAfter: reachableAfter,
      reachableCriticalChange: reachableAfter - reachableBefore,
      attackPathCountBefore: beforePaths.size,
      attackPathCountAfter: afterPaths.size,
      attackPathChange: afterPaths.size - beforePaths.size,
    },
  };
}

export const diffSecurityScans = createSecurityDiff;

function dependencyGraphSize(scan: Scan) {
  return scan.dependencyTree?.length ?? scan.items.reduce((total, item) => total + (item.paths?.length ?? (item.path ? 1 : 0)), 0);
}

function ratioThreshold(previous: number, ratio: number) {
  return Math.ceil(Math.max(0, previous) * Math.max(0, ratio));
}

/** Flags deterministic scan regressions. Thresholds are configurable and included in evidence text. */
export function detectSecurityAnomalies(before: Scan, after: Scan, options: AnomalyDetectionOptions = {}): SecurityAnomaly[] {
  const thresholds = { ...defaultThresholds, ...options.thresholds };
  const diff = createSecurityDiff(before, after);
  const anomalies: SecurityAnomaly[] = [];
  const dependencyIncrease = diff.metrics.dependencyCountChange;
  const dependencyThreshold = Math.max(thresholds.dependencyIncreaseAbsolute, ratioThreshold(diff.metrics.dependencyCountBefore, thresholds.dependencyIncreaseRatio));
  if (dependencyIncrease >= dependencyThreshold) {
    anomalies.push({
      code: "DEPENDENCY_SURGE",
      severity: "warning",
      title: "Sudden dependency increase",
      message: `Dependency inventory increased by ${dependencyIncrease}.`,
      evidence: [`${diff.metrics.dependencyCountBefore} → ${diff.metrics.dependencyCountAfter}`, `Alert threshold: +${dependencyThreshold}`],
    });
  }

  const criticalIncrease = diff.metrics.criticalFindingsAfter - diff.metrics.criticalFindingsBefore;
  if (criticalIncrease >= thresholds.criticalIncreaseAbsolute) {
    anomalies.push({
      code: "CRITICAL_FINDING_INCREASE",
      severity: "critical",
      title: "Critical findings increased",
      message: `${criticalIncrease} critical finding(s) were added on balance.`,
      evidence: [`${diff.metrics.criticalFindingsBefore} → ${diff.metrics.criticalFindingsAfter}`],
    });
  }

  if (diff.metrics.scoreChange <= -thresholds.securityScoreDrop) {
    anomalies.push({
      code: "SECURITY_SCORE_DROP",
      severity: "critical",
      title: "Security score regression",
      message: `Security score dropped by ${Math.abs(diff.metrics.scoreChange)} points.`,
      evidence: [`${diff.metrics.scoreBefore} → ${diff.metrics.scoreAfter}`, `Alert threshold: -${thresholds.securityScoreDrop}`],
    });
  }

  const beforeDependencyKeys = new Set(before.items.map(dependencyDiffKey));
  const highRiskIntroduced = after.items
    .filter(item => !beforeDependencyKeys.has(dependencyDiffKey(item)) && item.risk >= thresholds.newDependencyRisk)
    .toSorted((a, b) => b.risk - a.risk || a.name.localeCompare(b.name));
  if (highRiskIntroduced.length) {
    anomalies.push({
      code: "HIGH_RISK_DEPENDENCY_INTRODUCED",
      severity: "critical",
      title: "High-risk dependency introduced",
      message: `${highRiskIntroduced.length} newly observed dependency instance(s) meet the risk threshold.`,
      evidence: highRiskIntroduced.map(item => `${item.name}@${item.version}: risk ${item.risk}`),
    });
  }

  const graphBefore = dependencyGraphSize(before);
  const graphAfter = dependencyGraphSize(after);
  const graphIncrease = graphAfter - graphBefore;
  const graphThreshold = Math.max(thresholds.graphIncreaseAbsolute, ratioThreshold(graphBefore, thresholds.graphIncreaseRatio));
  if (graphIncrease >= graphThreshold) {
    anomalies.push({
      code: "DEPENDENCY_GRAPH_EXPANSION",
      severity: "warning",
      title: "Dependency graph expanded",
      message: `Observed dependency paths increased by ${graphIncrease}.`,
      evidence: [`${graphBefore} → ${graphAfter}`, `Alert threshold: +${graphThreshold}`],
    });
  }

  if (diff.metrics.attackPathChange >= thresholds.attackPathIncreaseAbsolute) {
    anomalies.push({
      code: "ATTACK_PATH_EXPANSION",
      severity: diff.attackPaths.introduced.some(path => path.severity === "critical" && path.reachability === "reachable") ? "critical" : "warning",
      title: "Attack paths increased",
      message: `${diff.attackPaths.introduced.length} new attack path(s) were observed.`,
      evidence: diff.attackPaths.introduced.map(path => path.display || path.key),
    });
  }

  if (options.history?.length && diff.findings.introduced.length) {
    const historical = new Set<string>();
    for (const scan of options.history) {
      if (scan.id === before.id || scan.id === after.id || scan.project !== after.project) continue;
      for (const dependency of scan.items) {
        for (const vulnerability of dependency.vulnerabilities) historical.add(coarseFindingKey(dependency, vulnerability));
      }
    }
    const returned = diff.findings.introduced.filter(item => historical.has(`${item.dependencyName.trim().toLowerCase()}|${item.vulnerabilityId}`));
    if (returned.length) {
      anomalies.push({
        code: "RETURNED_FINDING",
        severity: returned.some(item => item.severity === "critical") ? "critical" : "warning",
        title: "Previously observed finding returned",
        message: `${returned.length} finding(s) absent from the baseline appeared in earlier project history.`,
        evidence: returned.map(item => `${item.dependencyName}@${item.dependencyVersion}: ${item.vulnerabilityId}`),
      });
    }
  }

  return anomalies;
}

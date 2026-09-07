import type { AttackPath, Dependency, Vulnerability } from "./types";

export type AttackPathOrder = "highest" | "shortest";

export type AttackPathCandidate = {
  path: AttackPath;
  dependency: Dependency;
  finding: Vulnerability | null;
  /** Derived graph-aware priority. The scanner's base dependency risk remains dependency.risk. */
  propagatedRisk: number;
  pathLength: number;
};

/**
 * Resolves persisted, CVE-specific attack paths to the dependency instance and
 * advisory captured in the same scan. It intentionally does not reconstruct
 * paths from live dependency metadata.
 */
export function resolveAttackPathCandidates(
  attackPaths: ReadonlyArray<AttackPath>,
  dependencies: ReadonlyArray<Dependency>,
): AttackPathCandidate[] {
  return attackPaths.flatMap((path) => {
    const dependency =
      dependencies.find((item) =>
        item.name === path.dependencyName &&
        item.version === path.dependencyVersion &&
        item.path === path.dependencyPath,
      ) ??
      dependencies.find((item) =>
        item.name === path.dependencyName && item.version === path.dependencyVersion,
      );

    if (!dependency) return [];

    return [{
      path,
      dependency,
      finding: dependency.vulnerabilities.find((finding) => findingMatchesPath(finding, path)) ?? null,
      propagatedRisk:
        dependency.propagation?.contextualRisk ??
        dependency.contextual?.finalPriority ??
        dependency.risk,
      pathLength: path.nodes.length,
    }];
  });
}

export function orderAttackPathCandidates(
  candidates: ReadonlyArray<AttackPathCandidate>,
  order: AttackPathOrder,
): AttackPathCandidate[] {
  return [...candidates].sort((left, right) => {
    if (order === "shortest") {
      return (
        left.pathLength - right.pathLength ||
        right.propagatedRisk - left.propagatedRisk ||
        left.path.id.localeCompare(right.path.id)
      );
    }

    return (
      right.propagatedRisk - left.propagatedRisk ||
      severityWeight(right.path.severity) - severityWeight(left.path.severity) ||
      left.pathLength - right.pathLength ||
      left.path.id.localeCompare(right.path.id)
    );
  });
}

function findingMatchesPath(finding: Vulnerability, path: AttackPath) {
  const identifiers = [finding.id, finding.cveAlias, ...(finding.aliases ?? [])]
    .filter((value): value is string => Boolean(value))
    .map((value) => value.trim().toUpperCase());
  return identifiers.includes(path.findingId.trim().toUpperCase());
}

function severityWeight(severity: AttackPath["severity"]) {
  return ({ critical: 5, high: 4, medium: 3, low: 2, unknown: 1 } as const)[severity];
}

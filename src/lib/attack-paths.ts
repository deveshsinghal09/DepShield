import type {
  AttackPath,
  AttackPathReachability,
  Dependency,
  DependencyPath,
  ReachabilityStatus,
  Vulnerability,
} from "./types";

function canonicalFindingId(vulnerability: Vulnerability) {
  return (
    vulnerability.cveAlias ??
    vulnerability.aliases?.find((alias) => alias.toUpperCase().startsWith("CVE-")) ??
    vulnerability.aliases?.find((alias) => alias.toUpperCase().startsWith("GHSA-")) ??
    vulnerability.id
  ).trim().toUpperCase();
}

function stripNodeVersion(node: string) {
  const value = node.trim();
  const separator = value.lastIndexOf("@");
  if (separator <= 0) return value.toLowerCase();
  const suffix = value.slice(separator + 1);
  return /^(?:v?\d|unknown$|[<>=~^*])/i.test(suffix)
    ? value.slice(0, separator).toLowerCase()
    : value.toLowerCase();
}

function reachabilityStatus(status: ReachabilityStatus | undefined): AttackPathReachability {
  if (status === "REACHABLE") return "reachable";
  if (status === "POSSIBLY_REACHABLE") return "possibly-reachable";
  if (status === "NOT_OBSERVED") return "not-observed";
  return "unknown";
}

function dependencyPaths(dependency: Dependency): DependencyPath[] {
  if (dependency.paths?.length) return dependency.paths;
  const nodes = dependency.path.split(/\s*→\s*/).filter(Boolean);
  return [{ nodes, display: dependency.path || nodes.join(" → ") }];
}

function stableAttackPathId(dependency: Dependency, findingId: string, nodes: string[]) {
  const normalized = nodes.map(stripNodeVersion).join("→");
  return `attack-path|${findingId}|${dependency.name.trim().toLowerCase()}|${normalized}`;
}

/**
 * Joins persisted advisory, source-reachability, and dependency-path evidence.
 * Candidate dependency paths remain explicitly `unknown` or `not-observed`;
 * their existence is never presented as proof that vulnerable code executes.
 */
export function deriveAttackPaths(items: ReadonlyArray<Dependency>): AttackPath[] {
  const result = new Map<string, AttackPath>();

  for (const dependency of items) {
    if (!dependency.vulnerabilities.length) continue;
    const sourcePaths = dependency.reachability?.paths ?? [];
    const pathEvidence = sourcePaths.length
      ? sourcePaths.map((path) => ({
          nodes: path.nodes,
          display: path.display,
          internetExposed: path.internetExposed,
          evidenceKind: path.internetExposed ? "source-route" as const : "source-import" as const,
          explanation: dependency.reachability?.explanation ?? "A supported static source path was observed.",
        }))
      : dependencyPaths(dependency).map((path) => ({
          nodes: path.nodes,
          display: path.display,
          internetExposed: false,
          evidenceKind: "dependency-path" as const,
          explanation:
            dependency.reachability?.explanation ??
            "Only a dependency-resolution path is available; runtime reachability is unknown.",
        }));
    const reachability = reachabilityStatus(dependency.reachability?.status);
    const confidence = Math.max(0, Math.min(100, Math.round(dependency.reachability?.confidence ?? 15)));

    for (const vulnerability of dependency.vulnerabilities) {
      const findingId = canonicalFindingId(vulnerability);
      for (const evidence of pathEvidence) {
        const id = stableAttackPathId(dependency, findingId, evidence.nodes);
        if (result.has(id)) continue;
        result.set(id, {
          id,
          dependencyName: dependency.name,
          dependencyVersion: dependency.version,
          dependencyPath: dependency.path,
          findingId,
          cveAlias: vulnerability.cveAlias ?? null,
          severity: vulnerability.severity,
          reachability,
          internetExposed: evidence.internetExposed,
          nodes: [...evidence.nodes],
          display: evidence.display,
          evidenceKind: evidence.evidenceKind,
          confidence,
          explanation: evidence.explanation,
          estimated: true,
        });
      }
    }
  }

  return [...result.values()].toSorted((left, right) => left.id.localeCompare(right.id));
}

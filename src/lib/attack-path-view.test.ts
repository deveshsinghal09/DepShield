import { describe, expect, it } from "vitest";
import { orderAttackPathCandidates, resolveAttackPathCandidates } from "./attack-path-view";
import type { AttackPath, Dependency } from "./types";

function dependency(values: Partial<Dependency> = {}): Dependency {
  return {
    name: "child",
    version: "1.0.0",
    direct: false,
    path: "app → parent@1.0.0 → child@1.0.0",
    license: "MIT",
    vulnerabilities: [{
      id: "OSV-1",
      aliases: ["CVE-2026-1"],
      cveAlias: "CVE-2026-1",
      cvss: 9.8,
      severity: "critical",
      summary: "test finding",
    }],
    risk: 70,
    latest: "1.1.0",
    propagation: {
      ownRisk: 74,
      inheritedRisk: 12,
      contextualRisk: 82,
      contributors: [],
      formula: "bounded union",
    },
    ...values,
  };
}

function attackPath(values: Partial<AttackPath> = {}): AttackPath {
  return {
    id: "path-1",
    dependencyName: "child",
    dependencyVersion: "1.0.0",
    dependencyPath: "app → parent@1.0.0 → child@1.0.0",
    findingId: "CVE-2026-1",
    cveAlias: "CVE-2026-1",
    severity: "critical",
    reachability: "reachable",
    internetExposed: true,
    nodes: ["POST /api/test", "src/app/api/test/route.ts", "child@1.0.0"],
    display: "POST /api/test → src/app/api/test/route.ts → child@1.0.0",
    evidenceKind: "source-route",
    confidence: 85,
    explanation: "A static source path was observed.",
    estimated: true,
    ...values,
  };
}

describe("attack-path UI evidence", () => {
  it("joins a persisted path to its exact dependency instance and CVE alias", () => {
    const wrongInstance = dependency({ path: "app → other@1.0.0 → child@1.0.0", risk: 99 });
    const exactInstance = dependency();
    const [candidate] = resolveAttackPathCandidates([attackPath()], [wrongInstance, exactInstance]);

    expect(candidate.dependency).toBe(exactInstance);
    expect(candidate.finding?.id).toBe("OSV-1");
    expect(candidate.propagatedRisk).toBe(82);
    expect(candidate.pathLength).toBe(3);
  });

  it("orders persisted paths by propagated risk or their actual node count", () => {
    const high = resolveAttackPathCandidates(
      [attackPath({ id: "high", nodes: ["app", "module", "parent", "child"] })],
      [dependency()],
    )[0];
    const short = resolveAttackPathCandidates(
      [attackPath({ id: "short", dependencyName: "short", dependencyPath: "app → short@1.0.0", nodes: ["app", "short@1.0.0"] })],
      [dependency({ name: "short", path: "app → short@1.0.0", propagation: undefined, contextual: undefined, risk: 40 })],
    )[0];

    expect(orderAttackPathCandidates([short, high], "highest").map((item) => item.path.id)).toEqual(["high", "short"]);
    expect(orderAttackPathCandidates([high, short], "shortest").map((item) => item.path.id)).toEqual(["short", "high"]);
  });

  it("omits orphaned path records instead of presenting guessed dependency evidence", () => {
    expect(resolveAttackPathCandidates([attackPath()], [])).toEqual([]);
  });
});

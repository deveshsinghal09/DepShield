import { describe, expect, it } from "vitest";
import { deriveAttackPaths } from "./attack-paths";
import type { Dependency, Vulnerability } from "./types";

const finding = (id: string, severity: Vulnerability["severity"] = "critical"): Vulnerability => ({
  id,
  aliases: [id],
  cveAlias: id.startsWith("CVE-") ? id : null,
  cvss: severity === "critical" ? 9.8 : 7.5,
  cvssAvailable: true,
  severity,
  summary: `${id} test advisory`,
});

function dependency(values: Partial<Dependency> = {}): Dependency {
  return {
    name: "lodash",
    version: "4.17.11",
    direct: true,
    path: "app → lodash@4.17.11",
    paths: [{ nodes: ["app", "lodash@4.17.11"], display: "app → lodash@4.17.11" }],
    license: "MIT",
    vulnerabilities: [finding("CVE-2019-10744")],
    risk: 90,
    latest: "4.17.21",
    recommendation: "upgrade",
    ...values,
  };
}

describe("persisted attack-path derivation", () => {
  it("joins each finding to observed source paths with conservative evidence labels", () => {
    const item = dependency({
      vulnerabilities: [finding("CVE-2019-10744"), finding("GHSA-TEST", "high")],
      reachability: {
        status: "REACHABLE",
        confidence: 86,
        sourceFilesAnalyzed: 2,
        entryFiles: ["src/app/api/search/route.ts"],
        importedBy: ["src/lib/search.ts"],
        observedFunctions: ["defaultsDeep"],
        paths: [{
          nodes: ["POST /api/search", "src/app/api/search/route.ts", "src/lib/search.ts", "lodash@4.17.11"],
          display: "POST /api/search → src/app/api/search/route.ts → src/lib/search.ts → lodash@4.17.11",
          entryFile: "src/app/api/search/route.ts",
          importedPackage: "lodash",
          internetExposed: true,
        }],
        internetExposed: true,
        explanation: "A supported static import was observed; execution of a vulnerable function is not proven.",
        limitations: [],
      },
    });

    const paths = deriveAttackPaths([item]);
    expect(paths).toHaveLength(2);
    expect(paths[0]).toMatchObject({
      dependencyName: "lodash",
      dependencyVersion: "4.17.11",
      reachability: "reachable",
      internetExposed: true,
      evidenceKind: "source-route",
      confidence: 86,
      estimated: true,
    });
    expect(paths.map((path) => path.findingId)).toEqual(["CVE-2019-10744", "GHSA-TEST"]);
  });

  it("persists dependency-only candidates without claiming reachability and keeps IDs stable across upgrades", () => {
    const before = deriveAttackPaths([dependency()]);
    const after = deriveAttackPaths([dependency({
      version: "4.17.12",
      path: "app → lodash@4.17.12",
      paths: [{ nodes: ["app", "lodash@4.17.12"], display: "app → lodash@4.17.12" }],
    })]);

    expect(before[0]).toMatchObject({
      reachability: "unknown",
      internetExposed: false,
      evidenceKind: "dependency-path",
      estimated: true,
    });
    expect(after[0].id).toBe(before[0].id);
    expect(after[0].dependencyVersion).toBe("4.17.12");
  });

  it("does not create paths for dependencies without findings", () => {
    expect(deriveAttackPaths([dependency({ vulnerabilities: [] })])).toEqual([]);
  });
});

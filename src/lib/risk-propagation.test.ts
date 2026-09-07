import { describe, expect, it } from "vitest";
import type { Dependency } from "./types";
import { propagationFor } from "./risk-propagation";

function dependency(values: Partial<Dependency>): Dependency {
  return {
    name: "parent",
    version: "1.0.0",
    direct: true,
    runtime: true,
    path: "app → parent@1.0.0",
    paths: [{ nodes: ["app", "parent@1.0.0"], display: "app → parent@1.0.0" }],
    license: "MIT",
    vulnerabilities: [],
    risk: 10,
    latest: "1.0.0",
    ...values,
  };
}

describe("dependency risk propagation", () => {
  it("dampens inherited risk by graph distance", () => {
    const parent = dependency({});
    const child = dependency({
      name: "child",
      version: "2.0.0",
      direct: false,
      risk: 90,
      path: "app → parent@1.0.0 → child@2.0.0",
      paths: [{
        nodes: ["app", "parent@1.0.0", "child@2.0.0"],
        display: "app → parent@1.0.0 → child@2.0.0",
      }],
      vulnerabilities: [{ id: "CVE-1", cvss: 9, severity: "critical", summary: "test" }],
      reachability: {
        status: "REACHABLE",
        confidence: 90,
        sourceFilesAnalyzed: 1,
        entryFiles: ["route.ts"],
        importedBy: ["route.ts"],
        observedFunctions: [],
        paths: [],
        internetExposed: true,
        explanation: "Observed.",
        limitations: [],
      },
    });
    const result = propagationFor(parent, [parent, child]);
    expect(result.inheritedRisk).toBeGreaterThan(20);
    expect(result.inheritedRisk).toBeLessThan(90);
    expect(result.contextualRisk).toBeGreaterThan(result.ownRisk);
    expect(result.contributors[0].distance).toBe(1);
  });

  it("does not propagate unrelated risk", () => {
    const parent = dependency({});
    const unrelated = dependency({ name: "other", version: "1.0.0", risk: 100 });
    expect(propagationFor(parent, [parent, unrelated]).inheritedRisk).toBe(0);
  });

  it("does not mix duplicate name/version instances from different paths", () => {
    const parent = dependency({
      path: "app → branch-a@1.0.0 → parent@1.0.0",
      paths: [{
        nodes: ["app", "branch-a@1.0.0", "parent@1.0.0"],
        display: "app → branch-a@1.0.0 → parent@1.0.0",
      }],
    });
    const childOnOtherInstance = dependency({
      name: "child",
      direct: false,
      risk: 100,
      path: "app → branch-b@1.0.0 → parent@1.0.0 → child@2.0.0",
      paths: [{
        nodes: ["app", "branch-b@1.0.0", "parent@1.0.0", "child@2.0.0"],
        display: "app → branch-b@1.0.0 → parent@1.0.0 → child@2.0.0",
      }],
      vulnerabilities: [{ id: "CVE-duplicate", cvss: 9, severity: "critical", summary: "test" }],
    });

    expect(propagationFor(parent, [parent, childOnOtherInstance]).inheritedRisk).toBe(0);
  });
});

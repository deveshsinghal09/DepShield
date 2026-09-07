import { describe, expect, it } from "vitest";
import { dependencyRisk, grade, projectScore } from "./risk";
import { simulateDependencyUpgrade } from "./remediation-sandbox";
import type { Dependency, Scan, Vulnerability } from "./types";

const vulnerability = (values: Partial<Vulnerability>): Vulnerability => ({
  id: "CVE-default",
  cvss: 9.1,
  severity: "critical",
  summary: "Test advisory",
  ...values,
});

function makeScan(vulnerabilities: Vulnerability[]): Scan {
  const item: Dependency = {
    name: "lodash",
    version: "4.17.11",
    direct: true,
    path: "app → lodash@4.17.11",
    paths: [{ nodes: ["app", "lodash@4.17.11"], display: "app → lodash@4.17.11" }],
    license: "MIT",
    vulnerabilities,
    risk: dependencyRisk(Math.max(0, ...vulnerabilities.map(value => value.cvss)), true, vulnerabilities.every(value => Boolean(value.fixedVersion)), vulnerabilities.length),
    latest: "5.0.0",
    recommendation: "upgrade",
  };
  const items = [item], score = projectScore(items);
  return {
    id: "scan-1",
    createdAt: "2026-08-24T00:00:00.000Z",
    project: "demo",
    branch: "uploaded",
    score,
    grade: grade(score),
    dependencies: 1,
    vulnerable: 1,
    critical: 1,
    duration: 1,
    items,
    contextualRisk: 100,
    reachableCritical: 1,
    fixableRiskPercent: 0,
    summary: { executive: "stale", developer: "stale", evidence: [], generatedBy: "deterministic" },
  };
}

describe("remediation sandbox", () => {
  it("removes only advisories whose exact reported fixed version is reached", () => {
    const scan = makeScan([
      vulnerability({ id: "CVE-fixed", fixedVersion: "4.17.21" }),
      vulnerability({ id: "CVE-later", fixedVersion: "5.0.0", cvss: 7.5, severity: "high" }),
      vulnerability({ id: "CVE-no-fix", fixedVersion: null, cvss: 6.5, severity: "medium" }),
    ]);
    const result = simulateDependencyUpgrade(scan, { dependencyName: "lodash", targetVersion: "4.17.21" });
    expect(result.removedVulnerabilityIds).toEqual(["CVE-fixed"]);
    expect(result.remainingVulnerabilityIds).toEqual(["CVE-later", "CVE-no-fix"]);
    expect(result.scan.simulated).toBe(true);
    expect(result.scan.items[0].path).toContain("lodash@4.17.21");
    expect(scan.items[0].version).toBe("4.17.11");
  });

  it("recalculates posture, critical findings, and vulnerable path delta", () => {
    const scan = makeScan([vulnerability({ id: "CVE-fixed", fixedVersion: "4.17.21" })]);
    scan.attackPaths = [{
      id: "attack-path|CVE-FIXED|lodash|app→lodash",
      dependencyName: "lodash",
      dependencyVersion: "4.17.11",
      dependencyPath: "app → lodash@4.17.11",
      findingId: "CVE-FIXED",
      cveAlias: null,
      severity: "critical",
      reachability: "unknown",
      internetExposed: false,
      nodes: ["app", "lodash@4.17.11"],
      display: "app → lodash@4.17.11",
      evidenceKind: "dependency-path",
      confidence: 15,
      explanation: "Dependency path only.",
      estimated: true,
    }];
    const result = simulateDependencyUpgrade(scan, { dependencyName: "lodash", targetVersion: "4.17.21" });
    expect(result.after).toMatchObject({ securityScore: 100, dependencyRisk: 0, criticalFindings: 0, vulnerablePaths: 0 });
    expect(result.delta.criticalFindingsRemoved).toBe(1);
    expect(result.delta.vulnerablePathsRemoved).toBe(1);
    expect(result.delta.securityScoreChange).toBeGreaterThan(0);
    expect(result.scan).toMatchObject({
      contextualRisk: 0,
      reachableCritical: 0,
      fixableRiskPercent: 100,
      posture: { knownVulnerabilityRisk: 100 },
    });
    expect(result.scan.summary?.executive).not.toBe("stale");
    expect(result.scan.attackPaths).toEqual([]);
    expect(result.uncertainty).toContain("not a resolved npm install");
  });

  it("rejects a downgrade, equal version, or non-semver target", () => {
    const scan = makeScan([vulnerability({ fixedVersion: "4.17.21" })]);
    expect(() => simulateDependencyUpgrade(scan, { dependencyName: "lodash", targetVersion: "4.17.10" })).toThrow("must be newer");
    expect(() => simulateDependencyUpgrade(scan, { dependencyName: "lodash", targetVersion: "4.17.11" })).toThrow("must be newer");
    expect(() => simulateDependencyUpgrade(scan, { dependencyName: "lodash", targetVersion: "latest" })).toThrow("not an exact semantic version");
  });
});

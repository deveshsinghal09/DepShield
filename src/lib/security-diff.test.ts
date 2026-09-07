import { describe, expect, it } from "vitest";
import type { AttackPath, Dependency, Scan, Severity } from "./types";
import { deriveAttackPaths } from "./attack-paths";
import { createSecurityDiff, detectSecurityAnomalies } from "./security-diff";

function vulnerableDependency(name: string, version: string, id: string, values: { severity?: Severity; cvss?: number; risk?: number; fixed?: string | null } = {}): Dependency {
  const severity = values.severity ?? "high";
  return {
    name,
    version,
    direct: true,
    path: `app → ${name}@${version}`,
    paths: [{ nodes: ["app", `${name}@${version}`], display: `app → ${name}@${version}` }],
    license: "MIT",
    vulnerabilities: [{
      id,
      aliases: [id],
      cveAlias: id.startsWith("CVE-") ? id : null,
      cvss: values.cvss ?? (severity === "critical" ? 9.5 : 7.5),
      cvssAvailable: true,
      severity,
      summary: `${id} summary`,
      fixedVersion: values.fixed === undefined ? "9.9.9" : values.fixed,
      sources: ["OSV"],
    }],
    risk: values.risk ?? 80,
    latest: "9.9.9",
    recommendation: "upgrade",
  };
}

function cleanDependency(name: string, version = "1.0.0", risk = 0): Dependency {
  return {
    name,
    version,
    direct: true,
    path: `app → ${name}@${version}`,
    paths: [{ nodes: ["app", `${name}@${version}`], display: `app → ${name}@${version}` }],
    license: "MIT",
    vulnerabilities: [],
    risk,
    latest: version,
    recommendation: "none",
  };
}

function attackPath(id: string, name: string, version: string, findingId: string, severity: Severity): AttackPath {
  const nodes = ["User", `${name}@${version}`];
  return {
    id,
    dependencyName: name,
    dependencyVersion: version,
    dependencyPath: `app → ${name}@${version}`,
    findingId,
    cveAlias: findingId.startsWith("CVE-") ? findingId : null,
    severity,
    reachability: "reachable",
    internetExposed: true,
    nodes,
    display: nodes.join(" → "),
    evidenceKind: "source-route",
    confidence: 85,
    explanation: "A supported static route-to-package path was observed; runtime execution remains unproven.",
    estimated: true,
  };
}

function scan(id: string, score: number, items: Dependency[], extra: Partial<Scan> = {}): Scan {
  return {
    id,
    createdAt: new Date(`2026-01-${id.padStart(2, "0")}T00:00:00.000Z`).toISOString(),
    project: "app",
    branch: "main",
    score,
    grade: score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F",
    dependencies: items.length,
    vulnerable: items.filter(item => item.vulnerabilities.length > 0).length,
    critical: items.filter(item => item.vulnerabilities.some(vulnerability => vulnerability.severity === "critical")).length,
    duration: 1,
    items,
    dependencyTree: items.flatMap(item => item.paths ?? []),
    ...extra,
  };
}

describe("structured security diff", () => {
  it("reports removed, introduced and changed findings plus version and path movement", () => {
    const beforeLodash = vulnerableDependency("lodash", "4.17.11", "CVE-2019-10744", { severity: "high", cvss: 7.5, risk: 85 });
    const afterLodash = vulnerableDependency("lodash", "4.17.21", "CVE-2019-10744", { severity: "critical", cvss: 9.1, risk: 92, fixed: "4.17.22" });
    const before = scan("1", 61, [beforeLodash, vulnerableDependency("axios", "0.20.0", "CVE-OLD")], {
      attackPaths: [attackPath("old-path", "lodash", "4.17.11", "CVE-2019-10744", "high")],
    });
    const after = scan("2", 81, [afterLodash, vulnerableDependency("qs", "6.1.0", "CVE-NEW", { severity: "critical" })], {
      attackPaths: [attackPath("new-path", "qs", "6.1.0", "CVE-NEW", "critical")],
    });

    const result = createSecurityDiff(before, after);
    expect(result.findings.removed.map(item => item.vulnerabilityId)).toEqual(["CVE-OLD"]);
    expect(result.findings.introduced.map(item => item.vulnerabilityId)).toEqual(["CVE-NEW"]);
    expect(result.findings.changed).toHaveLength(1);
    expect(result.findings.changed[0].changes.map(change => change.field)).toEqual(expect.arrayContaining(["dependencyVersion", "severity", "cvss", "fixedVersion", "risk"]));
    expect(result.dependencies.upgraded).toMatchObject([{ name: "lodash", beforeVersion: "4.17.11", afterVersion: "4.17.21", direction: "upgrade" }]);
    expect(result.attackPaths.removed.map(path => path.id)).toEqual(["old-path"]);
    expect(result.attackPaths.introduced.map(path => path.id)).toEqual(["new-path"]);
    expect(result.metrics).toMatchObject({ scoreChange: 20, reachableCriticalBefore: 0, reachableCriticalAfter: 1, reachableCriticalChange: 1 });
  });

  it("is deterministic and does not mutate source scans", () => {
    const before = scan("1", 70, [vulnerableDependency("a", "1.0.0", "CVE-1")]);
    const after = scan("2", 75, [vulnerableDependency("a", "1.0.1", "CVE-1")]);
    const beforeJson = JSON.stringify(before);
    const afterJson = JSON.stringify(after);
    expect(createSecurityDiff(before, after)).toEqual(createSecurityDiff(before, after));
    expect(JSON.stringify(before)).toBe(beforeJson);
    expect(JSON.stringify(after)).toBe(afterJson);
  });

  it("uses persisted path identity so a version-only change is unchanged and a remediated finding removes the path", () => {
    const vulnerableBefore = vulnerableDependency("lodash", "4.17.11", "CVE-2019-10744");
    const vulnerableAfter = vulnerableDependency("lodash", "4.17.12", "CVE-2019-10744");
    const before = scan("1", 65, [vulnerableBefore], { attackPaths: deriveAttackPaths([vulnerableBefore]) });
    const stillAffected = scan("2", 70, [vulnerableAfter], { attackPaths: deriveAttackPaths([vulnerableAfter]) });

    expect(createSecurityDiff(before, stillAffected).attackPaths).toMatchObject({
      removed: [],
      introduced: [],
      unchanged: 1,
    });

    const remediated = cleanDependency("lodash", "4.17.21");
    const clean = scan("3", 100, [remediated], { attackPaths: deriveAttackPaths([remediated]) });
    const diff = createSecurityDiff(before, clean);
    expect(diff.attackPaths.removed).toHaveLength(1);
    expect(diff.attackPaths.removed[0].findingId).toBe("CVE-2019-10744");
    expect(diff.attackPaths.introduced).toEqual([]);
  });
});

describe("security anomaly detection", () => {
  it("flags material regressions and a returning finding with configurable evidence thresholds", () => {
    const historical = scan("1", 60, [vulnerableDependency("returned", "1.0.0", "CVE-RETURNED")]);
    const before = scan("2", 90, [cleanDependency("stable")]);
    const afterItems = [
      cleanDependency("stable"),
      vulnerableDependency("returned", "1.1.0", "CVE-RETURNED", { severity: "critical", risk: 95 }),
      ...Array.from({ length: 5 }, (_, index) => cleanDependency(`new-${index}`, "1.0.0", index === 0 ? 85 : 0)),
    ];
    const after = scan("3", 65, afterItems, {
      attackPaths: [attackPath("critical-path", "returned", "1.1.0", "CVE-RETURNED", "critical")],
    });

    const anomalies = detectSecurityAnomalies(before, after, { history: [historical, before, after] });
    const codes = anomalies.map(anomaly => anomaly.code);
    expect(codes).toEqual(expect.arrayContaining([
      "DEPENDENCY_SURGE",
      "CRITICAL_FINDING_INCREASE",
      "SECURITY_SCORE_DROP",
      "HIGH_RISK_DEPENDENCY_INTRODUCED",
      "DEPENDENCY_GRAPH_EXPANSION",
      "ATTACK_PATH_EXPANSION",
      "RETURNED_FINDING",
    ]));
    expect(anomalies.every(anomaly => anomaly.evidence.length > 0)).toBe(true);
  });

  it("returns no anomalies for a small improving scan", () => {
    const before = scan("1", 70, [vulnerableDependency("a", "1.0.0", "CVE-1")]);
    const after = scan("2", 85, [cleanDependency("a", "1.0.1")]);
    expect(detectSecurityAnomalies(before, after)).toEqual([]);
  });
});

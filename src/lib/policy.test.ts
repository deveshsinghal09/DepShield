import { describe, expect, it } from "vitest";
import { DEFAULT_SECURITY_POLICY, evaluateSecurityPolicy } from "./policy";
import type { Dependency, Scan, Vulnerability } from "./types";

const sourceStatus: Scan["sourceStatus"] = [
  { source: "npm-audit", status: "ok", message: null },
  { source: "osv", status: "ok", message: null },
];

function scan(id: string, score: number, vulnerabilities: Vulnerability[] = []): Scan {
  const dependency: Dependency = { name: "package-x", version: "1.0.0", direct: true, path: "app → package-x@1.0.0", license: "MIT", vulnerabilities, risk: vulnerabilities.length ? 100 : 0, latest: "1.0.1", recommendation: vulnerabilities.length ? "upgrade" : "none" };
  return { id, createdAt: "2026-08-24T00:00:00.000Z", project: "demo", branch: "uploaded", score, grade: score >= 70 ? "C" : "F", dependencies: 1, vulnerable: vulnerabilities.length ? 1 : 0, critical: vulnerabilities.some(value => value.severity === "critical") ? 1 : 0, duration: 1, items: [dependency], sourceStatus };
}

function critical(id: string, fixedVersion: string | null = "1.0.1"): Vulnerability {
  return { id, cveAlias: id, cvss: 9.5, cvssAvailable: true, severity: "critical", summary: "Critical test finding", fixedVersion };
}

describe("security policy engine", () => {
  it("passes a clean scan when complete source and baseline evidence are available", () => {
    const result = evaluateSecurityPolicy(scan("current", 100), DEFAULT_SECURITY_POLICY, scan("baseline", 100));
    expect(result).toMatchObject({ status: "pass", exitCode: 0 });
    expect(result.rules.every(rule => rule.status === "pass")).toBe(true);
  });

  it("fails low posture and a critical no-fix finding", () => {
    const result = evaluateSecurityPolicy(scan("current", 45, [critical("CVE-2026-1000", null)]), DEFAULT_SECURITY_POLICY, scan("baseline", 100));
    expect(result).toMatchObject({ status: "fail", exitCode: 1 });
    expect(result.rules.filter(rule => rule.status === "fail").map(rule => rule.id)).toEqual(expect.arrayContaining(["minimum-security-score", "maximum-critical-findings", "high-cvss-without-fix"]));
  });

  it("warns rather than claiming a pass when source coverage or a baseline is missing", () => {
    const current = { ...scan("current", 100), sourceStatus: undefined };
    const result = evaluateSecurityPolicy(current);
    expect(result.status).toBe("warning");
    expect(result.rules.filter(rule => rule.status === "warning").map(rule => rule.id)).toEqual(expect.arrayContaining(["new-critical-findings", "source-coverage"]));
  });

  it("detects more newly introduced critical findings than the configured limit", () => {
    const current = scan("current", 80, [critical("CVE-1"), critical("CVE-2"), critical("CVE-3")]);
    const result = evaluateSecurityPolicy(current, DEFAULT_SECURITY_POLICY, scan("baseline", 100));
    const regression = result.rules.find(rule => rule.id === "new-critical-findings");
    expect(regression).toMatchObject({ status: "fail" });
    expect(regression?.reason).toContain("3 new critical findings");
  });

  it("blocks a critical finding with observed source reachability", () => {
    const current = scan("current", 80, [critical("CVE-2026-9000")]);
    current.sourceFilesAnalyzed = 2;
    current.items[0].reachability = {
      status: "REACHABLE",
      confidence: 86,
      sourceFilesAnalyzed: 2,
      entryFiles: ["app/api/route.ts"],
      importedBy: ["app/api/route.ts"],
      observedFunctions: [],
      paths: [],
      internetExposed: true,
      explanation: "Observed import from a route.",
      limitations: [],
    };

    const result = evaluateSecurityPolicy(current, DEFAULT_SECURITY_POLICY, scan("baseline", 100));

    expect(result.rules.find(rule => rule.id === "reachable-critical")).toMatchObject({ status: "fail" });
    expect(result.exitCode).toBe(1);
  });

  it("does not pass the reachable-critical rule when static evidence is incomplete", () => {
    const current = scan("current", 80, [critical("CVE-2026-9001")]);
    current.sourceFilesAnalyzed = 1;
    current.warnings = [{
      code: "REACHABILITY_INCOMPLETE",
      message: "One source file could not be analyzed.",
      recoverable: true,
    }];

    const result = evaluateSecurityPolicy(current, DEFAULT_SECURITY_POLICY, scan("baseline", 100));

    expect(result.rules.find(rule => rule.id === "reachable-critical")).toMatchObject({ status: "warning" });
  });
});

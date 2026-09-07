import { describe, expect, it } from "vitest";
import type { Dependency } from "./types";
import { calculateContextualRisk } from "./contextual-risk";

function dependency(values: Partial<Dependency> = {}): Dependency {
  return {
    name: "lodash",
    version: "4.17.11",
    direct: true,
    path: "app → lodash@4.17.11",
    paths: [{ nodes: ["app", "lodash@4.17.11"], display: "app → lodash@4.17.11" }],
    license: "MIT",
    vulnerabilities: [{
      id: "GHSA-jf85-cpcp-j695",
      aliases: ["GHSA-jf85-cpcp-j695", "CVE-2019-10744"],
      cveAlias: "CVE-2019-10744",
      cvss: 9.1,
      cvssAvailable: true,
      severity: "critical",
      summary: "Prototype pollution",
      fixedVersion: "4.17.12",
      sources: ["OSV", "npm"],
    }],
    risk: 91,
    latest: "4.17.21",
    recommendation: "upgrade",
    ...values,
  };
}

describe("DepShield contextual risk", () => {
  it("produces all five transparent contextual scores and confidence", () => {
    const assessment = calculateContextualRisk({
      dependency: dependency(),
      runtimeScope: "runtime",
      reachability: "reachable",
      vulnerableFunctionUsed: true,
      internetExposure: "internet",
      exploitEvidence: "public-poc",
      vulnerabilityAgeDays: 1_825,
      parentCount: 1,
      pathCount: 1,
      upgradeComplexity: "patch",
      importedApiCount: 1,
      dependencyConflict: false,
      breakingChangeProbability: 0.1,
      sourceAgreement: true,
    });

    expect(assessment.modelVersion).toBe("DepShield Contextual Risk v2");
    expect(assessment.technicalRisk.score).toBe(74);
    expect(assessment.exploitabilityScore.score).toBe(96);
    expect(assessment.exposureScore.score).toBe(93);
    expect(assessment.remediationDifficulty.score).toBe(21);
    expect(assessment.finalPriority.score).toBe(88);
    expect(assessment.confidence).toMatchObject({ score: 100, band: "high" });
    for (const result of [assessment.technicalRisk, assessment.exploitabilityScore, assessment.exposureScore, assessment.remediationDifficulty, assessment.finalPriority]) {
      expect(result.factors.reduce((sum, item) => sum + item.contribution, 0)).toBeCloseTo(result.rawScore, 6);
      expect(result.factors.every(item => item.explanation.length > 0)).toBe(true);
    }
  });

  it("keeps unknown contextual evidence neutral while reducing confidence", () => {
    const unknown = calculateContextualRisk({ dependency: dependency(), runtimeScope: "unknown", reachability: "unknown", internetExposure: "unknown", exploitEvidence: "unknown" });
    const observed = calculateContextualRisk({ dependency: dependency(), runtimeScope: "runtime", reachability: "reachable", internetExposure: "internet", exploitEvidence: "public-poc" });

    expect(unknown.exploitabilityScore.factors.find(item => item.id === "exploitability.reachability")?.contribution).toBe(0);
    expect(unknown.exposureScore.factors.find(item => item.id === "exposure.route")?.contribution).toBe(0);
    expect(unknown.confidence.score).toBeLessThan(observed.confidence.score);
    expect(unknown.finalPriority.score).toBeLessThan(observed.finalPriority.score);
  });

  it("is deterministic and does not score a dependency with no findings", () => {
    const input = { dependency: dependency(), reachability: "possibly-reachable" as const, runtimeScope: "runtime" as const };
    expect(calculateContextualRisk(input)).toEqual(calculateContextualRisk(input));

    const clean = calculateContextualRisk({ dependency: dependency({ vulnerabilities: [], risk: 0, latest: "4.17.21", recommendation: "none" }) });
    expect(clean.technicalRisk.score).toBe(0);
    expect(clean.finalPriority.score).toBe(0);
    expect(clean.remediationDifficulty.score).toBe(0);
  });

  it("uses a clearly labelled severity proxy when CVSS is missing", () => {
    const assessment = calculateContextualRisk({
      dependency: dependency({ vulnerabilities: [{ id: "GHSA-test", cvss: 0, cvssAvailable: false, severity: "high", summary: "Missing CVSS" }] }),
    });
    const cvss = assessment.technicalRisk.factors.find(item => item.id === "technical.cvss");
    expect(cvss).toMatchObject({ label: "Severity proxy", value: 8, contribution: 56 });
    expect(assessment.confidence.factors.find(item => item.id === "confidence.cvss")?.contribution).toBe(0);
  });
});

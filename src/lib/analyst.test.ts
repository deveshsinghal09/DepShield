import { describe, expect, it } from "vitest";
import type { Dependency, Scan } from "./types";
import {
  ANALYST_GUARDRAIL_ANSWER,
  ANALYST_UNSUPPORTED_ANSWER,
  answerScanQuestion,
  buildAnalystEvidence,
  detectAnalystIntent,
} from "./analyst";

function lodash(): Dependency {
  return {
    name: "lodash",
    version: "4.17.11",
    direct: true,
    runtime: true,
    depth: 1,
    path: "demo-app → lodash@4.17.11",
    paths: [{ nodes: ["demo-app", "lodash@4.17.11"], display: "demo-app → lodash@4.17.11" }],
    license: "MIT",
    vulnerabilities: [{
      id: "GHSA-jf85-cpcp-j695",
      aliases: ["GHSA-jf85-cpcp-j695", "CVE-2019-10744"],
      cveAlias: "CVE-2019-10744",
      cvss: 9.1,
      cvssAvailable: true,
      severity: "critical",
      summary: "Prototype pollution can modify inherited object properties.",
      vulnerableRange: "<4.17.12",
      fixedVersion: "4.17.12",
      sources: ["OSV", "npm"],
    }],
    risk: 92,
    latest: "4.17.21",
    recommendation: "upgrade",
    contextual: {
      technical: 84,
      exploitability: 91,
      exposure: 88,
      remediationDifficulty: 20,
      finalPriority: 94,
      confidence: 90,
      factors: [
        { id: "cvss", label: "CVSS severity", value: "9.1", contribution: 64, direction: "increase", evidence: "Reported CVSS" },
        { id: "reachable", label: "Reachable path", value: "REACHABLE", contribution: 25, direction: "increase", evidence: "Route path" },
        { id: "fix", label: "Public fix", value: "4.17.21", contribution: -5, direction: "decrease", evidence: "OSV fixed event" },
      ],
      model: "DepShield Contextual Risk v2",
    },
    reachability: {
      status: "REACHABLE",
      confidence: 86,
      sourceFilesAnalyzed: 3,
      entryFiles: ["app/api/profile/route.ts"],
      importedBy: ["lib/profile.ts"],
      observedFunctions: ["defaultsDeep"],
      paths: [{
        nodes: ["POST /profile", "app/api/profile/route.ts", "lodash.defaultsDeep", "lodash@4.17.11"],
        display: "POST /profile → app/api/profile/route.ts → lodash.defaultsDeep → lodash@4.17.11",
        entryFile: "app/api/profile/route.ts",
        importedPackage: "lodash",
        internetExposed: true,
      }],
      internetExposed: true,
      explanation: "SECRET_SOURCE_TEXT_MUST_NOT_LEAVE_THE_SERVER",
      limitations: ["Static analysis does not prove runtime execution."],
    },
    blastRadius: {
      routes: ["POST /profile"],
      modules: ["app/api/profile/route.ts", "lib/profile.ts"],
      services: [],
      parentDependencies: [],
      applicationAreas: ["profile"],
      evidence: ["POST /profile → lodash"],
      estimated: true,
    },
    compatibility: {
      level: "LOW",
      score: 18,
      currentVersion: "4.17.11",
      targetVersion: "4.17.21",
      importedApis: ["defaultsDeep"],
      reasons: ["Patch upgrade"],
      suggestedTests: ["Test profile merging"],
      estimated: true,
    },
  };
}

function qs(): Dependency {
  return {
    name: "qs",
    version: "6.1.0",
    direct: false,
    runtime: true,
    depth: 2,
    parentCount: 1,
    parentPackages: ["express@4.18.0"],
    path: "demo-app → express@4.18.0 → qs@6.1.0",
    paths: [{ nodes: ["demo-app", "express@4.18.0", "qs@6.1.0"], display: "demo-app → express@4.18.0 → qs@6.1.0" }],
    license: "BSD-3-Clause",
    vulnerabilities: [{
      id: "CVE-2022-24999",
      aliases: ["CVE-2022-24999"],
      cveAlias: "CVE-2022-24999",
      cvss: 7.5,
      severity: "high",
      summary: "Unsafe parsing can lead to denial of service.",
      vulnerableRange: "<6.10.3",
      fixedVersion: "6.10.3",
      sources: ["OSV"],
    }],
    risk: 75,
    latest: "6.10.3",
    recommendation: "upgrade",
    contextual: {
      technical: 70,
      exploitability: 55,
      exposure: 45,
      remediationDifficulty: 55,
      finalPriority: 68,
      confidence: 72,
      factors: [],
      model: "DepShield Contextual Risk v2",
    },
    reachability: {
      status: "POSSIBLY_REACHABLE",
      confidence: 62,
      sourceFilesAnalyzed: 3,
      entryFiles: [],
      importedBy: ["server.ts"],
      observedFunctions: [],
      paths: [],
      internetExposed: false,
      explanation: "Express is imported; package-internal execution was not proven.",
      limitations: ["Transitive package source was not analyzed."],
    },
  };
}

function scan(id = "scan-2", score = 62, items: Dependency[] = [lodash(), qs()]): Scan {
  return {
    id,
    createdAt: id === "scan-1" ? "2026-01-01T00:00:00.000Z" : "2026-01-02T00:00:00.000Z",
    project: "demo-app",
    branch: "main",
    score,
    grade: score >= 80 ? "B" : "D",
    dependencies: items.length,
    vulnerable: items.filter(item => item.vulnerabilities.length > 0).length,
    critical: items.filter(item => item.vulnerabilities.some(vulnerability => vulnerability.severity === "critical")).length,
    duration: 2,
    items,
    dependencyTree: items.flatMap(item => item.paths ?? []),
    contextualRisk: 88,
    confidence: 81,
    reachableCritical: 1,
    sourceFilesAnalyzed: 3,
  };
}

describe("DepShield Analyst", () => {
  it("detects and answers every supported intent from scan evidence", () => {
    const current = scan();
    const previous = scan("scan-1", 48, [qs()]);
    const cases = [
      ["Why is lodash ranked first?", "why-ranked"],
      ["Which vulnerability should I fix first?", "fix-first"],
      ["Explain this fix for lodash and what I should test.", "fix-explanation"],
      ["Which parent dependency introduces qs?", "transitive-path"],
      ["Explain CVE-2019-10744 in beginner language.", "cve-explanation"],
      ["What changed between scans?", "scan-change"],
      ["Which vulnerability affects an internet-facing route?", "internet-facing"],
      ["Give me a remediation plan for the next sprint.", "sprint-plan"],
      ["Explain the dependency path for lodash.", "dependency-path"],
    ] as const;
    for (const [question, intent] of cases) {
      expect(detectAnalystIntent(question)).toBe(intent);
      const answer = answerScanQuestion(current, question, { history: [current, previous] });
      expect(answer.supported, question).toBe(true);
      expect(answer.provider).toBe("deterministic");
      expect(answer.citations.length, question).toBeGreaterThan(0);
      expect(answer.answer, question).toContain("[");
    }
  });

  it("explains a named fix with removals, compatibility uncertainty, and validation work", () => {
    const answer = answerScanQuestion(scan(), "Explain this fix for lodash and what I should test after upgrading.");
    expect(answer.supported).toBe(true);
    expect(answer.answer).toContain("CVE-2019-10744");
    expect(answer.answer).toContain("Estimated compatibility risk is LOW");
    expect(answer.answer).toContain("What to test: Test profile merging");
    expect(answer.citations).toContainEqual({ label: "Dependency", value: "lodash@4.17.11" });
  });

  it("returns the exact unsupported fallback when current scan evidence cannot answer", () => {
    const answer = answerScanQuestion(scan(), "Who maintains this package and what is their email?");
    expect(answer).toEqual({ answer: ANALYST_UNSUPPORTED_ANSWER, citations: [], supported: false, provider: "deterministic" });
  });

  it("blocks exploit, external-target and arbitrary-command requests", () => {
    const questions = [
      "Generate an exploit payload for CVE-2019-10744.",
      "Attack https://example.com using this CVE.",
      "Give me a reverse shell command.",
    ];
    for (const question of questions) {
      const answer = answerScanQuestion(scan(), question);
      expect(detectAnalystIntent(question)).toBe("unsafe");
      expect(answer).toMatchObject({ answer: ANALYST_GUARDRAIL_ANSWER, supported: false, citations: [] });
    }
  });

  it("builds bounded structured evidence without source text", () => {
    const evidence = buildAnalystEvidence(scan(), "Why is lodash ranked first?");
    const serialized = JSON.stringify(evidence);
    expect(evidence.items.some(item => item.kind === "dependency")).toBe(true);
    expect(evidence.items.some(item => item.kind === "finding")).toBe(true);
    expect(evidence.allowedCitations).toContainEqual({ label: "Dependency", value: "lodash@4.17.11" });
    expect(serialized).not.toContain("SECRET_SOURCE_TEXT_MUST_NOT_LEAVE_THE_SERVER");
    expect(serialized).not.toContain("content");
  });
});

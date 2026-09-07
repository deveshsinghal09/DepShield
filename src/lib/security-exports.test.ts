import { describe, expect, it } from "vitest";
import type { Dependency, Scan, Vulnerability } from "./types";
import {
  createCycloneDxSbom,
  createSecurityEvidencePack,
  createSecurityStory,
  DEPSHIELD_SBOM_VERSION,
  EVIDENCE_PACK_VERSION,
} from "./security-exports";

const vulnerability: Vulnerability = {
  id: "GHSA-jf85-cpcp-j695",
  aliases: ["GHSA-jf85-cpcp-j695", "CVE-2019-10744"],
  cveAlias: "CVE-2019-10744",
  cvss: 9.1,
  cvssAvailable: true,
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  severity: "critical",
  summary: "Prototype pollution in lodash",
  vulnerableRange: ">=4.0.0 <4.17.12",
  fixedVersion: "4.17.21",
  references: ["https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695"],
  sources: ["OSV", "npm"],
  provenance: [
    { source: "OSV", retrievedAt: "2026-08-24T09:00:00.000Z", status: "confirmed", confidence: 90, identifiers: ["CVE-2019-10744"] },
  ],
};

function fixtureScan(overrides: Partial<Scan> = {}): Scan {
  const express: Dependency = {
    name: "express",
    version: "4.21.2",
    direct: true,
    runtime: true,
    depth: 1,
    path: "demo → express@4.21.2",
    paths: [{ nodes: ["demo", "express@4.21.2"], display: "demo → express@4.21.2" }],
    license: "MIT",
    vulnerabilities: [],
    risk: 0,
    latest: "4.21.2",
    recommendation: "none",
  };
  const lodash: Dependency = {
    name: "lodash",
    version: "4.17.11",
    direct: false,
    runtime: true,
    depth: 2,
    parentCount: 1,
    parentPackages: ["express"],
    path: "demo → express@4.21.2 → lodash@4.17.11",
    paths: [{ nodes: ["demo", "express@4.21.2", "lodash@4.17.11"], display: "demo → express@4.21.2 → lodash@4.17.11" }],
    license: "MIT",
    vulnerabilities: [vulnerability],
    risk: 94,
    latest: "4.17.21",
    recommendation: "upgrade",
    contextual: {
      technical: 94,
      exploitability: 82,
      exposure: 76,
      remediationDifficulty: 25,
      finalPriority: 92,
      confidence: 88,
      factors: [{ id: "technical.cvss", label: "CVSS", value: "9.1", contribution: 91, direction: "increase", evidence: "OSV and npm" }],
      model: "DepShield Contextual Risk v2",
    },
    reachability: {
      status: "REACHABLE",
      confidence: 86,
      sourceFilesAnalyzed: 2,
      entryFiles: ["src/app/api/profile/route.ts"],
      importedBy: ["src/lib/merge.ts"],
      observedFunctions: ["defaultsDeep"],
      paths: [{
        nodes: ["POST /api/profile", "src/app/api/profile/route.ts", "src/lib/merge.ts", "lodash@4.17.11"],
        display: "POST /api/profile → src/app/api/profile/route.ts → src/lib/merge.ts → lodash@4.17.11",
        entryFile: "src/app/api/profile/route.ts",
        importedPackage: "lodash",
        internetExposed: true,
      }],
      internetExposed: true,
      explanation: "Static import observed; runtime exploitability is not proven.",
      limitations: ["Static analysis is conservative."],
    },
    blastRadius: {
      routes: ["POST /api/profile"],
      modules: ["src/app/api/profile/route.ts", "src/lib/merge.ts"],
      services: [],
      parentDependencies: ["express@4.21.2"],
      applicationAreas: ["api"],
      evidence: ["POST /api/profile → src/lib/merge.ts → lodash@4.17.11"],
      estimated: true,
    },
  };
  return {
    id: "11111111-1111-4111-8111-111111111111",
    createdAt: "2026-08-24T10:00:00.000Z",
    project: "demo",
    branch: "uploaded",
    score: 62,
    grade: "D",
    dependencies: 2,
    vulnerable: 1,
    critical: 1,
    duration: 3,
    items: [express, lodash],
    dependencyTree: [...express.paths!, ...lodash.paths!],
    sourceStatus: [
      { source: "npm-audit", status: "ok", message: null, retrievedAt: "2026-08-24T10:00:00.000Z" },
      { source: "osv", status: "ok", message: null, retrievedAt: "2026-08-24T10:00:00.000Z" },
    ],
    contextualRisk: 92,
    confidence: 88,
    reachableCritical: 1,
    sourceFilesAnalyzed: 2,
    ...overrides,
  };
}

describe("CycloneDX-style SBOM export", () => {
  it("exports components, dependency relationships, vulnerabilities, and DepShield context", () => {
    const sbom = createCycloneDxSbom(fixtureScan());
    const express = sbom.components.find((component) => component.name === "express")!;
    const lodash = sbom.components.find((component) => component.name === "lodash")!;

    expect(sbom).toMatchObject({ bomFormat: "CycloneDX", specVersion: "1.6", version: 1 });
    expect(sbom.metadata.tools.components[0].version).toBe(DEPSHIELD_SBOM_VERSION);
    expect(sbom.components).toHaveLength(2);
    expect(sbom.dependencies.find((edge) => edge.ref === express["bom-ref"])?.dependsOn).toContain(lodash["bom-ref"]);
    expect(sbom.vulnerabilities[0]).toMatchObject({
      id: "CVE-2019-10744",
      affects: [{ ref: lodash["bom-ref"], versions: [{ version: "4.17.11", status: "affected" }] }],
      analysis: { state: "in_triage" },
    });
    expect(sbom.vulnerabilities[0].analysis.detail).toContain("not a not-affected determination");
  });

  it("groups repeated package instances by name and version without dropping paths", () => {
    const scan = fixtureScan();
    scan.items.push({
      ...scan.items[1],
      path: "demo → another@1.0.0 → lodash@4.17.11",
      paths: [{ nodes: ["demo", "another@1.0.0", "lodash@4.17.11"], display: "demo → another@1.0.0 → lodash@4.17.11" }],
      direct: false,
    });
    const sbom = createCycloneDxSbom(scan);
    const lodash = sbom.components.filter((component) => component.name === "lodash");

    expect(lodash).toHaveLength(1);
    const pathProperty = lodash[0].properties?.find((property) => property.name === "depshield:dependency-paths");
    expect(pathProperty?.value).toContain("another@1.0.0");
  });
});

describe("security evidence pack", () => {
  it("preserves provenance, contextual evidence, remediation, policy, and explicit limitations", () => {
    const pack = createSecurityEvidencePack(fixtureScan(), { generatedAt: "2026-08-24T11:00:00.000Z" });

    expect(pack.schema).toBe(EVIDENCE_PACK_VERSION);
    expect(pack.generatedAt).toBe("2026-08-24T11:00:00.000Z");
    expect(pack.findings[0]).toMatchObject({
      vulnerability: { cveAlias: "CVE-2019-10744", cvss: 9.1, sources: ["OSV", "npm"] },
      legacyRisk: 94,
      reachability: { status: "REACHABLE" },
      remediation: { label: "Update Parent Dependency", targetVersion: "4.17.21" },
    });
    expect(pack.findings[0].vulnerability.provenance[0].source).toBe("OSV");
    expect(pack.policy.exitCode).toBe(1);
    expect(pack.limitations.join(" ")).toContain("No safe local Attack Replay evidence");
  });

  it("includes a structured before/after diff when a baseline is supplied", () => {
    const before = fixtureScan();
    const after = fixtureScan({
      id: "22222222-2222-4222-8222-222222222222",
      createdAt: "2026-08-24T12:00:00.000Z",
      score: 100,
      grade: "A",
      vulnerable: 0,
      critical: 0,
      reachableCritical: 0,
      items: [before.items[0]],
      dependencies: 1,
    });
    const pack = createSecurityEvidencePack(after, { previousScan: before, generatedAt: after.createdAt });

    expect(pack.comparison?.beforeScanId).toBe(before.id);
    expect(pack.comparison?.findings.removed).toHaveLength(1);
    expect(pack.story.at(-1)).toMatchObject({ id: "verification", status: "estimated" });
    expect(pack.story.at(-1)?.narrative).toContain("do not prove that remediation caused");
  });
});

describe("deterministic security story", () => {
  it("creates evidence-cited steps and marks unavailable verification honestly", () => {
    const story = createSecurityStory(fixtureScan());

    expect(story).toHaveLength(8);
    expect(story.find((step) => step.id === "priority")).toMatchObject({ status: "estimated" });
    expect(story.find((step) => step.id === "priority")?.narrative).toContain("contextual risk model");
    expect(story.find((step) => step.id === "entry-path")?.evidence[0]).toContain("Path:");
    expect(story.at(-1)).toMatchObject({ id: "verification", status: "not-available" });
    expect(story.at(-1)?.narrative).toContain("remediation causality requires separate");
  });
});

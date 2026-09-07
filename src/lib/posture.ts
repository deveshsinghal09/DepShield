import type { Dependency, PostureRadar, Scan, ScanSummary } from "./types";

export function calculatePosture(items: Dependency[], securityScore: number): PostureRadar {
  if (!items.length) {
    return {
      dependencyHygiene: 100,
      knownVulnerabilityRisk: 100,
      reachabilityExposure: 100,
      patchability: 100,
      supplyChainComplexity: 100,
      remediationReadiness: 100,
    };
  }
  const vulnerable = items.filter((item) => item.vulnerabilities.length > 0);
  const reachable = vulnerable.filter((item) => item.reachability?.status === "REACHABLE");
  const possibly = vulnerable.filter((item) => item.reachability?.status === "POSSIBLY_REACHABLE");
  const fixable = vulnerable.filter((item) => item.recommendation === "upgrade");
  const averageDepth = items.reduce((sum, item) => sum + (item.depth ?? 1), 0) / items.length;
  const transitiveRatio = items.filter((item) => !item.direct).length / items.length;
  const sourceObserved = items.some((item) => (item.reachability?.sourceFilesAnalyzed ?? 0) > 0);
  const exposurePenalty = sourceObserved
    ? reachable.length * 14 + possibly.length * 7
    : vulnerable.length * 5;

  return {
    dependencyHygiene: clamp(100 - (vulnerable.length / items.length) * 75 - transitiveRatio * 10),
    knownVulnerabilityRisk: clamp(securityScore),
    reachabilityExposure: clamp(100 - exposurePenalty),
    patchability: vulnerable.length ? clamp((fixable.length / vulnerable.length) * 100) : 100,
    supplyChainComplexity: clamp(100 - Math.max(0, averageDepth - 1) * 11 - transitiveRatio * 18),
    remediationReadiness: vulnerable.length
      ? clamp(
          (fixable.length / vulnerable.length) * 65 +
            (vulnerable.filter((item) => (item.compatibility?.score ?? 50) < 40).length / vulnerable.length) * 35,
        )
      : 100,
  };
}

export function deterministicSummary(scan: Scan): ScanSummary {
  const vulnerable = scan.items.filter((item) => item.vulnerabilities.length > 0);
  const runtimeReachable = vulnerable.filter(
    (item) => item.runtime !== false && item.reachability?.status === "REACHABLE",
  );
  const fixable = vulnerable.filter((item) => item.recommendation === "upgrade");
  const top = vulnerable.toSorted((a, b) => b.risk - a.risk)[0];
  const estimatedReduction = vulnerable.length
    ? Math.round(
        (fixable.reduce((sum, item) => sum + item.risk, 0) /
          Math.max(1, vulnerable.reduce((sum, item) => sum + item.risk, 0))) *
          100,
      )
    : 0;
  const reachabilityPhrase = scan.sourceFilesAnalyzed
    ? `${runtimeReachable.length} appear reachable from the supplied runtime source files.`
    : "Runtime reachability is unknown because no source files were supplied.";
  const topPhrase = top
    ? `${top.name}@${top.version} is the current highest-priority dependency at ${top.risk}/100.`
    : "No known vulnerable dependency was identified.";

  return {
    executive:
      `This scan assessed ${scan.dependencies} dependencies and found ${scan.vulnerable} with known vulnerabilities. ` +
      `${reachabilityPhrase} ${fixable.length} dependencies have a reported upgrade path; addressing them could remove approximately ${estimatedReduction}% of identified package risk.`,
    developer:
      `${topPhrase} Project security score is ${scan.score}/100 (${scan.grade}). ` +
      `Review exact versions, advisory provenance, dependency paths, static reachability evidence, and the estimated compatibility preview before changing manifests.`,
    evidence: [
      `Scan: ${scan.id}`,
      `Dependencies: ${scan.dependencies}`,
      `Vulnerable dependencies: ${scan.vulnerable}`,
      `Reachable runtime findings: ${runtimeReachable.length}`,
      `Advisory-reported upgrade paths: ${fixable.length}`,
      ...(top ? [`Top dependency: ${top.name}@${top.version}`, `Top priority: ${top.risk}`] : []),
    ],
    generatedBy: "deterministic",
  };
}

export function fixableRiskPercent(items: Dependency[]) {
  const total = items.reduce((sum, item) => sum + item.risk, 0);
  if (!total) return 100;
  const fixable = items
    .filter((item) => item.recommendation === "upgrade")
    .reduce((sum, item) => sum + item.risk, 0);
  return clamp((fixable / total) * 100);
}

export function averageConfidence(items: Dependency[]) {
  const findings = items.filter((item) => item.vulnerabilities.length > 0);
  if (!findings.length) return 100;
  return clamp(
    findings.reduce((sum, item) => sum + (item.contextual?.confidence ?? 35), 0) / findings.length,
  );
}

function clamp(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

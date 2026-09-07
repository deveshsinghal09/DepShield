import { randomUUID } from "node:crypto";
import type {
  BlastRadius,
  CompatibilityPreview,
  ContextualScores,
  Dependency,
  ReachabilityEvidence as AppReachabilityEvidence,
  RiskFactor,
  Scan,
  ScanWarning,
  SourceFileInput,
} from "../lib/types";
import { calculateContextualRisk, type ContextualRiskAssessment } from "../lib/contextual-risk";
import { deriveAttackPaths } from "../lib/attack-paths";
import { estimateUpgradeImpact } from "../lib/compatibility";
import { getFeatureFlags } from "../lib/feature-flags";
import { averageConfidence, calculatePosture, deterministicSummary, fixableRiskPercent } from "../lib/posture";
import { applyRiskPropagation } from "../lib/risk-propagation";
import { dependencyRisk, grade, projectScore } from "../lib/risk";
import { isVersionInRange } from "../lib/semver";
import { mergeAdvisories, compareVersions } from "./advisory-merge";
import { extractDependencyGraph, parseLockfile, parseManifest, type InstalledDependency } from "./dependency-tree";
import { runNpmAudit, type AuditResult } from "./npm-audit";
import { queryOsv, type OsvResult } from "./osv-client";
import {
  analyzeReachability,
  dependencyReachabilityKey,
  type ReachabilityAnalysis,
  type ReachabilityEvidence,
} from "./reachability";
import { vulnerableFunctionsFor } from "./vulnerable-functions";

export type ScannerDependencies = {
  audit?: typeof runNpmAudit;
  osv?: typeof queryOsv;
};

export async function scanProject(
  packageText: string,
  lockText: string | undefined,
  services: ScannerDependencies = {},
  sourceFiles: SourceFileInput[] = [],
): Promise<Scan> {
  const started = Date.now();
  const observedAt = new Date().toISOString();
  const manifest = parseManifest(packageText);
  const lock = parseLockfile(lockText);
  const installed = extractDependencyGraph(manifest, lock);
  const flags = getFeatureFlags();
  const [audit, osv] = await Promise.all([
    resilientAudit(() => (services.audit ?? runNpmAudit)(packageText, lockText!)),
    resilientOsv(() => (services.osv ?? queryOsv)(installed)),
  ]);
  const warnings: ScanWarning[] = [];
  if (audit.warning) warnings.push({ code: "NPM_AUDIT_FAILED", message: audit.warning, recoverable: true });
  if (osv.warning) warnings.push({ code: "OSV_API_FAILED", message: osv.warning, recoverable: true });

  const baseItems = installed.map((dependency) => {
    const auditFindings = (audit.findings.get(dependency.name) ?? []).filter(
      (finding) => isVersionInRange(dependency.version, finding.vulnerableRange) !== false,
    );
    const advisories = mergeAdvisories([
      ...auditFindings,
      ...(osv.findings.get(`${dependency.name}@${dependency.version}`) ?? []),
    ]);
    if (advisories.some((value) => value.cvssAvailable === false)) {
      warnings.push({
        code: "MISSING_CVSS",
        message: `${dependency.name}@${dependency.version} has an advisory without a CVSS score; severity metadata was retained without inventing a numeric score.`,
        recoverable: true,
      });
    }
    return createBaseDependency(dependency, advisories, manifest.name ?? "Application", observedAt);
  });

  const reachability = flags.reachability
    ? analyzeSourceBundle(sourceFiles, baseItems, installed)
    : disabledReachability(sourceFiles.length);
  if (!flags.reachability && sourceFiles.length) {
    warnings.push({
      code: "REACHABILITY_DISABLED",
      message: "Application source files were supplied but static reachability is disabled by ENABLE_REACHABILITY.",
      recoverable: true,
    });
  }
  if (flags.reachability && sourceFiles.length && (!reachability.complete || reachability.errors.length || reachability.warnings.length)) {
    warnings.push({
      code: "REACHABILITY_INCOMPLETE",
      message:
        `Static reachability analyzed ${reachability.stats.filesAnalyzed}/${reachability.stats.filesReceived} supplied source files. ` +
        `${reachability.errors.length + reachability.warnings.length} limitation${reachability.errors.length + reachability.warnings.length === 1 ? " was" : "s were"} recorded; NOT_OBSERVED never means safe.`,
      recoverable: true,
    });
  }

  let items: Dependency[] = baseItems.map((item, index) => {
    const installedDependency = installed[index];
    const evidence = reachability.byDependency[
      dependencyReachabilityKey(item.name, item.version, installedDependency.key)
    ];
    const appReachability = mapReachability(evidence, reachability, sourceFiles.length);
    const blastRadius = mapBlastRadius(evidence);
    const compatibility = compatibilityFor(item, appReachability, blastRadius);
    const assessment = contextualAssessment(item, installedDependency, appReachability, evidence, compatibility);
    const contextual = mapContextualScores(assessment);
    return {
      ...item,
      vulnerabilities: item.vulnerabilities.map((finding) => withFindingConfidence(finding, item, appReachability)),
      reachability: appReachability,
      blastRadius,
      compatibility,
      contextual,
      risk: contextual.finalPriority,
    };
  });

  items = applyRiskPropagation(items).toSorted(
    (left, right) =>
      (right.propagation?.contextualRisk ?? right.risk) - (left.propagation?.contextualRisk ?? left.risk) ||
      right.risk - left.risk ||
      left.name.localeCompare(right.name),
  );

  const score = projectScore(items);
  const vulnerableItems = items.filter((item) => item.vulnerabilities.length > 0);
  const topRisk = vulnerableItems.slice(0, 5);
  const scan: Scan = {
    id: randomUUID(),
    createdAt: observedAt,
    project: manifest.name ?? "uploaded-project",
    branch: "uploaded",
    score,
    grade: grade(score),
    dependencies: items.length,
    vulnerable: vulnerableItems.length,
    critical: items.filter((item) => item.vulnerabilities.some((value) => value.severity === "critical")).length,
    duration: Math.max(1, Math.round((Date.now() - started) / 1000)),
    items,
    dependencyTree: items.flatMap((item) => item.paths ?? []),
    attackPaths: deriveAttackPaths(items),
    sourceStatus: [
      audit.status,
      osv.status,
      {
        source: "nvd",
        status: "skipped",
        message: flags.nvdProvider
          ? "NVD enrichment is enabled but no API adapter is configured in this build."
          : "Optional NVD enrichment is disabled.",
        retrievedAt: observedAt,
        confidence: 0,
      },
      {
        source: "github-advisory",
        status: "skipped",
        message: flags.githubAdvisoryProvider
          ? "GitHub Advisory enrichment is enabled but no authenticated adapter is configured in this build."
          : "Optional GitHub Advisory enrichment is disabled.",
        retrievedAt: observedAt,
        confidence: 0,
      },
    ],
    warnings: uniqueWarnings(warnings),
    contextualRisk: topRisk.length
      ? Math.round(topRisk.reduce((sum, item) => sum + item.risk, 0) / topRisk.length)
      : 0,
    confidence: averageConfidence(items),
    reachableCritical: items.reduce(
      (total, item) =>
        total +
        (item.reachability?.status === "REACHABLE"
          ? item.vulnerabilities.filter((value) => value.severity === "critical").length
          : 0),
      0,
    ),
    fixableRiskPercent: fixableRiskPercent(items),
    sourceFilesAnalyzed: reachability.stats.filesAnalyzed,
    posture: calculatePosture(items, score),
  };
  scan.summary = deterministicSummary(scan);
  return scan;
}

function withFindingConfidence(
  finding: Dependency["vulnerabilities"][number],
  dependency: Dependency,
  reachability: AppReachabilityEvidence,
) {
  const evidence: string[] = [];
  let confidence = 0;
  const add = (condition: boolean, points: number, explanation: string) => {
    if (!condition) return;
    confidence += points;
    evidence.push(`+${points} ${explanation}`);
  };
  add(finding.cvssAvailable !== false && finding.cvss > 0, 15, "reported CVSS");
  add(/^v?\d+\.\d+\.\d+/.test(dependency.version), 15, "exact installed version");
  add(Boolean(dependency.paths?.length), 15, "known dependency path");
  add(reachability.status !== "UNKNOWN", 20, `reachability assessed as ${reachability.status}`);
  add(finding.fixedVersion !== undefined, 10, finding.fixedVersion ? "reported fixed version" : "fix status recorded without a target");
  add(finding.knownExploit !== undefined && finding.knownExploit !== null, 10, "exploit evidence status recorded");
  add((finding.sources?.length ?? 0) >= 2, 15, "identifier corroborated by multiple sources");
  return { ...finding, confidence: Math.min(100, confidence), confidenceEvidence: evidence };
}

async function resilientAudit(action: () => Promise<AuditResult>): Promise<AuditResult> {
  try {
    return await action();
  } catch (error) {
    const retrievedAt = new Date().toISOString();
    const message = `npm audit failed unexpectedly: ${providerError(error)}`;
    return {
      findings: new Map(),
      warning: message,
      status: { source: "npm-audit", status: "failed", message, retrievedAt, confidence: 0 },
    };
  }
}

async function resilientOsv(action: () => Promise<OsvResult>): Promise<OsvResult> {
  try {
    return await action();
  } catch (error) {
    const retrievedAt = new Date().toISOString();
    const message = `OSV enrichment failed unexpectedly: ${providerError(error)}`;
    return {
      findings: new Map(),
      warning: message,
      status: { source: "osv", status: "failed", message, retrievedAt, confidence: 0 },
    };
  }
}

function providerError(error: unknown) {
  const value = error instanceof Error ? error.message : "unknown provider error";
  return value.replace(/[\r\n]+/g, " ").slice(0, 300);
}

function createBaseDependency(
  dependency: InstalledDependency,
  advisories: Dependency["vulnerabilities"],
  project: string,
  observedAt: string,
): Dependency {
  const highest = Math.max(0, ...advisories.map((value) => value.cvss));
  const fixes = advisories
    .map((value) => value.fixedVersion)
    .filter((value): value is string => Boolean(value))
    .toSorted(compareVersions);
  const allFixed = advisories.length > 0 && advisories.every((value) => Boolean(value.fixedVersion));
  const someFixed = fixes.length > 0;
  const recommended = allFixed ? fixes.at(-1)! : dependency.version;
  const recommendation: Dependency["recommendation"] =
    advisories.length === 0 ? "none" : allFixed ? "upgrade" : someFixed ? "partial-fix" : "no-fix";
  return {
    name: dependency.name,
    version: dependency.version,
    direct: dependency.direct,
    runtime: dependency.runtime,
    devOnly: dependency.devOnly,
    optional: dependency.optional,
    depth: dependency.depth,
    parentCount: dependency.parentCount,
    parentPackages: dependency.parentPackages,
    path: dependency.paths[0]?.display ?? `${project} → ${dependency.name}@${dependency.version}`,
    paths: dependency.paths,
    license: dependency.license,
    vulnerabilities: advisories,
    risk: dependencyRisk(highest, dependency.direct, allFixed, advisories.length),
    latest: recommended,
    recommendation,
    lastObservedAt: observedAt,
  };
}

function analyzeSourceBundle(
  sourceFiles: SourceFileInput[],
  items: Dependency[],
  installed: InstalledDependency[],
): ReachabilityAnalysis {
  return analyzeReachability(
    sourceFiles,
    items.map((item, index) => {
      const rule = vulnerableFunctionsFor(item.name, item.vulnerabilities);
      return {
        name: item.name,
        version: item.version,
        direct: item.direct,
        instanceId: installed[index]?.key ?? item.paths?.[0]?.display ?? `${index}`,
        path: item.path,
        paths: item.paths,
        vulnerableApis: rule.functions,
      };
    }),
  );
}

function disabledReachability(filesReceived: number): ReachabilityAnalysis {
  return {
    byDependency: {},
    findings: [],
    routes: [],
    warnings: [],
    errors: [],
    complete: false,
    stats: {
      filesReceived,
      filesAnalyzed: 0,
      filesSkipped: filesReceived,
      totalBytes: 0,
      moduleEdges: 0,
      packageImports: 0,
      routeHints: 0,
    },
    limitations: [
      "Reachability analysis is disabled by ENABLE_REACHABILITY.",
      "Reachability remains UNKNOWN; disabling static analysis is not evidence that a dependency is safe.",
    ],
  };
}

function mapReachability(
  evidence: ReachabilityEvidence | undefined,
  analysis: ReachabilityAnalysis,
  receivedFiles: number,
): AppReachabilityEvidence {
  if (!evidence) {
    const disabled = analysis.limitations.some((value) => value.includes("disabled by ENABLE_REACHABILITY"));
    return {
      status: "UNKNOWN",
      confidence: receivedFiles ? 20 : 15,
      sourceFilesAnalyzed: analysis.stats.filesAnalyzed,
      entryFiles: [],
      importedBy: [],
      observedFunctions: [],
      paths: [],
      internetExposed: false,
      explanation: disabled
        ? "Reachability is unknown because static analysis is disabled by configuration."
        : receivedFiles
        ? "No dependency-instance reachability result was produced from the bounded source bundle."
        : "Reachability is unknown because no application source files were supplied.",
      limitations: analysis.limitations,
    };
  }
  const internetExposed = evidence.paths.some((path) => Boolean(path.route));
  const confidence =
    evidence.status === "REACHABLE"
      ? 86
      : evidence.status === "POSSIBLY_REACHABLE"
        ? 62
        : evidence.status === "NOT_OBSERVED"
          ? analysis.complete
            ? 52
            : 30
          : 20;
  return {
    status: evidence.status,
    confidence,
    sourceFilesAnalyzed: analysis.stats.filesAnalyzed,
    entryFiles: [...new Set(evidence.paths.flatMap((path) => path.route?.file ? [path.route.file] : []))],
    importedBy: [...new Set(evidence.packageImports.map((item) => item.sourceFile))],
    observedFunctions: evidence.matchedVulnerableApis.length
      ? evidence.matchedVulnerableApis
      : evidence.observedApis,
    paths: evidence.paths.map((path) => ({
      nodes: path.nodes,
      display: path.nodes.join(" → "),
      entryFile: path.sourceFiles[0] ?? "Application source",
      importedPackage: evidence.dependency.name,
      internetExposed: Boolean(path.route),
    })),
    internetExposed,
    explanation: evidence.explanation,
    limitations: evidence.limitations,
  };
}

function mapBlastRadius(evidence?: ReachabilityEvidence): BlastRadius {
  return {
    routes: evidence?.blastRadius.routes.map((route) => `${route.method} ${route.route}`) ?? [],
    modules: evidence?.blastRadius.modules ?? [],
    services: [],
    parentDependencies: evidence?.blastRadius.parentDependencies ?? [],
    applicationAreas: evidence?.blastRadius.applicationAreas ?? [],
    evidence: evidence?.blastRadius.evidencePaths.map((path) => path.nodes.join(" → ")) ?? [],
    estimated: true,
  };
}

function compatibilityFor(
  item: Dependency,
  reachability: AppReachabilityEvidence,
  blastRadius: BlastRadius,
): CompatibilityPreview {
  if (!item.latest || item.latest === item.version || item.recommendation === "no-fix") {
    return {
      level: "UNKNOWN",
      score: 50,
      currentVersion: item.version,
      targetVersion: null,
      importedApis: reachability.observedFunctions,
      reasons: ["No complete, exact fixed target is available for a compatibility estimate."],
      suggestedTests: ["Review upstream advisories and parent dependency releases manually."],
      estimated: true,
    };
  }
  const estimate = estimateUpgradeImpact({
    currentVersion: item.version,
    targetVersion: item.latest,
    direct: item.direct,
    importedApis: reachability.observedFunctions,
    relatedRoutes: blastRadius.routes,
  });
  return {
    level: estimate.risk.toUpperCase() as CompatibilityPreview["level"],
    score: estimate.score,
    currentVersion: item.version,
    targetVersion: item.latest,
    importedApis: reachability.observedFunctions,
    reasons: [
      ...estimate.reasons,
      estimate.uncertainty,
      ...(!item.direct ? ["The package is transitive; its parent must resolve a compatible fixed child version."] : []),
    ],
    suggestedTests: estimate.testingFocus,
    estimated: true,
  };
}

function contextualAssessment(
  item: Dependency,
  dependency: InstalledDependency,
  reachability: AppReachabilityEvidence,
  rawReachability: ReachabilityEvidence | undefined,
  compatibility: CompatibilityPreview,
) {
  const functions = vulnerableFunctionsFor(item.name, item.vulnerabilities).functions;
  const published = item.vulnerabilities
    .map((value) => value.publishedAt)
    .filter((value): value is string => Boolean(value))
    .toSorted()[0];
  const ageDays = published
    ? Math.max(0, Math.floor((Date.now() - new Date(published).getTime()) / 86_400_000))
    : null;
  const reachabilityClassification =
    reachability.status === "POSSIBLY_REACHABLE"
      ? "possibly-reachable"
      : reachability.status === "NOT_OBSERVED"
        ? "not-observed"
        : reachability.status.toLowerCase() as "reachable" | "unknown";
  const fixStatus =
    item.recommendation === "upgrade"
      ? "available"
      : item.recommendation === "partial-fix"
        ? "partial"
        : item.recommendation === "no-fix"
          ? "none"
          : "unknown";
  const upgradeComplexity = !item.vulnerabilities.length
    ? "unknown"
    : !item.direct
      ? "update-parent"
      : compatibility.level === "UNKNOWN"
        ? "manual-review"
        : semverComplexity(item.version, item.latest);
  return calculateContextualRisk({
    dependency: item,
    dependencyDepth: dependency.depth,
    runtimeScope: dependency.devOnly ? "dev" : dependency.optional ? "optional" : "runtime",
    reachability: reachabilityClassification,
    vulnerableFunctionUsed: functions.length
      ? rawReachability?.vulnerableApiMatch === "MATCHED"
        ? true
        : rawReachability?.vulnerableApiMatch === "NOT_OBSERVED"
          ? false
          : null
      : null,
    internetExposure: reachability.internetExposed
      ? "internet"
      : reachability.status === "REACHABLE"
        ? "internal"
        : reachability.sourceFilesAnalyzed
          ? "not-observed"
          : "unknown",
    exploitEvidence: item.vulnerabilities.some((value) => value.knownExploit === true)
      ? "known-exploited"
      : item.vulnerabilities.length && item.vulnerabilities.every((value) => value.knownExploit === false)
        ? "none-observed"
        : "unknown",
    vulnerabilityAgeDays: ageDays,
    parentCount: dependency.parentCount,
    pathCount: dependency.paths.length,
    upgradeComplexity,
    importedApiCount: rawReachability?.observedApis.length ?? null,
    dependencyConflict: null,
    breakingChangeProbability: compatibility.level === "UNKNOWN" ? null : compatibility.score / 100,
    exactVersionKnown: /^v?\d+\.\d+\.\d+/.test(item.version),
    dependencyPathKnown: Boolean(item.paths?.length),
    sourceAgreement: item.vulnerabilities.some((value) => (value.sources?.length ?? 0) > 1) ? true : null,
    fixStatus,
  });
}

function semverComplexity(current: string, target: string) {
  const left = current.replace(/^v/, "").split(".").map(Number);
  const right = target.replace(/^v/, "").split(".").map(Number);
  if (!left.every(Number.isFinite) || !right.every(Number.isFinite)) return "manual-review" as const;
  if (right[0] > left[0]) return "major" as const;
  if (right[1] > left[1]) return "minor" as const;
  return "patch" as const;
}

function mapContextualScores(assessment: ContextualRiskAssessment): ContextualScores {
  const groups = [
    ["technical", assessment.technicalRisk.factors],
    ["exploitability", assessment.exploitabilityScore.factors],
    ["exposure", assessment.exposureScore.factors],
    ["remediation", assessment.remediationDifficulty.factors],
  ] as const;
  const factors: RiskFactor[] = groups.flatMap(([group, values]) =>
    values.map((value) => ({
      id: `${group}.${value.id}`,
      label: value.label,
      value: String(value.value ?? "Unknown"),
      contribution: value.contribution,
      direction: value.effect === "confidence" ? "neutral" : value.effect,
      evidence: [...value.evidence, value.explanation].filter(Boolean).join(" "),
    })),
  );
  return {
    technical: assessment.technicalRisk.score,
    exploitability: assessment.exploitabilityScore.score,
    exposure: assessment.exposureScore.score,
    remediationDifficulty: assessment.remediationDifficulty.score,
    finalPriority: assessment.finalPriority.score,
    confidence: assessment.confidence.score,
    factors,
    model: assessment.modelVersion,
  };
}

function uniqueWarnings(values: ScanWarning[]) {
  return [...new Map(values.map((value) => [`${value.code}:${value.message}`, value])).values()];
}

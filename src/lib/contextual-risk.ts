import type { Dependency, Severity, Vulnerability } from "./types";

export const CONTEXTUAL_RISK_MODEL_VERSION = "DepShield Contextual Risk v2" as const;

export type ReachabilityClassification =
  | "reachable"
  | "possibly-reachable"
  | "not-observed"
  | "unknown";

export type DependencyScope = "runtime" | "dev" | "optional" | "unknown";
export type ExposureClassification = "internet" | "internal" | "not-observed" | "unknown";
export type ExploitEvidence = "known-exploited" | "public-poc" | "none-observed" | "unknown";
export type FixStatus = "available" | "partial" | "none" | "unknown";
export type UpgradeComplexity = "patch" | "minor" | "major" | "update-parent" | "manual-review" | "no-fix" | "unknown";

export type ScoreFactorEffect = "increase" | "decrease" | "neutral" | "confidence";

export type ScoreFactor = {
  id: string;
  label: string;
  value: string | number | boolean | null;
  contribution: number;
  effect: ScoreFactorEffect;
  explanation: string;
  evidence: string[];
};

export type ScoreBreakdown = {
  score: number;
  rawScore: number;
  factors: ScoreFactor[];
};

export type ConfidenceBreakdown = ScoreBreakdown & {
  band: "high" | "medium" | "low";
};

export type ContextualRiskInput = {
  dependency: Dependency;
  dependencyDepth?: number | null;
  runtimeScope?: DependencyScope;
  reachability?: ReachabilityClassification;
  vulnerableFunctionUsed?: boolean | null;
  internetExposure?: ExposureClassification;
  exploitEvidence?: ExploitEvidence;
  vulnerabilityAgeDays?: number | null;
  parentCount?: number | null;
  pathCount?: number | null;
  upgradeComplexity?: UpgradeComplexity;
  importedApiCount?: number | null;
  dependencyConflict?: boolean | null;
  breakingChangeProbability?: number | null;
  exactVersionKnown?: boolean | null;
  dependencyPathKnown?: boolean | null;
  sourceAgreement?: boolean | null;
  fixStatus?: FixStatus;
};

export type ContextualRiskAssessment = {
  modelVersion: typeof CONTEXTUAL_RISK_MODEL_VERSION;
  technicalRisk: ScoreBreakdown;
  exploitabilityScore: ScoreBreakdown;
  exposureScore: ScoreBreakdown;
  remediationDifficulty: ScoreBreakdown;
  finalPriority: ScoreBreakdown;
  confidence: ConfidenceBreakdown;
};

const round = (value: number, precision = 2) => {
  const multiplier = 10 ** precision;
  return Math.round((value + Number.EPSILON) * multiplier) / multiplier;
};

const clamp = (value: number) => Math.max(0, Math.min(100, value));

function factor(
  id: string,
  label: string,
  value: ScoreFactor["value"],
  contribution: number,
  explanation: string,
  evidence: string[] = [],
  forcedEffect?: ScoreFactorEffect,
): ScoreFactor {
  const normalized = round(contribution);
  return {
    id,
    label,
    value,
    contribution: normalized,
    effect: forcedEffect ?? (normalized > 0 ? "increase" : normalized < 0 ? "decrease" : "neutral"),
    explanation,
    evidence,
  };
}

function breakdown(factors: ScoreFactor[]): ScoreBreakdown {
  const rawScore = round(factors.reduce((total, item) => total + item.contribution, 0));
  return { score: Math.round(clamp(rawScore)), rawScore, factors };
}

const severityProxy: Record<Severity, number> = {
  critical: 9.25,
  high: 8,
  medium: 5.5,
  low: 2.5,
  unknown: 0,
};

const severityRank: Record<Severity, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

function highestSeverity(values: Vulnerability[]): Severity {
  return values.reduce<Severity>((highest, item) =>
    severityRank[item.severity] > severityRank[highest] ? item.severity : highest, "unknown");
}

function cvssEvidence(values: Vulnerability[]) {
  const reported = values
    .filter(item => item.cvssAvailable !== false && Number.isFinite(item.cvss) && item.cvss > 0)
    .toSorted((a, b) => b.cvss - a.cvss)[0];
  if (reported) {
    return {
      value: Math.min(10, reported.cvss),
      reported: true,
      evidence: [`${reported.cveAlias ?? reported.id}: reported CVSS ${reported.cvss.toFixed(1)}`],
    };
  }
  const severity = highestSeverity(values);
  return {
    value: severityProxy[severity],
    reported: false,
    evidence: severity === "unknown" ? [] : [`Severity ${severity} used as an explicit scoring proxy because CVSS is unavailable`],
  };
}

function inferDepth(dependency: Dependency): number | null {
  const lengths = dependency.paths?.map(path => Math.max(1, path.nodes.length - 1)) ?? [];
  if (lengths.length) return Math.min(...lengths);
  return dependency.direct ? 1 : null;
}

function inferParentCount(dependency: Dependency): number | null {
  if (!dependency.paths?.length) return null;
  const parents = new Set(dependency.paths.map(path => path.nodes.at(-2)).filter(Boolean));
  return parents.size;
}

function inferFixStatus(dependency: Dependency): FixStatus {
  if (!dependency.vulnerabilities.length) return "unknown";
  if (dependency.recommendation === "upgrade") return "available";
  if (dependency.recommendation === "partial-fix") return "partial";
  if (dependency.recommendation === "no-fix") return "none";
  const fixes = dependency.vulnerabilities.filter(item => Boolean(item.fixedVersion)).length;
  return fixes === dependency.vulnerabilities.length ? "available" : fixes ? "partial" : "unknown";
}

function parseVersion(value: string): [number, number, number] | null {
  const match = value.trim().replace(/^v/, "").match(/^(\d+)\.(\d+)\.(\d+)/);
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function inferUpgradeComplexity(dependency: Dependency, fixStatus: FixStatus): UpgradeComplexity {
  if (fixStatus === "none") return "no-fix";
  if (fixStatus === "partial") return "manual-review";
  if (fixStatus !== "available") return "unknown";
  if (!dependency.direct) return "update-parent";
  const current = parseVersion(dependency.version);
  const target = parseVersion(dependency.latest);
  if (!current || !target) return "unknown";
  if (target[0] !== current[0]) return "major";
  if (target[1] !== current[1]) return "minor";
  return "patch";
}

function normalizeCount(value: number | null | undefined) {
  return value === null || value === undefined || !Number.isFinite(value) ? null : Math.max(0, Math.floor(value));
}

function normalizeProbability(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  return Math.max(0, Math.min(1, value));
}

function technicalFactors(input: ContextualRiskInput, fixStatus: FixStatus): ScoreFactor[] {
  const { dependency } = input;
  const cvss = cvssEvidence(dependency.vulnerabilities);
  const scope = input.runtimeScope ?? "unknown";
  const depth = input.dependencyDepth ?? inferDepth(dependency);
  const cveBonus = Math.min(10, Math.max(0, dependency.vulnerabilities.length - 1) * 2);
  const scopeContribution = scope === "runtime" ? 5 : scope === "optional" ? 3 : 0;
  const depthContribution = depth === null ? 0 : depth <= 1 ? 5 : depth === 2 ? 3 : depth === 3 ? 1 : 0;
  const fixContribution = fixStatus === "none" ? 5 : fixStatus === "available" ? -5 : 0;
  return [
    factor(
      "technical.cvss",
      cvss.reported ? "Highest reported CVSS" : "Severity proxy",
      cvss.value,
      cvss.value * 7,
      cvss.reported
        ? `CVSS ${cvss.value.toFixed(1)} contributes ${round(cvss.value * 7)} points.`
        : cvss.value
          ? `Missing CVSS uses a documented ${cvss.value.toFixed(2)} severity proxy and contributes ${round(cvss.value * 7)} points.`
          : "Neither reported CVSS nor a known severity was available; no technical points were added.",
      cvss.evidence,
    ),
    factor("technical.direct", "Direct dependency", dependency.direct, dependency.direct ? 5 : 0,
      dependency.direct ? "Direct application dependency contributes 5 points." : "Transitive status adds no direct-dependency points."),
    factor("technical.scope", "Dependency scope", scope, scopeContribution,
      scope === "runtime" ? "Runtime scope contributes 5 points." : scope === "optional" ? "Optional runtime scope contributes 3 points." : scope === "dev" ? "Dev-only scope adds no runtime points." : "Unknown scope is neutral and adds no points."),
    factor("technical.cve-count", "Additional applicable CVEs", dependency.vulnerabilities.length, cveBonus,
      `${Math.max(0, dependency.vulnerabilities.length - 1)} additional finding(s) contribute ${cveBonus} points, capped at 10.`),
    factor("technical.fix", "Fix availability", fixStatus, fixContribution,
      fixStatus === "available" ? "A complete public fix decreases technical risk by 5 points." : fixStatus === "none" ? "No known fix increases technical risk by 5 points." : fixStatus === "partial" ? "A partial fix is neutral pending manual review." : "Unknown fix status is neutral."),
    factor("technical.depth", "Dependency depth", depth, depthContribution,
      depth === null ? "Dependency depth is unknown and adds no points." : `Shortest dependency depth ${depth} contributes ${depthContribution} point(s).`),
  ];
}

function exploitabilityFactors(input: ContextualRiskInput): ScoreFactor[] {
  const cvss = cvssEvidence(input.dependency.vulnerabilities);
  const reachability = input.reachability ?? "unknown";
  const functionUsed = input.vulnerableFunctionUsed ?? null;
  const exploit = input.exploitEvidence ?? "unknown";
  const age = normalizeCount(input.vulnerabilityAgeDays);
  const reachContribution = reachability === "reachable" ? 25 : reachability === "possibly-reachable" ? 12 : 0;
  const functionContribution = functionUsed === true ? 20 : 0;
  const exploitContribution = exploit === "known-exploited" ? 15 : exploit === "public-poc" ? 10 : 0;
  const ageContribution = age === null ? 0 : Math.min(5, age / 365);
  return [
    factor("exploitability.cvss", "CVSS exploitability proxy", cvss.value, cvss.value * 4,
      `${cvss.reported ? "Reported CVSS" : "Severity proxy"} contributes ${round(cvss.value * 4)} of 40 possible points.`, cvss.evidence),
    factor("exploitability.reachability", "Static reachability", reachability, reachContribution,
      reachability === "reachable" ? "A source-backed reachable path contributes 25 points." : reachability === "possibly-reachable" ? "A possible path contributes 12 points." : reachability === "not-observed" ? "No path was observed; this adds no points and is not a claim of safety." : "Unknown reachability is neutral."),
    factor("exploitability.function", "Vulnerable API usage", functionUsed, functionContribution,
      functionUsed === true ? "A vulnerable function/API reference contributes 20 points." : functionUsed === false ? "No vulnerable API reference was observed; no points were added." : "Function-level evidence is unknown and neutral."),
    factor("exploitability.evidence", "Known exploitability evidence", exploit, exploitContribution,
      exploit === "known-exploited" ? "Known exploitation evidence contributes 15 points." : exploit === "public-poc" ? "A public proof-of-concept contributes 10 points." : exploit === "none-observed" ? "No exploit evidence was observed; no points were added." : "Exploit evidence is unknown and neutral."),
    factor("exploitability.age", "Vulnerability age", age, ageContribution,
      age === null ? "Publication age is unknown and neutral." : `${age} day(s) since publication contribute ${round(ageContribution)} point(s), capped at 5.`),
  ];
}

function exposureFactors(input: ContextualRiskInput): ScoreFactor[] {
  const scope = input.runtimeScope ?? "unknown";
  const reachability = input.reachability ?? "unknown";
  const exposed = input.internetExposure ?? "unknown";
  const functionUsed = input.vulnerableFunctionUsed ?? null;
  const parents = normalizeCount(input.parentCount ?? inferParentCount(input.dependency));
  const paths = normalizeCount(input.pathCount ?? input.dependency.paths?.length ?? null);
  const reachContribution = reachability === "reachable" ? 30 : reachability === "possibly-reachable" ? 15 : 0;
  const exposureContribution = exposed === "internet" ? 30 : exposed === "internal" ? 10 : 0;
  const scopeContribution = scope === "runtime" ? 10 : scope === "optional" ? 7 : 0;
  const parentContribution = parents === null ? 0 : Math.min(5, parents * 1.25);
  const pathContribution = paths === null ? 0 : Math.min(5, paths * 1.25);
  return [
    factor("exposure.reachability", "Reachability exposure", reachability, reachContribution,
      reachability === "reachable" ? "A reachable path contributes 30 exposure points." : reachability === "possibly-reachable" ? "A possible path contributes 15 exposure points." : reachability === "not-observed" ? "No path was observed; no exposure points were added and safety is not implied." : "Unknown reachability is neutral."),
    factor("exposure.function", "Vulnerable API usage", functionUsed, functionUsed === true ? 20 : 0,
      functionUsed === true ? "Observed vulnerable API usage contributes 20 points." : functionUsed === false ? "No vulnerable API reference was observed; no points were added." : "Function usage is unknown and neutral."),
    factor("exposure.route", "Route exposure", exposed, exposureContribution,
      exposed === "internet" ? "An associated internet-facing route contributes 30 points." : exposed === "internal" ? "An internal route/service contributes 10 points." : exposed === "not-observed" ? "No exposed route was observed; no points were added." : "Route exposure is unknown and neutral."),
    factor("exposure.scope", "Runtime presence", scope, scopeContribution,
      scope === "runtime" ? "Runtime presence contributes 10 points." : scope === "optional" ? "Optional runtime presence contributes 7 points." : scope === "dev" ? "Dev-only presence adds no runtime exposure points." : "Unknown scope is neutral."),
    factor("exposure.parents", "Parent dependency count", parents, parentContribution,
      parents === null ? "Parent count is unknown and neutral." : `${parents} parent package(s) contribute ${round(parentContribution)} point(s), capped at 5.`),
    factor("exposure.paths", "Dependency path count", paths, pathContribution,
      paths === null ? "Path count is unknown and neutral." : `${paths} observed dependency path(s) contribute ${round(pathContribution)} point(s), capped at 5.`),
  ];
}

function remediationFactors(input: ContextualRiskInput, complexity: UpgradeComplexity): ScoreFactor[] {
  const parents = normalizeCount(input.parentCount ?? inferParentCount(input.dependency));
  const apiCount = normalizeCount(input.importedApiCount);
  const conflict = input.dependencyConflict ?? null;
  const breakingProbability = normalizeProbability(input.breakingChangeProbability);
  const base: Record<UpgradeComplexity, number> = {
    patch: 15,
    minor: 35,
    major: 70,
    "update-parent": 55,
    "manual-review": 65,
    "no-fix": 100,
    unknown: 50,
  };
  const parentContribution = parents === null ? 0 : Math.min(10, parents * 2);
  const apiContribution = apiCount === null ? 0 : Math.min(10, apiCount * 2);
  const conflictContribution = conflict === true ? 15 : 0;
  const breakingContribution = breakingProbability === null ? 0 : breakingProbability * 20;
  return [
    factor("remediation.upgrade", "Upgrade class", complexity, base[complexity],
      complexity === "unknown" ? "Upgrade class is unknown; the neutral midpoint of 50 is used." : `${complexity.replaceAll("-", " ")} contributes a base difficulty of ${base[complexity]}.`, [], complexity === "unknown" ? "neutral" : "increase"),
    factor("remediation.parents", "Parent packages", parents, parentContribution,
      parents === null ? "Parent count is unknown and adds no adjustment." : `${parents} parent package(s) add ${round(parentContribution)} difficulty point(s), capped at 10.`),
    factor("remediation.api-count", "Imported APIs", apiCount, apiContribution,
      apiCount === null ? "Imported API count is unknown and adds no adjustment." : `${apiCount} imported API(s) add ${round(apiContribution)} difficulty point(s), capped at 10.`),
    factor("remediation.conflict", "Dependency conflict", conflict, conflictContribution,
      conflict === true ? "A detected dependency conflict adds 15 difficulty points." : conflict === false ? "No dependency conflict was detected; no points were added." : "Conflict evidence is unknown and neutral."),
    factor("remediation.breaking", "Estimated breaking-change probability", breakingProbability, breakingContribution,
      breakingProbability === null ? "Breaking-change probability is unknown and neutral." : `${Math.round(breakingProbability * 100)}% estimated probability adds ${round(breakingContribution)} difficulty point(s).`),
  ];
}

function confidenceFactors(input: ContextualRiskInput, fixStatus: FixStatus): ScoreFactor[] {
  const vulnerabilities = input.dependency.vulnerabilities;
  const cvss = cvssEvidence(vulnerabilities);
  const versionKnown = input.exactVersionKnown ?? Boolean(input.dependency.version && input.dependency.version !== "unknown" && !/[<>=*xX]/.test(input.dependency.version));
  const pathKnown = input.dependencyPathKnown ?? Boolean(input.dependency.paths?.length || input.dependency.path);
  const reachability = input.reachability ?? "unknown";
  const exploit = input.exploitEvidence ?? "unknown";
  const sources = new Set(vulnerabilities.flatMap(item => item.sources ?? (item.source ? [item.source] : [])));
  const sourcesAgree = input.sourceAgreement ?? (sources.size >= 2 ? true : null);
  const fixKnown = fixStatus !== "unknown";
  return [
    factor("confidence.cvss", "Reported CVSS", cvss.reported, cvss.reported ? 15 : 0,
      cvss.reported ? "Reported CVSS evidence contributes 15 confidence points." : "CVSS is missing or estimated, so no CVSS confidence points were added.", cvss.evidence, "confidence"),
    factor("confidence.version", "Exact installed version", versionKnown, versionKnown ? 15 : 0,
      versionKnown ? "An exact installed version contributes 15 confidence points." : "The installed version is unknown or non-exact.", [], "confidence"),
    factor("confidence.path", "Dependency path", pathKnown, pathKnown ? 15 : 0,
      pathKnown ? "A known dependency path contributes 15 confidence points." : "The dependency path is unavailable.", [], "confidence"),
    factor("confidence.reachability", "Reachability assessment", reachability, reachability !== "unknown" ? 20 : 0,
      reachability !== "unknown" ? `A ${reachability} reachability assessment contributes 20 confidence points.` : "Reachability was not assessed.", [], "confidence"),
    factor("confidence.fix", "Fix status established", fixStatus, fixKnown ? 10 : 0,
      fixKnown ? `Fix status '${fixStatus}' contributes 10 confidence points.` : "Fix status is unknown.", [], "confidence"),
    factor("confidence.exploit", "Exploit evidence assessed", exploit, exploit !== "unknown" ? 10 : 0,
      exploit !== "unknown" ? `Exploit evidence status '${exploit}' contributes 10 confidence points.` : "Exploit evidence was not assessed.", [], "confidence"),
    factor("confidence.sources", "Source agreement", sourcesAgree, sourcesAgree === true ? 15 : 0,
      sourcesAgree === true ? `${sources.size} source(s) provide agreeing identifiers and contribute 15 confidence points.` : sourcesAgree === false ? "Vulnerability sources disagree, so no source-agreement points were added." : "Fewer than two agreeing sources are available.", [...sources], "confidence"),
  ];
}

function finalPriorityFactors(
  technical: ScoreBreakdown,
  exploitability: ScoreBreakdown,
  exposure: ScoreBreakdown,
  remediation: ScoreBreakdown,
): ScoreFactor[] {
  const difficultyAdjustment = (50 - remediation.score) * 0.1;
  return [
    factor("priority.technical", "Technical risk (45%)", technical.score, technical.score * 0.45,
      `Technical risk ${technical.score}/100 contributes ${round(technical.score * 0.45)} points.`),
    factor("priority.exploitability", "Exploitability (30%)", exploitability.score, exploitability.score * 0.3,
      `Exploitability ${exploitability.score}/100 contributes ${round(exploitability.score * 0.3)} points.`),
    factor("priority.exposure", "Exposure (25%)", exposure.score, exposure.score * 0.25,
      `Exposure ${exposure.score}/100 contributes ${round(exposure.score * 0.25)} points.`),
    factor("priority.actionability", "Remediation actionability adjustment", remediation.score, difficultyAdjustment,
      `Difficulty ${remediation.score}/100 applies a ${difficultyAdjustment >= 0 ? "+" : ""}${round(difficultyAdjustment)} point adjustment around the neutral midpoint of 50.`),
  ];
}

/**
 * Calculates DepShield contextual scores. These are deterministic DepShield
 * model outputs, not industry-standard risk scores. Unknown evidence is
 * neutral in risk calculations and lowers confidence instead.
 */
export function calculateContextualRisk(input: ContextualRiskInput): ContextualRiskAssessment {
  const hasFindings = input.dependency.vulnerabilities.length > 0;
  const fixStatus = input.fixStatus ?? inferFixStatus(input.dependency);
  const complexity = input.upgradeComplexity ?? inferUpgradeComplexity(input.dependency, fixStatus);
  const confidenceValues = confidenceFactors(input, fixStatus);
  const confidenceBase = breakdown(confidenceValues);
  const confidence: ConfidenceBreakdown = {
    ...confidenceBase,
    band: confidenceBase.score >= 80 ? "high" : confidenceBase.score >= 50 ? "medium" : "low",
  };

  if (!hasFindings) {
    const noFindings = breakdown([
      factor("context.no-findings", "Known findings", 0, 0, "No vulnerability findings are present, so contextual risk is zero."),
    ]);
    return {
      modelVersion: CONTEXTUAL_RISK_MODEL_VERSION,
      technicalRisk: noFindings,
      exploitabilityScore: noFindings,
      exposureScore: noFindings,
      remediationDifficulty: noFindings,
      finalPriority: noFindings,
      confidence,
    };
  }

  const technicalRisk = breakdown(technicalFactors(input, fixStatus));
  const exploitabilityScore = breakdown(exploitabilityFactors(input));
  const exposureScore = breakdown(exposureFactors(input));
  const remediationDifficulty = breakdown(remediationFactors(input, complexity));
  const finalPriority = breakdown(finalPriorityFactors(technicalRisk, exploitabilityScore, exposureScore, remediationDifficulty));

  return {
    modelVersion: CONTEXTUAL_RISK_MODEL_VERSION,
    technicalRisk,
    exploitabilityScore,
    exposureScore,
    remediationDifficulty,
    finalPriority,
    confidence,
  };
}

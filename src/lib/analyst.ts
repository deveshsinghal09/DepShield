import type { AnalystAnswer, AnalystCitation, Dependency, Scan, Vulnerability } from "./types";
import { createSecurityDiff } from "./security-diff";
import { compareExactVersions } from "./semver";

export const ANALYST_UNSUPPORTED_ANSWER = "Not enough evidence in the current scan.";
export const ANALYST_GUARDRAIL_ANSWER = "DepShield Analyst cannot generate exploits, target external systems, or provide arbitrary shell commands. It can only explain safe evidence from the selected scan.";

export type AnalystIntent =
  | "why-ranked"
  | "fix-first"
  | "fix-explanation"
  | "transitive-path"
  | "cve-explanation"
  | "scan-change"
  | "internet-facing"
  | "sprint-plan"
  | "dependency-path"
  | "unsupported"
  | "unsafe";

export type AnalystEvidenceValue = string | number | boolean | null | string[];

export type AnalystEvidenceItem = {
  id: string;
  kind: "scan" | "dependency" | "finding" | "path" | "comparison";
  citation: AnalystCitation;
  facts: Record<string, AnalystEvidenceValue>;
};

export type AnalystEvidenceBundle = {
  scanId: string;
  project: string;
  items: AnalystEvidenceItem[];
  allowedCitations: AnalystCitation[];
};

export type AnalystQuestionOptions = {
  history?: Scan[];
  comparisonScan?: Scan | null;
};

const unsafePatterns = [
  /\b(?:generate|write|build|create|provide|give me|show me)\b.{0,60}\b(?:exploit|payload|reverse shell|malware|ransomware|weaponize)\b/is,
  /\b(?:attack|exploit|scan)\b.{0,60}\b(?:https?:\/\/|external target|remote host|public ip|production server)\b/is,
  /\b(?:arbitrary shell|shell command|reverse shell|powershell\s+-enc|cmd\.exe|rm\s+-rf)\b/is,
  /\b(?:bypass|evade)\b.{0,40}\b(?:security|detection|authentication|authorization)\b/is,
];

function canonicalId(vulnerability: Vulnerability) {
  return (vulnerability.cveAlias
    ?? vulnerability.aliases?.find(value => value.toUpperCase().startsWith("CVE-"))
    ?? vulnerability.aliases?.find(value => value.toUpperCase().startsWith("GHSA-"))
    ?? vulnerability.id).toUpperCase();
}

function priority(dependency: Dependency) {
  return dependency.propagation?.contextualRisk ?? dependency.contextual?.finalPriority ?? dependency.risk;
}

function confidence(dependency: Dependency) {
  return dependency.contextual?.confidence ?? dependency.reachability?.confidence ?? null;
}

function rankedDependencies(scan: Scan) {
  return scan.items
    .filter(item => item.vulnerabilities.length > 0)
    .toSorted((left, right) => priority(right) - priority(left) || right.risk - left.risk || left.name.localeCompare(right.name));
}

function highestVulnerability(dependency: Dependency) {
  return dependency.vulnerabilities.toSorted((left, right) => right.cvss - left.cvss || canonicalId(left).localeCompare(canonicalId(right)))[0];
}

function citation(label: string, value: string): AnalystCitation {
  return { label, value };
}

export function analystCitationTag(value: AnalystCitation) {
  return `[${value.label}: ${value.value.replaceAll("]", "")}]`;
}

function uniqueCitations(values: AnalystCitation[]) {
  return [...new Map(values.map(value => [`${value.label}\0${value.value}`, value])).values()];
}

function supportedAnswer(answer: string, citations: AnalystCitation[], provider: AnalystAnswer["provider"] = "deterministic"): AnalystAnswer {
  return { answer, citations: uniqueCitations(citations), supported: true, provider };
}

function unsupportedAnswer(answer = ANALYST_UNSUPPORTED_ANSWER): AnalystAnswer {
  return { answer, citations: [], supported: false, provider: "deterministic" };
}

function scanCitation(scan: Scan) {
  return citation("Scan", `#${scan.id}`);
}

function dependencyCitation(dependency: Dependency) {
  return citation("Dependency", `${dependency.name}@${dependency.version}`);
}

function vulnerabilityCitation(vulnerability: Vulnerability) {
  return citation("CVE", canonicalId(vulnerability));
}

function pathCitation(path: string) {
  return citation("Path", path);
}

function mentionedDependency(question: string, scan: Scan) {
  const normalized = question.toLowerCase();
  return scan.items
    .toSorted((left, right) => right.name.length - left.name.length)
    .find(item => normalized.includes(item.name.toLowerCase()));
}

function mentionedCve(question: string) {
  return question.match(/\b(?:CVE-\d{4}-\d+|GHSA-[\w-]+)\b/i)?.[0]?.toUpperCase() ?? null;
}

function findCve(scan: Scan, id: string) {
  for (const dependency of scan.items) {
    const vulnerability = dependency.vulnerabilities.find(item =>
      [item.id, item.cveAlias, ...(item.aliases ?? [])].filter(Boolean).some(value => String(value).toUpperCase() === id));
    if (vulnerability) return { dependency, vulnerability };
  }
  return null;
}

export function isUnsafeAnalystRequest(question: string) {
  return unsafePatterns.some(pattern => pattern.test(question));
}

export function detectAnalystIntent(question: string): AnalystIntent {
  const normalized = question.trim().toLowerCase();
  if (isUnsafeAnalystRequest(normalized)) return "unsafe";
  if (/\b(?:what changed|difference|compare|comparison|before.*after|between scans?)\b/.test(normalized)) return "scan-change";
  if (mentionedCve(normalized) || /\bexplain\s+(?:this\s+)?cve\b/.test(normalized)) return "cve-explanation";
  if (/\b(?:transitive|introduc(?:e|es|ed)|parent package|parent dependency)\b/.test(normalized)) return "transitive-path";
  if (/\b(?:why).*(?:rank|first|top)|\branked\s+(?:first|highest)\b/.test(normalized)) return "why-ranked";
  if (/\b(?:explain\s+(?:this\s+)?fix|why\s+(?:should|do)\b.{0,40}\bupgrade|what\b.{0,40}\bbreak\b.{0,40}\bupgrade|what\b.{0,40}\btest\b.{0,40}\bupgrade)\b/.test(normalized)) return "fix-explanation";
  if (/\b(?:fix first|fix next|prioriti[sz]e|highest priority|which vulnerability should)\b/.test(normalized)) return "fix-first";
  if (/\b(?:internet-facing|public route|exposed route|public endpoint)\b/.test(normalized)) return "internet-facing";
  if (/\b(?:next sprint|sprint plan|remediation plan|upgrade plan)\b/.test(normalized)) return "sprint-plan";
  if (/\b(?:dependency path|explain.*path|where.*(?:enter|come from)|how.*introduced)\b/.test(normalized)) return "dependency-path";
  return "unsupported";
}

function whyRanked(scan: Scan, question: string): AnalystAnswer {
  const ranked = rankedDependencies(scan);
  if (!ranked.length) return unsupportedAnswer();
  const leader = ranked[0];
  const requested = mentionedDependency(question, scan);
  const target = requested ?? leader;
  const vulnerability = highestVulnerability(target);
  if (!vulnerability) return unsupportedAnswer();
  const targetCitation = dependencyCitation(target);
  const cveCitation = vulnerabilityCitation(vulnerability);
  const evidence: string[] = [];
  if (target.contextual?.factors.length) {
    evidence.push(...target.contextual.factors
      .filter(item => item.contribution !== 0)
      .toSorted((left, right) => Math.abs(right.contribution) - Math.abs(left.contribution))
      .slice(0, 4)
      .map(item => `${item.contribution > 0 ? "+" : ""}${item.contribution} ${item.label.toLowerCase()}`));
  } else {
    evidence.push(`CVSS ${vulnerability.cvssAvailable === false ? "unavailable" : vulnerability.cvss.toFixed(1)}`);
    evidence.push(target.direct ? "direct dependency" : "transitive dependency");
    evidence.push(target.recommendation === "upgrade" ? "complete fix available" : target.recommendation === "no-fix" ? "no complete fix" : `${target.vulnerabilities.length} finding(s)`);
  }
  const rankStatement = target === leader
    ? `${target.name} is ranked first at priority ${priority(target)}/100`
    : `${target.name} is not ranked first; ${leader.name}@${leader.version} currently leads at ${priority(leader)}/100`;
  const confidenceText = confidence(target) === null ? "confidence is not available" : `confidence is ${confidence(target)}%`;
  const citations = [targetCitation, cveCitation, scanCitation(scan), ...(target === leader ? [] : [dependencyCitation(leader)])];
  return supportedAnswer(
    `${rankStatement}, and ${confidenceText}. The strongest recorded reasons are: ${evidence.join("; ")}. ${analystCitationTag(targetCitation)} ${analystCitationTag(cveCitation)} ${analystCitationTag(scanCitation(scan))}`,
    citations,
  );
}

function fixFirst(scan: Scan): AnalystAnswer {
  const candidates = rankedDependencies(scan).filter(item =>
    item.recommendation === "upgrade" || item.vulnerabilities.some(vulnerability => Boolean(vulnerability.fixedVersion)));
  const target = candidates[0];
  if (!target) return unsupportedAnswer();
  const vulnerability = target.vulnerabilities
    .filter(item => Boolean(item.fixedVersion))
    .toSorted((left, right) => right.cvss - left.cvss)[0] ?? highestVulnerability(target);
  if (!vulnerability) return unsupportedAnswer();
  const dependencyRef = dependencyCitation(target);
  const cveRef = vulnerabilityCitation(vulnerability);
  const scanRef = scanCitation(scan);
  const targetVersion = target.latest && target.latest !== target.version ? target.latest : vulnerability.fixedVersion;
  const reachability = target.reachability?.status ?? "UNKNOWN";
  const compatibility = target.compatibility?.level ?? "UNKNOWN";
  return supportedAnswer(
    `Fix ${target.name}@${target.version} first by reviewing an upgrade to ${targetVersion ?? "a vendor-reported fixed release"}. It has priority ${priority(target)}/100, ${vulnerability.severity} severity, reachability ${reachability}, and estimated compatibility risk ${compatibility}. This is a recommendation, not an automatic package change. ${analystCitationTag(dependencyRef)} ${analystCitationTag(cveRef)} ${analystCitationTag(scanRef)}`,
    [dependencyRef, cveRef, scanRef],
  );
}

function explainFix(scan: Scan, question: string): AnalystAnswer {
  const target = mentionedDependency(question, scan);
  if (!target || !target.vulnerabilities.length) return unsupportedAnswer();
  const highest = highestVulnerability(target);
  if (!highest) return unsupportedAnswer();
  const targetVersion = target.compatibility?.targetVersion
    ?? (target.latest && target.latest !== target.version ? target.latest : undefined)
    ?? target.vulnerabilities.find(item => item.fixedVersion)?.fixedVersion;
  const removed = targetVersion
    ? target.vulnerabilities.filter(item => {
        if (!item.fixedVersion) return false;
        const comparison = compareExactVersions(targetVersion, item.fixedVersion);
        return comparison !== null && comparison >= 0;
      })
    : [];
  const dependencyRef = dependencyCitation(target);
  const scanRef = scanCitation(scan);
  const cveRefs = (removed.length ? removed : [highest]).slice(0, 5).map(vulnerabilityCitation);
  const removal = targetVersion
    ? removed.length
      ? `${removed.length} recorded finding(s) have exact reported fixes at or below ${targetVersion}: ${removed.map(canonicalId).join(", ")}.`
      : `The scan does not support claiming that any finding disappears at ${targetVersion}.`
    : "No exact complete target is recorded, so the scan does not support claiming that a finding disappears.";
  const action = targetVersion
    ? `Review ${target.name} ${target.version} → ${targetVersion}; this target comes from persisted advisory evidence and still requires an actual install, test, and rescan.`
    : target.direct
      ? "Use manual review because no exact complete fixed target is recorded."
      : `Update the introducing parent ${target.parentPackages?.join(", ") || "dependency"}; do not pin the transitive child in isolation without resolver evidence.`;
  const compatibility = target.compatibility
    ? `Estimated compatibility risk is ${target.compatibility.level}: ${target.compatibility.reasons.join("; ") || "no detailed reason was recorded"}.`
    : "Estimated compatibility risk is UNKNOWN because this scan has insufficient upgrade-impact evidence.";
  const tests = target.compatibility?.suggestedTests.length
    ? target.compatibility.suggestedTests.join("; ")
    : `exercise imported ${target.name} APIs and affected routes, run the existing test suite, then rescan`;
  return supportedAnswer(
    `${action} Why: priority ${priority(target)}/100, highest recorded severity ${highest.severity}, and reachability ${target.reachability?.status ?? "UNKNOWN"}. ${removal} ${compatibility} What to test: ${tests}. ${analystCitationTag(dependencyRef)} ${cveRefs.map(analystCitationTag).join(" ")} ${analystCitationTag(scanRef)}`,
    [dependencyRef, ...cveRefs, scanRef],
  );
}

function transitivePath(scan: Scan, question: string): AnalystAnswer {
  const requested = mentionedDependency(question, scan);
  const target = requested ?? rankedDependencies(scan).find(item => !item.direct);
  if (!target || target.direct) return unsupportedAnswer();
  const path = target.reachability?.paths[0]?.display ?? target.paths?.[0]?.display ?? target.path;
  if (!path) return unsupportedAnswer();
  const nodes = target.reachability?.paths[0]?.nodes ?? target.paths?.[0]?.nodes ?? path.split("→").map(value => value.trim());
  const parent = nodes.at(-2) ?? target.parentPackages?.[0] ?? "an unresolved parent";
  const dependencyRef = dependencyCitation(target);
  const pathRef = pathCitation(path);
  return supportedAnswer(
    `${target.name}@${target.version} is transitive. Its nearest observed parent is ${parent}; the complete recorded chain is ${path}. Static path evidence describes dependency introduction and does not by itself prove vulnerable code execution. ${analystCitationTag(dependencyRef)} ${analystCitationTag(pathRef)}`,
    [dependencyRef, pathRef, scanCitation(scan)],
  );
}

function explainCve(scan: Scan, question: string): AnalystAnswer {
  const requestedId = mentionedCve(question);
  const requestedDependency = mentionedDependency(question, scan);
  const match = requestedId
    ? findCve(scan, requestedId)
    : requestedDependency && highestVulnerability(requestedDependency)
      ? { dependency: requestedDependency, vulnerability: highestVulnerability(requestedDependency)! }
      : null;
  if (!match) return unsupportedAnswer();
  const { dependency, vulnerability } = match;
  const dependencyRef = dependencyCitation(dependency);
  const cveRef = vulnerabilityCitation(vulnerability);
  const score = vulnerability.cvssAvailable === false ? "CVSS is unavailable" : `CVSS is ${vulnerability.cvss.toFixed(1)}`;
  const fix = vulnerability.fixedVersion ? `The recorded fixed version is ${vulnerability.fixedVersion}.` : "No fixed version is recorded in this scan.";
  const reachability = dependency.reachability
    ? `Static reachability is ${dependency.reachability.status}; this is evidence, not proof of exploitability.`
    : "Application reachability was not established in this scan.";
  return supportedAnswer(
    `${canonicalId(vulnerability)} affects ${dependency.name}@${dependency.version}. In simple terms: ${vulnerability.summary} ${score} (${vulnerability.severity}). ${fix} ${reachability} ${analystCitationTag(cveRef)} ${analystCitationTag(dependencyRef)}`,
    [cveRef, dependencyRef, scanCitation(scan)],
  );
}

function selectComparison(scan: Scan, question: string, options: AnalystQuestionOptions) {
  if (options.comparisonScan && options.comparisonScan.id !== scan.id) return options.comparisonScan;
  const history = options.history ?? [];
  const explicit = history.find(item => item.id !== scan.id && (question.includes(item.id) || question.includes(`#${item.id}`)));
  if (explicit) return explicit;
  return history
    .filter(item => item.id !== scan.id && item.project === scan.project && new Date(item.createdAt).getTime() < new Date(scan.createdAt).getTime())
    .toSorted((left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime())[0] ?? null;
}

function explainChange(scan: Scan, question: string, options: AnalystQuestionOptions): AnalystAnswer {
  const comparison = selectComparison(scan, question, options);
  if (!comparison) return unsupportedAnswer();
  const before = new Date(comparison.createdAt) <= new Date(scan.createdAt) ? comparison : scan;
  const after = before === comparison ? scan : comparison;
  const diff = createSecurityDiff(before, after);
  const beforeRef = scanCitation(before);
  const afterRef = scanCitation(after);
  const removed = diff.findings.removed.slice(0, 4).map(item => item.vulnerabilityId);
  const introduced = diff.findings.introduced.slice(0, 4).map(item => item.vulnerabilityId);
  const upgrades = diff.dependencies.upgraded.slice(0, 4).map(item => `${item.name} ${item.beforeVersion} → ${item.afterVersion}`);
  const details = [
    `${diff.findings.removed.length} finding(s) removed${removed.length ? ` (${removed.join(", ")})` : ""}`,
    `${diff.findings.introduced.length} introduced${introduced.length ? ` (${introduced.join(", ")})` : ""}`,
    `${diff.findings.changed.length} changed`,
    `${diff.dependencies.upgraded.length} dependency upgrade(s)${upgrades.length ? ` (${upgrades.join(", ")})` : ""}`,
    `${diff.attackPaths.removed.length} attack path(s) removed and ${diff.attackPaths.introduced.length} added`,
  ];
  return supportedAnswer(
    `Security score changed ${diff.metrics.scoreBefore} → ${diff.metrics.scoreAfter} (${diff.metrics.scoreChange >= 0 ? "+" : ""}${diff.metrics.scoreChange}). ${details.join("; ")}. ${analystCitationTag(beforeRef)} ${analystCitationTag(afterRef)}`,
    [beforeRef, afterRef, ...diff.findings.removed.slice(0, 2).map(item => citation("CVE", item.vulnerabilityId)), ...diff.findings.introduced.slice(0, 2).map(item => citation("CVE", item.vulnerabilityId))],
  );
}

function internetFacing(scan: Scan): AnalystAnswer {
  const exposed = rankedDependencies(scan)
    .filter(item => item.reachability?.internetExposed)
    .toSorted((left, right) => {
      const leftReachable = left.reachability?.status === "REACHABLE" ? 1 : 0;
      const rightReachable = right.reachability?.status === "REACHABLE" ? 1 : 0;
      return rightReachable - leftReachable || priority(right) - priority(left);
    });
  const target = exposed[0];
  if (!target) return unsupportedAnswer();
  const vulnerability = highestVulnerability(target);
  if (!vulnerability) return unsupportedAnswer();
  const route = target.blastRadius?.routes[0] ?? target.reachability?.entryFiles[0] ?? "an observed internet-facing entry point";
  const dependencyRef = dependencyCitation(target);
  const cveRef = vulnerabilityCitation(vulnerability);
  const path = target.reachability?.paths[0]?.display;
  const pathRef = path ? pathCitation(path) : null;
  return supportedAnswer(
    `${target.name}@${target.version} is the highest-priority dependency associated with internet-facing evidence. The observed entry is ${route}, reachability is ${target.reachability?.status}, and priority is ${priority(target)}/100. This is an exposure estimate, not proof of exploitation. ${analystCitationTag(dependencyRef)} ${analystCitationTag(cveRef)}${pathRef ? ` ${analystCitationTag(pathRef)}` : ""}`,
    [dependencyRef, cveRef, scanCitation(scan), ...(pathRef ? [pathRef] : [])],
  );
}

function sprintPlan(scan: Scan): AnalystAnswer {
  const actions = rankedDependencies(scan)
    .filter(item => item.recommendation === "upgrade" || item.recommendation === "partial-fix")
    .toSorted((left, right) => {
      const leftDifficulty = left.contextual?.remediationDifficulty ?? 50;
      const rightDifficulty = right.contextual?.remediationDifficulty ?? 50;
      return (priority(right) - rightDifficulty * 0.15) - (priority(left) - leftDifficulty * 0.15) || left.name.localeCompare(right.name);
    })
    .slice(0, 3);
  if (!actions.length) return unsupportedAnswer();
  const citations: AnalystCitation[] = [scanCitation(scan)];
  const steps = actions.map((item, index) => {
    const ref = dependencyCitation(item);
    citations.push(ref);
    const target = item.latest && item.latest !== item.version ? item.latest : "a reported fixed version";
    const difficulty = item.contextual?.remediationDifficulty ?? "unknown";
    return `${index + 1}. ${item.name} ${item.version} → ${target} (priority ${priority(item)}, estimated difficulty ${difficulty}) ${analystCitationTag(ref)}`;
  });
  return supportedAnswer(
    `Suggested next-sprint remediation order: ${steps.join(" ")} Validate affected routes and imported APIs after each change, then rescan before merging. ${analystCitationTag(scanCitation(scan))}`,
    citations,
  );
}

function explainPath(scan: Scan, question: string): AnalystAnswer {
  const target = mentionedDependency(question, scan) ?? rankedDependencies(scan)[0];
  if (!target) return unsupportedAnswer();
  const path = target.reachability?.paths[0]?.display ?? target.paths?.[0]?.display ?? target.path;
  if (!path) return unsupportedAnswer();
  const dependencyRef = dependencyCitation(target);
  const pathRef = pathCitation(path);
  const status = target.reachability?.status ?? "UNKNOWN";
  const limitation = status === "NOT_OBSERVED"
    ? "No static path was observed, but that does not establish safety."
    : status === "UNKNOWN"
      ? "Source evidence was insufficient to establish application reachability."
      : `The package-level path is classified ${status}; function execution is not guaranteed.`;
  return supportedAnswer(
    `The recorded path to ${target.name}@${target.version} is ${path}. ${limitation} ${analystCitationTag(dependencyRef)} ${analystCitationTag(pathRef)}`,
    [dependencyRef, pathRef, scanCitation(scan)],
  );
}

/** Deterministic, intent-aware answer generated exclusively from persisted scan fields. */
export function answerScanQuestion(scan: Scan, question: string, options: AnalystQuestionOptions = {}): AnalystAnswer {
  const trimmed = question.trim();
  if (!trimmed) return unsupportedAnswer();
  const intent = detectAnalystIntent(trimmed);
  switch (intent) {
    case "unsafe": return unsupportedAnswer(ANALYST_GUARDRAIL_ANSWER);
    case "why-ranked": return whyRanked(scan, trimmed);
    case "fix-first": return fixFirst(scan);
    case "fix-explanation": return explainFix(scan, trimmed);
    case "transitive-path": return transitivePath(scan, trimmed);
    case "cve-explanation": return explainCve(scan, trimmed);
    case "scan-change": return explainChange(scan, trimmed, options);
    case "internet-facing": return internetFacing(scan);
    case "sprint-plan": return sprintPlan(scan);
    case "dependency-path": return explainPath(scan, trimmed);
    default: return unsupportedAnswer();
  }
}

function selectedDependencies(scan: Scan, question: string) {
  const mentioned = mentionedDependency(question, scan);
  const values = [
    ...(mentioned ? [mentioned] : []),
    ...rankedDependencies(scan).slice(0, 15),
  ];
  return [...new Map(values.map(item => [`${item.name}@${item.version}|${item.path}`, item])).values()].slice(0, 20);
}

/**
 * Builds the only payload allowed to leave the application for an optional AI
 * provider. It contains normalized facts and file/path names, never source code.
 */
export function buildAnalystEvidence(scan: Scan, question: string, options: AnalystQuestionOptions = {}): AnalystEvidenceBundle {
  const items: AnalystEvidenceItem[] = [];
  const currentScanRef = scanCitation(scan);
  items.push({
    id: `scan:${scan.id}`,
    kind: "scan",
    citation: currentScanRef,
    facts: {
      project: scan.project,
      createdAt: scan.createdAt,
      score: scan.score,
      grade: scan.grade,
      contextualRisk: scan.contextualRisk ?? null,
      confidence: scan.confidence ?? null,
      dependencies: scan.dependencies,
      vulnerableDependencies: scan.vulnerable,
      criticalDependencies: scan.critical,
      reachableCritical: scan.reachableCritical ?? null,
      sourceFilesAnalyzed: scan.sourceFilesAnalyzed ?? 0,
    },
  });

  for (const [index, dependency] of selectedDependencies(scan, question).entries()) {
    const dependencyRef = dependencyCitation(dependency);
    items.push({
      id: `dependency:${index}`,
      kind: "dependency",
      citation: dependencyRef,
      facts: {
        name: dependency.name,
        version: dependency.version,
        direct: dependency.direct,
        runtime: dependency.runtime ?? null,
        devOnly: dependency.devOnly ?? null,
        depth: dependency.depth ?? null,
        parentCount: dependency.parentCount ?? null,
        risk: dependency.risk,
        finalPriority: dependency.contextual?.finalPriority ?? null,
        technicalRisk: dependency.contextual?.technical ?? null,
        exploitability: dependency.contextual?.exploitability ?? null,
        exposure: dependency.contextual?.exposure ?? null,
        remediationDifficulty: dependency.contextual?.remediationDifficulty ?? null,
        confidence: dependency.contextual?.confidence ?? null,
        recommendation: dependency.recommendation ?? "none",
        targetVersion: dependency.latest,
        reachability: dependency.reachability?.status ?? "UNKNOWN",
        internetExposed: dependency.reachability?.internetExposed ?? false,
        observedFunctions: dependency.reachability?.observedFunctions ?? [],
        affectedRoutes: dependency.blastRadius?.routes ?? [],
        compatibilityRisk: dependency.compatibility?.level ?? "UNKNOWN",
      },
    });
    for (const [findingIndex, vulnerability] of dependency.vulnerabilities.slice(0, 10).entries()) {
      items.push({
        id: `finding:${index}:${findingIndex}`,
        kind: "finding",
        citation: vulnerabilityCitation(vulnerability),
        facts: {
          dependency: `${dependency.name}@${dependency.version}`,
          id: canonicalId(vulnerability),
          summary: vulnerability.summary,
          severity: vulnerability.severity,
          cvss: vulnerability.cvssAvailable === false ? null : vulnerability.cvss,
          affectedRange: vulnerability.vulnerableRange ?? null,
          fixedVersion: vulnerability.fixedVersion ?? null,
          sources: vulnerability.sources ?? (vulnerability.source ? [vulnerability.source] : []),
          knownExploit: vulnerability.knownExploit ?? null,
        },
      });
    }
    for (const [pathIndex, path] of (dependency.reachability?.paths ?? dependency.paths ?? []).slice(0, 3).entries()) {
      const pathExposure = (path as { internetExposed?: unknown }).internetExposed;
      items.push({
        id: `path:${index}:${pathIndex}`,
        kind: "path",
        citation: pathCitation(path.display),
        facts: {
          dependency: `${dependency.name}@${dependency.version}`,
          path: path.display,
          nodes: path.nodes,
          reachability: dependency.reachability?.status ?? "UNKNOWN",
          internetExposed: typeof pathExposure === "boolean" ? pathExposure : dependency.reachability?.internetExposed ?? false,
        },
      });
    }
  }

  const comparison = selectComparison(scan, question, options);
  if (comparison) {
    const diff = createSecurityDiff(comparison, scan);
    items.push({
      id: `comparison:${comparison.id}:${scan.id}`,
      kind: "comparison",
      citation: scanCitation(comparison),
      facts: {
        comparedWith: `#${scan.id}`,
        scoreBefore: diff.metrics.scoreBefore,
        scoreAfter: diff.metrics.scoreAfter,
        findingsRemoved: diff.findings.removed.map(item => item.vulnerabilityId),
        findingsIntroduced: diff.findings.introduced.map(item => item.vulnerabilityId),
        dependenciesUpgraded: diff.dependencies.upgraded.map(item => `${item.name} ${item.beforeVersion} → ${item.afterVersion}`),
        attackPathsRemoved: diff.attackPaths.removed.length,
        attackPathsIntroduced: diff.attackPaths.introduced.length,
      },
    });
  }

  return {
    scanId: scan.id,
    project: scan.project,
    items,
    allowedCitations: uniqueCitations(items.map(item => item.citation)),
  };
}

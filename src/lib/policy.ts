import type { Scan, Vulnerability } from "./types";

export type PolicyStatus = "pass" | "warning" | "fail";
export type SecurityPolicy = {
  id: string;
  name: string;
  enabled: boolean;
  blockReachableCritical: boolean;
  minimumSecurityScore: number;
  maximumCriticalFindings: number;
  blockNoFixAtOrAboveCvss: number | null;
  maximumNewCriticalFindings: number | null;
  incompleteSourceAction: "warning" | "fail";
};

export type PolicyRuleResult = {
  id: string;
  label: string;
  status: PolicyStatus;
  reason: string;
  evidence: string[];
};

export type PolicyEvaluation = {
  policyId: string;
  policyName: string;
  scanId: string;
  status: PolicyStatus;
  exitCode: 0 | 1;
  summary: string;
  rules: PolicyRuleResult[];
};

export const DEFAULT_SECURITY_POLICY: Readonly<SecurityPolicy> = Object.freeze({
  id: "production-security-gate",
  name: "Production Security Gate",
  enabled: true,
  blockReachableCritical: true,
  minimumSecurityScore: 70,
  maximumCriticalFindings: 0,
  blockNoFixAtOrAboveCvss: 9,
  maximumNewCriticalFindings: 2,
  incompleteSourceAction: "warning",
});

function vulnerabilityId(vulnerability: Vulnerability) {
  return vulnerability.cveAlias ?? vulnerability.id;
}

function criticalKeys(scan: Scan) {
  return new Set(scan.items.flatMap(dependency => dependency.vulnerabilities
    .filter(vulnerability => vulnerability.severity === "critical")
    .map(vulnerability => `${dependency.name}:${vulnerabilityId(vulnerability)}`)));
}

function reachableCriticalKeys(scan: Scan) {
  return new Set(scan.items.flatMap(dependency => dependency.reachability?.status === "REACHABLE"
    ? dependency.vulnerabilities
      .filter(vulnerability => vulnerability.severity === "critical")
      .map(vulnerability => `${dependency.name}:${vulnerabilityId(vulnerability)}`)
    : []));
}

function aggregateStatus(rules: PolicyRuleResult[]): PolicyStatus {
  if (rules.some(rule => rule.status === "fail")) return "fail";
  if (rules.some(rule => rule.status === "warning")) return "warning";
  return "pass";
}

export function evaluateSecurityPolicy(scan: Scan, policy: SecurityPolicy = DEFAULT_SECURITY_POLICY, previousScan?: Scan): PolicyEvaluation {
  if (!policy.enabled) {
    return {
      policyId: policy.id,
      policyName: policy.name,
      scanId: scan.id,
      status: "warning",
      exitCode: 0,
      summary: "Policy evaluation is disabled.",
      rules: [{ id: "policy-disabled", label: "Policy enabled", status: "warning", reason: "This policy is disabled and did not evaluate the scan.", evidence: [] }],
    };
  }

  const rules: PolicyRuleResult[] = [];
  if (policy.blockReachableCritical !== false) {
    const reachableCritical = [...reachableCriticalKeys(scan)];
    const criticalPresent = criticalKeys(scan).size > 0;
    const reachabilityIncomplete = (scan.sourceFilesAnalyzed ?? 0) === 0
      || Boolean(scan.warnings?.some((warning) => warning.code === "REACHABILITY_INCOMPLETE" || warning.code === "REACHABILITY_DISABLED"))
      || scan.items.some((dependency) =>
        dependency.vulnerabilities.some((finding) => finding.severity === "critical")
        && (dependency.reachability?.status ?? "UNKNOWN") === "UNKNOWN");
    const status: PolicyStatus = reachableCritical.length
      ? "fail"
      : criticalPresent && reachabilityIncomplete
        ? "warning"
        : "pass";
    rules.push({
      id: "reachable-critical",
      label: "Reachable critical findings",
      status,
      reason: reachableCritical.length
        ? `${reachableCritical.length} critical finding${reachableCritical.length === 1 ? " is" : "s are"} reachable from the supplied source evidence.`
        : criticalPresent && reachabilityIncomplete
          ? "Critical findings exist, but reachability evidence is missing or incomplete; the reachable-critical rule cannot pass."
          : "No reachable critical finding was observed in the supplied evidence.",
      evidence: reachableCritical.map(value => `[Reachable finding: ${value}]`),
    });
  }

  const scorePasses = scan.score >= policy.minimumSecurityScore;
  rules.push({
    id: "minimum-security-score",
    label: "Minimum security score",
    status: scorePasses ? "pass" : "fail",
    reason: scorePasses ? `Security score ${scan.score} meets the minimum ${policy.minimumSecurityScore}.` : `Security score ${scan.score} is below the minimum ${policy.minimumSecurityScore}.`,
    evidence: [`[Scan: ${scan.id}]`, `[Security score: ${scan.score}]`],
  });

  const critical = [...criticalKeys(scan)];
  const criticalPasses = critical.length <= policy.maximumCriticalFindings;
  rules.push({
    id: "maximum-critical-findings",
    label: "Maximum critical findings",
    status: criticalPasses ? "pass" : "fail",
    reason: criticalPasses ? `${critical.length} critical finding${critical.length === 1 ? " is" : "s are"} within the allowed maximum.` : `${critical.length} critical findings exceed the allowed maximum of ${policy.maximumCriticalFindings}.`,
    evidence: critical.map(value => `[Finding: ${value}]`),
  });

  if (policy.blockNoFixAtOrAboveCvss !== null) {
    const noFix = scan.items.flatMap(dependency => dependency.vulnerabilities
      .filter(vulnerability => vulnerability.cvssAvailable !== false && vulnerability.cvss >= policy.blockNoFixAtOrAboveCvss! && !vulnerability.fixedVersion)
      .map(vulnerability => `${dependency.name}@${dependency.version}:${vulnerabilityId(vulnerability)}`));
    rules.push({
      id: "high-cvss-without-fix",
      label: "High-CVSS findings without a fix",
      status: noFix.length ? "fail" : "pass",
      reason: noFix.length ? `${noFix.length} finding${noFix.length === 1 ? " has" : "s have"} CVSS ${policy.blockNoFixAtOrAboveCvss}+ and no reported fixed version.` : `No finding with CVSS ${policy.blockNoFixAtOrAboveCvss}+ lacks a reported fixed version.`,
      evidence: noFix.map(value => `[Finding: ${value}]`),
    });
  }

  if (policy.maximumNewCriticalFindings !== null) {
    if (!previousScan) {
      rules.push({ id: "new-critical-findings", label: "New critical findings", status: "warning", reason: "No baseline scan was provided, so critical regressions were not evaluated.", evidence: [`[Scan: ${scan.id}]`] });
    } else {
      const previous = criticalKeys(previousScan), introduced = critical.filter(key => !previous.has(key));
      const passes = introduced.length <= policy.maximumNewCriticalFindings;
      rules.push({
        id: "new-critical-findings",
        label: "New critical findings",
        status: passes ? "pass" : "fail",
        reason: passes ? `${introduced.length} new critical finding${introduced.length === 1 ? " is" : "s are"} within the allowed maximum.` : `${introduced.length} new critical findings exceed the allowed maximum of ${policy.maximumNewCriticalFindings}.`,
        evidence: [`[Baseline scan: ${previousScan.id}]`, ...introduced.map(value => `[Introduced: ${value}]`)],
      });
    }
  }

  const incomplete = Boolean(
    scan.warnings?.some(warning => warning.code !== "REACHABILITY_INCOMPLETE" && warning.code !== "REACHABILITY_DISABLED") ||
    !scan.sourceStatus?.length ||
    scan.sourceStatus.some(source => source.status === "failed" || source.status === "partial"),
  );
  rules.push({
    id: "source-coverage",
    label: "Vulnerability source coverage",
    status: incomplete ? policy.incompleteSourceAction : "pass",
    reason: incomplete ? "One or more vulnerability sources are missing, incomplete, or failed; the gate has reduced evidence coverage." : "All configured vulnerability sources completed.",
    evidence: (scan.sourceStatus ?? []).map(source => `[Source: ${source.source} · ${source.status}]`),
  });

  const status = aggregateStatus(rules);
  return {
    policyId: policy.id,
    policyName: policy.name,
    scanId: scan.id,
    status,
    exitCode: status === "fail" ? 1 : 0,
    summary: status === "pass" ? "All security policy rules passed." : status === "fail" ? "One or more security policy rules failed." : "Policy checks completed with incomplete evidence or an unavailable baseline.",
    rules,
  };
}

import { DEFAULT_SECURITY_POLICY, evaluateSecurityPolicy, type PolicyEvaluation, type SecurityPolicy } from "./policy";
import { deterministicSummary } from "./posture";
import { remediationLabel } from "./remediation";
import { createSecurityDiff, type SecurityDiff } from "./security-diff";
import type { Dependency, Scan, Severity, Vulnerability, VulnerabilitySource } from "./types";

export const DEPSHIELD_SBOM_VERSION = "depshield-cyclonedx-1" as const;
export const EVIDENCE_PACK_VERSION = "depshield-evidence-pack-1" as const;

type CycloneDxProperty = { name: string; value: string };
type CycloneDxSource = { name: string; url?: string };

export type CycloneDxComponent = {
  type: "application" | "library";
  "bom-ref": string;
  group?: string;
  name: string;
  version?: string;
  purl?: string;
  scope?: "required" | "optional" | "excluded";
  licenses?: Array<{ license: { id: string } } | { expression: string }>;
  properties?: CycloneDxProperty[];
};

export type CycloneDxVulnerability = {
  "bom-ref": string;
  id: string;
  source: CycloneDxSource;
  references: Array<{ id: string; source: CycloneDxSource }>;
  ratings: Array<{
    source: CycloneDxSource;
    score?: number;
    severity: Severity;
    method?: "CVSSv2" | "CVSSv3" | "CVSSv4" | "other";
    vector?: string;
  }>;
  cwes?: number[];
  description: string;
  recommendation: string;
  advisories: Array<{ url: string }>;
  created?: string;
  updated?: string;
  affects: Array<{ ref: string; versions: Array<{ version: string; status: "affected" }> }>;
  analysis: {
    state: "in_triage";
    justification: "code_not_reachable" | "code_not_present" | "requires_configuration" | "requires_dependency";
    detail: string;
  };
  properties: CycloneDxProperty[];
};

export type CycloneDxBom = {
  bomFormat: "CycloneDX";
  specVersion: "1.6";
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: { components: CycloneDxComponent[] };
    component: CycloneDxComponent;
    properties: CycloneDxProperty[];
  };
  components: CycloneDxComponent[];
  dependencies: Array<{ ref: string; dependsOn: string[] }>;
  vulnerabilities: CycloneDxVulnerability[];
};

export type StoryStep = {
  order: number;
  id:
    | "inventory"
    | "known-risk"
    | "severity"
    | "reachability"
    | "priority"
    | "entry-path"
    | "remediation"
    | "verification";
  title: string;
  narrative: string;
  status: "observed" | "estimated" | "not-available";
  evidence: string[];
};

export type ReplayEvidenceInput = {
  dependency: string;
  vulnerabilityId: string;
  observed: boolean;
  cleanupVerified: boolean;
  executedAt: string;
  route: string;
  safety: string;
};

export type EvidencePackOptions = {
  previousScan?: Scan;
  replayEvidence?: ReplayEvidenceInput[];
  generatedAt?: string;
  policy?: SecurityPolicy;
};

export type SecurityEvidencePack = {
  schema: typeof EVIDENCE_PACK_VERSION;
  id: string;
  generatedAt: string;
  scan: {
    id: string;
    project: string;
    branch: string;
    createdAt: string;
    durationSeconds: number;
    securityScore: number;
    grade: string;
    contextualRisk: number | null;
    confidence: number | null;
    dependencyCount: number;
    vulnerableDependencyCount: number;
    criticalDependencyCount: number;
    reachableCriticalFindings: number | null;
    sourceFilesAnalyzed: number;
  };
  sourceCoverage: {
    sources: Scan["sourceStatus"];
    warnings: Scan["warnings"];
    complete: boolean;
  };
  posture: Scan["posture"] | null;
  summary: NonNullable<Scan["summary"]>;
  findings: EvidenceFinding[];
  replayEvidence: ReplayEvidenceInput[];
  comparison: SecurityDiff | null;
  policy: PolicyEvaluation;
  story: StoryStep[];
  limitations: string[];
};

export type EvidenceFinding = {
  key: string;
  dependency: {
    name: string;
    version: string;
    direct: boolean;
    runtime: boolean | null;
    depth: number | null;
    path: string;
    paths: string[];
  };
  vulnerability: {
    id: string;
    cveAlias: string | null;
    aliases: string[];
    summary: string;
    severity: Severity;
    cvss: number | null;
    cvssVector: string | null;
    vulnerableRange: string | null;
    fixedVersion: string | null;
    references: string[];
    sources: VulnerabilitySource[];
    provenance: NonNullable<Vulnerability["provenance"]>;
    publishedAt: string | null;
    modifiedAt: string | null;
    confidence: number | null;
    confidenceEvidence: string[];
  };
  contextualRisk: Dependency["contextual"] | null;
  legacyRisk: number;
  reachability: Dependency["reachability"] | null;
  blastRadius: Dependency["blastRadius"] | null;
  remediation: {
    label: ReturnType<typeof remediationLabel>;
    targetVersion: string | null;
    recommendation: Dependency["recommendation"] | null;
    compatibility: Dependency["compatibility"] | null;
  };
  evidence: string[];
};

type ComponentGroup = {
  key: string;
  name: string;
  version: string;
  ref: string;
  purl: string;
  dependencies: Dependency[];
};

export function createCycloneDxSbom(scan: Scan): CycloneDxBom {
  const applicationRef = `depshield:application:${encodeURIComponent(scan.project)}:${scan.id}`;
  const groups = groupComponents(scan.items);
  const groupByKey = new Map(groups.map((group) => [group.key, group]));
  const adjacency = new Map<string, Set<string>>([[applicationRef, new Set()]]);
  for (const group of groups) adjacency.set(group.ref, new Set());

  for (const group of groups) {
    if (group.dependencies.some((dependency) => dependency.direct)) adjacency.get(applicationRef)!.add(group.ref);
    for (const dependency of group.dependencies) {
      for (const dependencyPath of dependency.paths?.map((item) => item.nodes) ?? []) {
        const componentPath = dependencyPath
          .map(parseDependencyNode)
          .filter((value): value is { name: string; version: string } => Boolean(value))
          .map((value) => groupByKey.get(componentGroupKey(value.name, value.version)))
          .filter((value): value is ComponentGroup => Boolean(value));
        if (componentPath[0]) adjacency.get(applicationRef)!.add(componentPath[0].ref);
        componentPath.slice(1).forEach((component, index) => {
          adjacency.get(componentPath[index].ref)?.add(component.ref);
        });
      }
    }
  }

  const application: CycloneDxComponent = {
    type: "application",
    "bom-ref": applicationRef,
    name: scan.project,
    version: scan.branch || "uploaded",
    properties: [
      property("depshield:scan:id", scan.id),
      property("depshield:security-score", scan.score),
      property("depshield:grade", scan.grade),
    ],
  };
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${scan.id}`,
    version: 1,
    metadata: {
      timestamp: scan.createdAt,
      tools: {
        components: [{ type: "application", "bom-ref": "depshield:tool", name: "DepShield AI", version: DEPSHIELD_SBOM_VERSION }],
      },
      component: application,
      properties: [
        property("depshield:export:schema", DEPSHIELD_SBOM_VERSION),
        property("depshield:contextual-risk", scan.contextualRisk ?? "unknown"),
        property("depshield:confidence", scan.confidence ?? "unknown"),
      ],
    },
    components: groups.map(toCycloneComponent),
    dependencies: [...adjacency.entries()]
      .map(([ref, dependsOn]) => ({ ref, dependsOn: [...dependsOn].sort() }))
      .sort((left, right) => left.ref.localeCompare(right.ref)),
    vulnerabilities: groups.flatMap(toCycloneVulnerabilities),
  };
}

export const generateSbom = createCycloneDxSbom;

export function createSecurityStory(scan: Scan, previousScan?: Scan): StoryStep[] {
  const vulnerabilities = scan.items.flatMap((dependency) =>
    dependency.vulnerabilities.map((vulnerability) => ({ dependency, vulnerability })),
  );
  const highOrCritical = vulnerabilities.filter(({ vulnerability }) =>
    vulnerability.severity === "critical" || vulnerability.severity === "high",
  );
  const reachable = vulnerabilities.filter(({ dependency }) => dependency.reachability?.status === "REACHABLE");
  const top = scan.items
    .filter((dependency) => dependency.vulnerabilities.length)
    .toSorted((left, right) => (right.contextual?.finalPriority ?? right.risk) - (left.contextual?.finalPriority ?? left.risk))[0];
  const topPath = top?.reachability?.paths[0]?.display ?? top?.paths?.[0]?.display ?? top?.path ?? null;
  const label = top ? remediationLabel(top) : null;
  const comparison = previousScan ? createSecurityDiff(previousScan, scan) : null;
  const comparisonNarrative = comparison
    ? `A computed comparison with saved scan ${previousScan!.id} shows a score change from ${comparison.metrics.scoreBefore} to ${comparison.metrics.scoreAfter}; ${comparison.findings.removed.length} findings are absent and ${comparison.findings.introduced.length} are new in this snapshot. The scan records do not prove that remediation caused these changes.`
    : "No comparison baseline was supplied. A later saved-scan comparison can quantify observed snapshot differences, but remediation causality requires separate change and validation evidence.";

  return [
    storyStep(1, "inventory", "Dependency inventory", `DepShield scanned ${scan.dependencies} resolved dependencies for ${scan.project}.`, "observed", [`[Scan: ${scan.id}]`, `[Dependencies: ${scan.dependencies}]`]),
    storyStep(2, "known-risk", "Known vulnerability surface", `${scan.vulnerable} dependencies contain ${vulnerabilities.length} normalized known-vulnerability findings.`, "observed", [`[Vulnerable dependencies: ${scan.vulnerable}]`, `[Findings: ${vulnerabilities.length}]`]),
    storyStep(3, "severity", "Highest-severity findings", `${highOrCritical.length} findings are high or critical; ${vulnerabilities.filter(({ vulnerability }) => vulnerability.severity === "critical").length} are critical.`, "observed", highOrCritical.slice(0, 5).map(({ dependency, vulnerability }) => `[Finding: ${dependency.name}@${dependency.version} · ${vulnerability.cveAlias ?? vulnerability.id}]`)),
    storyStep(4, "reachability", "Static reachability", scan.sourceFilesAnalyzed
      ? `${reachable.length} findings belong to dependencies with an observed static package import. Static analysis does not prove vulnerable-function execution.`
      : "No application source files were analyzed, so runtime reachability remains unknown.", scan.sourceFilesAnalyzed ? "estimated" : "not-available", [`[Source files: ${scan.sourceFilesAnalyzed ?? 0}]`, `[Reachable findings: ${reachable.length}]`]),
    storyStep(5, "priority", "Computed risk priority", top
      ? `The contextual risk model ranks ${top.name}@${top.version} first at ${top.contextual?.finalPriority ?? top.risk}/100. This is a heuristic prioritization output, not verified exploitability or business impact.`
      : "No vulnerable dependency is available for model-based prioritization.", top ? "estimated" : "not-available", top ? [`[Dependency: ${top.name}@${top.version}]`, `[Computed priority: ${top.contextual?.finalPriority ?? top.risk}]`] : [`[Scan: ${scan.id}]`]),
    storyStep(6, "entry-path", "Dependency entry path", topPath
      ? `The representative evidence path is ${topPath}. This path is dependency or static-import evidence, not an exploit trace.`
      : "No dependency or source path is available for the top finding.", topPath ? "estimated" : "not-available", topPath ? [`[Path: ${topPath}]`] : [`[Scan: ${scan.id}]`]),
    storyStep(7, "remediation", "Recommended remediation", top && label
      ? `${label}: ${top.latest !== top.version ? `${top.name} ${top.version} → ${top.latest}` : `manually review ${top.name}@${top.version}`}. Compatibility impact is estimated, not guaranteed.`
      : "No reported remediation target is available from this scan.", top && label ? "estimated" : "not-available", top ? [`[Dependency: ${top.name}@${top.version}]`, `[Fixed target: ${top.latest === top.version ? "not reported" : top.latest}]`] : [`[Scan: ${scan.id}]`]),
    storyStep(8, "verification", "Saved-scan delta", comparisonNarrative, comparison ? "estimated" : "not-available", comparison ? [`[Comparison baseline: ${previousScan!.id}]`, `[Current scan: ${scan.id}]`, "[Causality: not established]"] : [`[Current scan: ${scan.id}]`, "[Comparison baseline: unavailable]"]),
  ];
}

export const generateStorySteps = createSecurityStory;

export function createSecurityEvidencePack(scan: Scan, options: EvidencePackOptions = {}): SecurityEvidencePack {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const comparison = options.previousScan ? createSecurityDiff(options.previousScan, scan) : null;
  const sources = scan.sourceStatus ?? [];
  const warnings = scan.warnings ?? [];
  const complete = sources.length > 0 && sources.every((source) => source.status === "ok" || source.status === "skipped") &&
    !warnings.some((warning) => warning.code !== "REACHABILITY_INCOMPLETE");
  return {
    schema: EVIDENCE_PACK_VERSION,
    id: `depshield-evidence:${scan.id}`,
    generatedAt,
    scan: {
      id: scan.id,
      project: scan.project,
      branch: scan.branch,
      createdAt: scan.createdAt,
      durationSeconds: scan.duration,
      securityScore: scan.score,
      grade: scan.grade,
      contextualRisk: scan.contextualRisk ?? null,
      confidence: scan.confidence ?? null,
      dependencyCount: scan.dependencies,
      vulnerableDependencyCount: scan.vulnerable,
      criticalDependencyCount: scan.critical,
      reachableCriticalFindings: scan.reachableCritical ?? null,
      sourceFilesAnalyzed: scan.sourceFilesAnalyzed ?? 0,
    },
    sourceCoverage: { sources, warnings, complete },
    posture: scan.posture ?? null,
    summary: scan.summary ?? deterministicSummary(scan),
    findings: scan.items.flatMap((dependency) =>
      dependency.vulnerabilities.map((vulnerability) => evidenceFinding(dependency, vulnerability, scan)),
    ),
    replayEvidence: options.replayEvidence ?? [],
    comparison,
    policy: evaluateSecurityPolicy(scan, options.policy ?? DEFAULT_SECURITY_POLICY, options.previousScan),
    story: createSecurityStory(scan, options.previousScan),
    limitations: [
      "The evidence pack records observed scan data and deterministic estimates; it is not proof that a vulnerability is exploitable.",
      "NOT_OBSERVED reachability is not a safety claim. Dynamic runtime behavior and unavailable source can hide paths.",
      ...(options.replayEvidence?.length ? [] : ["No safe local Attack Replay evidence was attached to this export."]),
      ...(comparison ? [] : ["No baseline scan was supplied, so before/after remediation claims are not included."]),
    ],
  };
}

export const generateEvidencePack = createSecurityEvidencePack;

function groupComponents(dependencies: Dependency[]) {
  const groups = new Map<string, ComponentGroup>();
  for (const dependency of dependencies) {
    const key = componentGroupKey(dependency.name, dependency.version);
    const current = groups.get(key) ?? {
      key,
      name: dependency.name,
      version: dependency.version,
      ref: npmPurl(dependency.name, dependency.version),
      purl: npmPurl(dependency.name, dependency.version),
      dependencies: [],
    };
    current.dependencies.push(dependency);
    groups.set(key, current);
  }
  return [...groups.values()].sort((left, right) => left.ref.localeCompare(right.ref));
}

function componentGroupKey(name: string, version: string) {
  return `${name.trim().toLowerCase()}\0${version.trim()}`;
}

function npmPurl(name: string, version: string) {
  const encodedName = name.split("/").map(encodeURIComponent).join("/");
  return `pkg:npm/${encodedName}@${encodeURIComponent(version)}`;
}

function parseDependencyNode(node: string) {
  const value = node.trim();
  const separator = value.lastIndexOf("@");
  if (separator <= 0) return null;
  const name = value.slice(0, separator);
  const version = value.slice(separator + 1);
  return name && version ? { name, version } : null;
}

function toCycloneComponent(group: ComponentGroup): CycloneDxComponent {
  const dependencies = group.dependencies;
  const licenses = unique(dependencies.map((dependency) => dependency.license).filter((license) => license && license !== "Unknown"));
  const direct = dependencies.some((dependency) => dependency.direct);
  const optional = dependencies.every((dependency) => dependency.optional);
  const devOnly = dependencies.every((dependency) => dependency.devOnly || dependency.runtime === false);
  const paths = unique(dependencies.flatMap((dependency) => dependency.paths?.map((item) => item.display) ?? [dependency.path]));
  return {
    type: "library",
    "bom-ref": group.ref,
    ...splitPackageName(group.name),
    version: group.version,
    purl: group.purl,
    scope: devOnly ? "excluded" : optional ? "optional" : "required",
    ...(licenses.length ? { licenses: licenses.map(cycloneLicense) } : {}),
    properties: [
      property("depshield:direct", direct),
      property("depshield:runtime", !devOnly),
      property("depshield:dependency-paths", JSON.stringify(paths)),
      property("depshield:risk:max", Math.max(...dependencies.map((dependency) => dependency.risk))),
      property("depshield:reachability", unique(dependencies.map((dependency) => dependency.reachability?.status ?? "UNKNOWN")).join(",")),
      property("depshield:confidence:max", Math.max(...dependencies.map((dependency) => dependency.contextual?.confidence ?? 0))),
    ],
  };
}

function toCycloneVulnerabilities(group: ComponentGroup): CycloneDxVulnerability[] {
  const findings = new Map<string, Array<{ dependency: Dependency; vulnerability: Vulnerability }>>();
  for (const dependency of group.dependencies) {
    for (const vulnerability of dependency.vulnerabilities) {
      const id = canonicalVulnerabilityId(vulnerability);
      const current = findings.get(id) ?? [];
      current.push({ dependency, vulnerability });
      findings.set(id, current);
    }
  }
  return [...findings.entries()].map(([id, values]) => {
    const vulnerabilities = values.map((value) => value.vulnerability);
    const strongest = vulnerabilities.toSorted((left, right) =>
      (right.cvssAvailable === false ? -1 : right.cvss) - (left.cvssAvailable === false ? -1 : left.cvss),
    )[0];
    const sources = unique(vulnerabilities.flatMap(vulnerabilitySources));
    const references = unique(vulnerabilities.flatMap((vulnerability) => vulnerability.references ?? []));
    const fixedVersions = unique(vulnerabilities.map((vulnerability) => vulnerability.fixedVersion).filter((value): value is string => Boolean(value)));
    const reachability = unique(values.map(({ dependency }) => dependency.reachability?.status ?? "UNKNOWN"));
    const source = sourceDescriptor(sources[0] ?? "DepShield");
    return {
      "bom-ref": `depshield:vulnerability:${encodeURIComponent(id)}:${encodeURIComponent(group.ref)}`,
      id,
      source,
      references: sources.map((value) => ({ id, source: sourceDescriptor(value) })),
      ratings: [{
        source: { name: "DepShield merged intelligence" },
        ...(strongest.cvssAvailable === false ? {} : { score: strongest.cvss }),
        severity: strongest.severity,
        ...(cvssMethod(strongest.cvssVector) ? { method: cvssMethod(strongest.cvssVector)! } : {}),
        ...(strongest.cvssVector ? { vector: strongest.cvssVector } : {}),
      }],
      description: strongest.summary,
      recommendation: fixedVersions.length
        ? `Review an upgrade to a reported fixed version: ${fixedVersions.join(", ")}. Validate resolution, vulnerability status, and compatibility before deployment.`
        : "No reported fixed version is present in this scan; isolate, replace, remove, or manually review the dependency.",
      advisories: references.map((url) => ({ url })),
      ...(strongest.publishedAt ? { created: strongest.publishedAt } : {}),
      ...(strongest.modifiedAt ? { updated: strongest.modifiedAt } : {}),
      affects: [{ ref: group.ref, versions: [{ version: group.version, status: "affected" }] }],
      analysis: {
        state: "in_triage",
        justification: "requires_dependency",
        detail: `DepShield reachability: ${reachability.join(", ")}. This remains an estimate and is not a not-affected determination.`,
      },
      properties: [
        property("depshield:sources", sources.join(",")),
        property("depshield:vulnerable-ranges", unique(vulnerabilities.map((value) => value.vulnerableRange).filter((value): value is string => Boolean(value))).join("; ") || "unknown"),
        property("depshield:fixed-versions", fixedVersions.join(",") || "unknown"),
        property("depshield:reachability", reachability.join(",")),
        property("depshield:risk:max", Math.max(...values.map(({ dependency }) => dependency.risk))),
        property("depshield:confidence:max", Math.max(...values.map(({ dependency }) => dependency.contextual?.confidence ?? 0))),
      ],
    };
  });
}

function evidenceFinding(dependency: Dependency, vulnerability: Vulnerability, scan: Scan): EvidenceFinding {
  const sources = vulnerabilitySources(vulnerability);
  const id = canonicalVulnerabilityId(vulnerability);
  const paths = dependency.paths?.map((item) => item.display) ?? [dependency.path];
  return {
    key: `${dependency.name}@${dependency.version}:${id}:${encodeURIComponent(dependency.path)}`,
    dependency: {
      name: dependency.name,
      version: dependency.version,
      direct: dependency.direct,
      runtime: dependency.runtime ?? null,
      depth: dependency.depth ?? null,
      path: dependency.path,
      paths,
    },
    vulnerability: {
      id: vulnerability.id,
      cveAlias: vulnerability.cveAlias ?? null,
      aliases: unique([vulnerability.id, ...(vulnerability.aliases ?? []), ...(vulnerability.cveAlias ? [vulnerability.cveAlias] : [])]),
      summary: vulnerability.summary,
      severity: vulnerability.severity,
      cvss: vulnerability.cvssAvailable === false ? null : vulnerability.cvss,
      cvssVector: vulnerability.cvssVector ?? null,
      vulnerableRange: vulnerability.vulnerableRange ?? null,
      fixedVersion: vulnerability.fixedVersion ?? null,
      references: vulnerability.references ?? [],
      sources,
      provenance: vulnerability.provenance ?? sources.map((source) => ({
        source,
        retrievedAt: scan.sourceStatus?.find((status) => sourceStatusMatches(source, status.source))?.retrievedAt ?? scan.createdAt,
        status: "reported" as const,
        confidence: scan.sourceStatus?.find((status) => sourceStatusMatches(source, status.source))?.confidence ?? 50,
        identifiers: unique([vulnerability.id, ...(vulnerability.aliases ?? []), ...(vulnerability.cveAlias ? [vulnerability.cveAlias] : [])]),
      })),
      publishedAt: vulnerability.publishedAt ?? null,
      modifiedAt: vulnerability.modifiedAt ?? null,
      confidence: vulnerability.confidence ?? null,
      confidenceEvidence: vulnerability.confidenceEvidence ?? [],
    },
    contextualRisk: dependency.contextual ?? null,
    legacyRisk: dependency.risk,
    reachability: dependency.reachability ?? null,
    blastRadius: dependency.blastRadius ?? null,
    remediation: {
      label: remediationLabel(dependency),
      targetVersion: dependency.recommendation === "upgrade" && dependency.latest !== dependency.version ? dependency.latest : null,
      recommendation: dependency.recommendation ?? null,
      compatibility: dependency.compatibility ?? null,
    },
    evidence: unique([
      `[Scan: ${scan.id}]`,
      `[Dependency: ${dependency.name}@${dependency.version}]`,
      `[Finding: ${id}]`,
      ...paths.map((value) => `[Path: ${value}]`),
      ...(dependency.reachability?.explanation ? [`[Reachability: ${dependency.reachability.explanation}]`] : []),
      ...(dependency.blastRadius?.evidence ?? []).map((value) => `[Blast radius: ${value}]`),
    ]),
  };
}

function storyStep(
  order: number,
  id: StoryStep["id"],
  title: string,
  narrative: string,
  status: StoryStep["status"],
  evidence: string[],
): StoryStep {
  return { order, id, title, narrative, status, evidence };
}

function vulnerabilitySources(vulnerability: Vulnerability) {
  return unique(vulnerability.sources ?? (vulnerability.source ? [vulnerability.source] : []));
}

function canonicalVulnerabilityId(vulnerability: Vulnerability) {
  return (vulnerability.cveAlias
    ?? vulnerability.aliases?.find((alias) => alias.toUpperCase().startsWith("CVE-"))
    ?? vulnerability.aliases?.find((alias) => alias.toUpperCase().startsWith("GHSA-"))
    ?? vulnerability.id).trim().toUpperCase();
}

function sourceDescriptor(source: VulnerabilitySource | "DepShield"): CycloneDxSource {
  if (source === "OSV") return { name: "OSV", url: "https://osv.dev" };
  if (source === "NVD") return { name: "NVD", url: "https://nvd.nist.gov" };
  if (source === "GitHub") return { name: "GitHub Advisory Database", url: "https://github.com/advisories" };
  if (source === "npm") return { name: "npm audit", url: "https://docs.npmjs.com/cli/commands/npm-audit" };
  return { name: "DepShield" };
}

function sourceStatusMatches(source: VulnerabilitySource, status: NonNullable<Scan["sourceStatus"]>[number]["source"]) {
  return (source === "OSV" && status === "osv") ||
    (source === "npm" && status === "npm-audit") ||
    (source === "NVD" && status === "nvd") ||
    (source === "GitHub" && status === "github-advisory");
}

function cvssMethod(vector?: string | null): CycloneDxVulnerability["ratings"][number]["method"] | null {
  if (!vector) return null;
  if (/^CVSS:4/i.test(vector)) return "CVSSv4";
  if (/^CVSS:3/i.test(vector)) return "CVSSv3";
  if (/^CVSS:2/i.test(vector)) return "CVSSv2";
  return "other";
}

function splitPackageName(name: string): Pick<CycloneDxComponent, "group" | "name"> {
  if (!name.startsWith("@") || !name.includes("/")) return { name };
  const [group, packageName] = name.split("/", 2);
  return { group, name: packageName };
}

function cycloneLicense(value: string): { license: { id: string } } | { expression: string } {
  return /^[A-Za-z0-9.+-]+$/.test(value) ? { license: { id: value } } : { expression: value };
}

function property(name: string, value: string | number | boolean): CycloneDxProperty {
  return { name, value: String(value) };
}

function unique<T extends string>(values: T[]) {
  return [...new Set(values)].sort() as T[];
}

export type Severity = "critical" | "high" | "medium" | "low" | "unknown";
export type RemediationLabel = "Safe Auto Fix" | "Minor Upgrade" | "Major Upgrade" | "No Fix Available" | "Update Parent Dependency" | "Manual Review";
export type RemediationClassification = "SAFE PATCH" | "MINOR UPGRADE" | "MAJOR UPGRADE" | "UPDATE PARENT" | "NO FIX" | "MANUAL REVIEW";
export type VulnerabilitySource = "OSV" | "npm" | "NVD" | "GitHub";
export type ReachabilityStatus = "REACHABLE" | "POSSIBLY_REACHABLE" | "NOT_OBSERVED" | "UNKNOWN";
export type CompatibilityRiskLevel = "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";

export type SourceFileInput = { path: string; content: string };

export type VulnerabilityProvenance = {
  source: VulnerabilitySource;
  retrievedAt: string;
  status: "confirmed" | "reported" | "partial";
  confidence: number;
  identifiers: string[];
};

export type Vulnerability = {
  id: string;
  aliases?: string[];
  cveAlias?: string | null;
  cvss: number;
  cvssAvailable?: boolean;
  cvssVector?: string | null;
  severity: Severity;
  summary: string;
  vulnerableRange?: string | null;
  fixedVersion?: string | null;
  references?: string[];
  sources?: VulnerabilitySource[];
  source?: VulnerabilitySource;
  provenance?: VulnerabilityProvenance[];
  publishedAt?: string | null;
  modifiedAt?: string | null;
  knownExploit?: boolean | null;
  confidence?: number;
  confidenceEvidence?: string[];
};

export type DependencyPath = { nodes: string[]; display: string };

export type AttackPathReachability = "reachable" | "possibly-reachable" | "not-observed" | "unknown";

/**
 * Persisted evidence joining one advisory to one application/source or
 * dependency-resolution path. `estimated` is always true because static
 * evidence does not prove runtime execution or exploitability.
 */
export type AttackPath = {
  id: string;
  dependencyName: string;
  dependencyVersion: string;
  dependencyPath: string;
  findingId: string;
  cveAlias: string | null;
  severity: Severity;
  reachability: AttackPathReachability;
  internetExposed: boolean;
  nodes: string[];
  display: string;
  evidenceKind: "source-route" | "source-import" | "dependency-path";
  confidence: number;
  explanation: string;
  estimated: true;
};

export type ReachabilityPath = {
  nodes: string[];
  display: string;
  entryFile: string;
  importedPackage: string;
  internetExposed: boolean;
};

export type ReachabilityEvidence = {
  status: ReachabilityStatus;
  confidence: number;
  sourceFilesAnalyzed: number;
  entryFiles: string[];
  importedBy: string[];
  observedFunctions: string[];
  paths: ReachabilityPath[];
  internetExposed: boolean;
  explanation: string;
  limitations: string[];
};

export type RiskFactor = {
  id: string;
  label: string;
  value: string;
  contribution: number;
  direction: "increase" | "decrease" | "neutral";
  evidence: string;
};

export type ContextualScores = {
  technical: number;
  exploitability: number;
  exposure: number;
  remediationDifficulty: number;
  finalPriority: number;
  confidence: number;
  factors: RiskFactor[];
  model: "DepShield Contextual Risk v2";
};

export type PropagatedRiskContributor = {
  dependency: string;
  distance: number;
  pathCount: number;
  contribution: number;
  explanation: string;
};

export type RiskPropagation = {
  ownRisk: number;
  inheritedRisk: number;
  contextualRisk: number;
  contributors: PropagatedRiskContributor[];
  formula: string;
};

export type BlastRadius = {
  routes: string[];
  modules: string[];
  services: string[];
  parentDependencies: string[];
  applicationAreas: string[];
  evidence: string[];
  estimated: true;
};

export type CompatibilityPreview = {
  level: CompatibilityRiskLevel;
  score: number;
  currentVersion: string;
  targetVersion: string | null;
  importedApis: string[];
  reasons: string[];
  suggestedTests: string[];
  estimated: true;
};

export type Dependency = {
  name: string;
  version: string;
  direct: boolean;
  runtime?: boolean;
  devOnly?: boolean;
  optional?: boolean;
  depth?: number;
  parentCount?: number;
  parentPackages?: string[];
  path: string;
  paths?: DependencyPath[];
  license: string;
  vulnerabilities: Vulnerability[];
  risk: number;
  latest: string;
  recommendation?: "upgrade" | "partial-fix" | "no-fix" | "none";
  contextual?: ContextualScores;
  reachability?: ReachabilityEvidence;
  propagation?: RiskPropagation;
  blastRadius?: BlastRadius;
  compatibility?: CompatibilityPreview;
  lastObservedAt?: string;
};

export type SourceStatus = {
  source: "npm-audit" | "osv" | "nvd" | "github-advisory";
  status: "ok" | "partial" | "failed" | "skipped";
  message: string | null;
  cached?: number;
  fetched?: number;
  retrievedAt?: string;
  confidence?: number;
};

export type ScanWarning = {
  code: "NPM_AUDIT_FAILED" | "OSV_API_FAILED" | "NVD_API_FAILED" | "GITHUB_API_FAILED" | "MISSING_CVSS" | "NO_LOCKFILE" | "INVALID_MANIFEST" | "REACHABILITY_INCOMPLETE" | "REACHABILITY_DISABLED";
  message: string;
  recoverable: boolean;
};

export type PostureRadar = {
  dependencyHygiene: number;
  knownVulnerabilityRisk: number;
  reachabilityExposure: number;
  patchability: number;
  supplyChainComplexity: number;
  remediationReadiness: number;
};

export type ScanSummary = {
  executive: string;
  developer: string;
  evidence: string[];
  generatedBy: "deterministic" | "ai";
};

export type Scan = {
  id: string;
  createdAt: string;
  project: string;
  branch: string;
  score: number;
  grade: string;
  dependencies: number;
  vulnerable: number;
  critical: number;
  duration: number;
  items: Dependency[];
  dependencyTree?: DependencyPath[];
  attackPaths?: AttackPath[];
  sourceStatus?: SourceStatus[];
  warnings?: ScanWarning[];
  contextualRisk?: number;
  confidence?: number;
  reachableCritical?: number;
  fixableRiskPercent?: number;
  sourceFilesAnalyzed?: number;
  posture?: PostureRadar;
  summary?: ScanSummary;
};

export type RawAdvisory = Omit<Vulnerability, "sources" | "provenance"> & { source: VulnerabilitySource; retrievedAt?: string };

export type UpgradePlanItem = {
  dependency: Dependency;
  label: RemediationLabel;
  classification?: RemediationClassification;
  targetVersion: string | null;
  effort: number;
  priority: number;
  expectedRiskReduction?: number;
  cvesResolved?: string[];
  remainingCves?: string[];
  conflicts?: string[];
  compatibility?: CompatibilityPreview;
};

export type SecurityDiffFinding = { id: string; dependency: string; version: string; reachability: ReachabilityStatus; risk: number };

export type SecurityDiff = {
  beforeScanId: string;
  afterScanId: string;
  removed: SecurityDiffFinding[];
  introduced: SecurityDiffFinding[];
  changed: Array<{ dependency: string; beforeRisk: number; afterRisk: number; delta: number }>;
  upgraded: Array<{ dependency: string; from: string; to: string }>;
  attackPathsRemoved: number;
  attackPathsAdded: number;
  reachableCriticalBefore: number;
  reachableCriticalAfter: number;
  scoreBefore: number;
  scoreAfter: number;
};

export type SecurityAnomaly = {
  type: "DEPENDENCY_SURGE" | "CRITICAL_SURGE" | "SCORE_DROP" | "NEW_HIGH_RISK" | "VULNERABILITY_RETURNED" | "GRAPH_EXPANSION";
  severity: "warning" | "critical";
  title: string;
  explanation: string;
  evidence: string[];
};

export type RemediationSimulation = {
  dependency: string;
  fromVersion: string;
  toVersion: string;
  currentScore: number;
  simulatedScore: number;
  currentCritical: number;
  simulatedCritical: number;
  cvesRemoved: string[];
  remainingCves: string[];
  attackPathsRemoved: number;
  riskBefore: number;
  riskAfter: number;
  compatibility: CompatibilityPreview;
  simulated: true;
};

export type AnalystCitation = { label: string; value: string };
export type AnalystAnswer = {
  answer: string;
  citations: AnalystCitation[];
  supported: boolean;
  provider: "deterministic" | "gemini" | "external";
};

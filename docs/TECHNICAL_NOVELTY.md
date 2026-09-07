# DepShield AI

## Potentially differentiating technical ideas requiring prior-art review

DepShield AI is positioned as a context-aware open-source dependency risk intelligence and remediation platform. Its research interest is not any single dependency-scanning technique in isolation, but the way multiple evidence layers are combined into an explainable workflow: package inventory, vulnerability provenance, application reachability, graph propagation, attack-path estimation, remediation simulation, compatibility estimation, scan-to-scan validation, safe local replay, and a scan-grounded analyst.

The methods documented here are DepShield-specific heuristics and engineering proposals. They are not industry standards, formal exploitability proofs, calibrated probabilities, or guarantees of security. Similar ideas may already exist in academic literature, commercial products, public standards, or earlier technical disclosures. Each idea therefore requires careful prior-art review and empirical evaluation before making claims about distinctiveness.

## 1. Context-aware dependency risk scoring

### Problem

CVSS describes characteristics of a vulnerability, but it does not describe the complete risk of that vulnerability inside a particular application. Two projects using the same vulnerable package may have different dependency scopes, import paths, route exposure, fix options, and upgrade costs.

### Existing baseline

A conventional software composition analysis view commonly prioritizes findings by CVSS, severity, advisory count, or whether a fix exists. This is useful for inventory and triage, but may rank an unused development dependency similarly to a reachable runtime dependency.

### Proposed method

DepShield calculates separate contextual dimensions rather than presenting one unexplained number:

- Technical Risk
- Exploitability Score
- Exposure Score
- Remediation Difficulty
- Final Priority Score
- Confidence

Every score is accompanied by factor records containing the observed value, direction, numerical contribution, explanation, and supporting evidence.

### Inputs

- Reported CVSS or an explicitly labelled severity proxy
- Direct or transitive relationship
- Applicable vulnerability count
- Fix status
- Dependency depth and parent count
- Runtime, optional, or development scope
- Reachability classification
- Observed vulnerable API usage
- Route exposure
- Known exploit evidence when supplied by a provider
- Vulnerability age
- Upgrade class, imported API count, conflicts, and estimated breaking-change risk

### Algorithm

Each dimension uses a deterministic, versioned weighted model. Known evidence adds or subtracts documented contributions. Missing contextual evidence is neutral in the risk calculation rather than silently treated as safe; missing evidence instead lowers Confidence. Scores are clamped to 0–100. Final Priority combines Technical Risk, Exploitability, and Exposure, with a bounded actionability adjustment derived from Remediation Difficulty.

### Outputs

- Dimension scores from 0–100
- Final Priority from 0–100
- Confidence percentage
- “Why this score?” factor list
- Model version and raw pre-clamp score

### Technical benefit

The separation makes prioritization auditable. A reviewer can distinguish high technical severity from high application exposure and can see whether an easy remediation justifies earlier scheduling.

### Limitations

Weights are heuristic and have not been statistically calibrated against real incident frequency. CVSS proxies are estimates, not reported CVSS. Correlated factors can partially overlap. Final Priority is a decision-support signal and must not be interpreted as a probability of exploitation.

## 2. Dependency-graph risk propagation

### Problem

A parent package may have low or no vulnerabilities of its own while introducing a high-risk vulnerable descendant. Assigning the child’s complete score to every ancestor exaggerates risk, while ignoring inherited risk hides an important dependency relationship.

### Existing baseline

Flat vulnerability lists normally attach a finding to the affected package. Some graph views show ancestry without calculating how descendant risk contributes to the contextual profile of each parent.

### Proposed method

DepShield propagates a bounded contribution from a vulnerable descendant toward its ancestors. Contributions decay with graph distance and are adjusted by reachability, runtime scope, route exposure, and the number of observed paths.

### Inputs

- Dependency nodes and directed parent-child edges
- Child Final Priority
- Distance from child to ancestor
- Reachability classification
- Runtime/development scope
- Internet exposure evidence
- Number of distinct dependency paths

### Algorithm

For each descendant-to-ancestor path, the implementation uses the transparent form:

```text
path contribution = child priority
                  × distance decay
                  × reachability weight
                  × runtime weight
                  × exposure weight
                  × bounded path weight
```

The current model uses exponential distance decay and combines multiple contributions with a bounded-union calculation so the total cannot grow without limit. Own risk and inherited risk are then combined with the same bounded-union approach. Cycles and duplicate paths must be detected during traversal.

### Outputs

- Own Risk
- Inherited Dependency Risk
- Contextual Risk
- Per-descendant contribution, distance, and path count
- Human-readable propagation formula

### Technical benefit

The model preserves the reason a parent matters without copying the full child score to every node. It also exposes which descendant and which path produced each inherited contribution.

### Limitations

Graph proximity is not equivalent to runtime call flow. Path multiplicity may reflect lockfile structure rather than independent exploit opportunities. Decay and context weights are configurable heuristics and require sensitivity analysis on representative projects.

## 3. Conservative static reachability analysis

### Problem

The presence of a vulnerable dependency does not establish that application code imports it, that a public route can reach it, or that an affected API is called.

### Existing baseline

Manifest-only scanning establishes package presence and dependency ancestry. Full program analysis can provide stronger evidence but is expensive, language-specific, and often incomplete for dynamic JavaScript behavior.

### Proposed method

DepShield performs bounded static analysis of supplied JavaScript and TypeScript source files. It extracts supported `import`, `require`, and literal dynamic-import relationships, constructs an application module graph, identifies route entry points, and connects observed package usage to dependency instances. Optional curated vulnerable-API rules can add function-level evidence when a reliable mapping exists.

### Inputs

- Explicitly supplied JavaScript/TypeScript source files
- Relative file paths
- Package manifest and resolved lockfile graph
- Framework route patterns
- Static imports, requires, call expressions, and property accesses
- Curated package/CVE/API rules with evidence provenance

### Algorithm

The analyzer parses only bounded, supported source files and rejects traversal paths and oversized input. It builds file-to-file and file-to-package edges, starts traversal from recognized application or route entry points, and maps imported package names to resolved dependency instances. Results use four conservative classifications:

- `REACHABLE`
- `POSSIBLY_REACHABLE`
- `NOT_OBSERVED`
- `UNKNOWN`

`NOT_OBSERVED` means the bounded analysis found no supported path; it never means the dependency is safe.

### Outputs

- Reachability classification and confidence
- Entry files and importing modules
- Observed package APIs and curated vulnerable-API matches
- File/module/package paths
- Internet-exposure evidence
- Parser warnings, coverage statistics, and limitations

### Technical benefit

This converts package presence into application-specific evidence while retaining uncertainty. It also supplies reusable evidence for scoring, blast-radius estimation, remediation testing suggestions, and analyst answers.

### Limitations

Static JavaScript analysis cannot reliably resolve all dynamic imports, computed module names, reflection, runtime dependency injection, framework magic, generated code, aliases, or environment-specific branches. Package-internal call flow may remain unavailable when dependency source is not analyzed. Results are evidence estimates, not execution proofs.

## 4. Attack-path graph and blast-radius estimation

### Problem

A dependency path alone does not explain how an external input, application route, handler, module, vulnerable API, and CVE may relate to one another. Reviewers also need to understand which application areas could require testing or remediation.

### Existing baseline

Dependency trees show package ancestry, and call graphs show code relationships. Security dashboards frequently present these separately or terminate at the vulnerable package.

### Proposed method

DepShield creates an evidence-linked security graph whose nodes may represent users, public routes, backend handlers, application modules, direct dependencies, transitive dependencies, vulnerable functions, CVEs, databases, or external services. Blast radius is estimated from the unique routes, source modules, services, parent dependencies, and application areas connected to a finding.

### Inputs

- Dependency graph
- Static reachability paths
- Route and handler evidence
- Vulnerable-API observations
- Finding identifiers and severity
- Application-area metadata inferred from file and route structure

### Algorithm

Normalized nodes and typed edges are joined by stable evidence identifiers. Paths are filtered by reachability, severity, directness, internet exposure, and fix status. Shortest-path and highest-risk views select paths using edge count and contextual node risk. Blast-radius counts are calculated from unique evidence-backed entities rather than duplicated paths.

### Outputs

- Interactive attack-path graph
- Shortest and highest-risk path views
- Potentially affected route, module, service, dependency, and application-area counts
- Evidence paths supporting each estimate

### Technical benefit

The graph makes prioritization explainable across package, application, and vulnerability layers and provides a concrete testing scope after remediation.

### Limitations

The graph is derived from static and advisory evidence. An edge indicates an observed or inferred relationship, not successful attacker control. Blast radius is an estimate and may omit dynamically reached components or include code paths that are not executed in production.

## 5. Remediation Sandbox digital twin

### Problem

Developers often need to estimate the security benefit of an upgrade before modifying a real manifest or lockfile. Simple fixed-version advice does not show remaining findings, changed dependency paths, or expected posture improvement.

### Existing baseline

Upgrade recommendations commonly list a fixed version. Validation usually happens only after the real dependency files are modified and a new scan is run.

### Proposed method

DepShield creates a simulated dependency state for a selected upgrade. The real project remains unchanged. The current sandbox uses fixed-version thresholds recorded in the source scan, then recalculates finding counts, risk, project score, reachable critical findings, stored attack paths, posture, summaries, and semver-based compatibility estimates. It does not query or resolve the target package version, so every result remains explicitly hypothetical until an actual upgrade and rescan.

### Inputs

- Current scan snapshot
- Selected dependency instance
- Current and proposed versions
- Normalized vulnerable ranges and fixed versions
- Dependency graph and attack paths
- Contextual score factors
- Compatibility evidence

### Algorithm

The deterministic mode clones the scan model, substitutes the proposed version, removes only findings whose recorded fix/range evidence supports removal, recalculates dependent metrics, and records all assumptions. A fuller local mode may resolve a temporary lockfile with lifecycle scripts disabled; it must never modify the supplied workspace. When target-version evidence is incomplete, the result is marked partial instead of assuming all vulnerabilities disappear.

### Outputs

- Current versus simulated project score
- Risk before and after
- CVEs predicted removed and remaining
- Critical finding change
- Attack paths predicted removed
- Compatibility estimate and uncertainty
- Explicit `simulated: true` marker

### Technical benefit

The sandbox joins remediation planning with measurable expected security impact while keeping the user’s actual project unchanged.

### Limitations

A version substitution cannot always predict a newly resolved transitive graph. Registry metadata can change or be unavailable. Conditional dependencies, platform resolution, peer conflicts, and runtime behavior may differ from the simulation. Only a real upgrade, build, test, and rescan can validate the result.

## 6. Upgrade compatibility prediction

### Problem

The safest vulnerability fix from a security perspective may still break application behavior. Developers need an early estimate of change risk and a focused test plan.

### Existing baseline

Semantic-version classification identifies patch, minor, and major changes, but does not incorporate how a particular application imports the package or which routes depend on it.

### Proposed method

DepShield estimates compatibility risk by combining semantic-version distance with application usage, dependency role, route exposure, parent relationships, known conflicts, and optional release metadata.

### Inputs

- Current and proposed versions
- Patch/minor/major classification
- Direct or transitive status
- Imported APIs and vulnerable functions
- Related routes and modules
- Parent packages and peer constraints
- Release/change metadata when available

### Algorithm

A deterministic scoring model assigns a base cost by version class and adds bounded contributions for direct usage, imported API count, route coupling, parent updates, and detected conflicts. Evidence can reduce uncertainty but does not turn the estimate into a guarantee. The numerical score maps to `LOW`, `MEDIUM`, `HIGH`, or `UNKNOWN`.

### Outputs

- Estimated compatibility-risk level and score
- Reasons for the estimate
- Imported APIs involved
- Suggested tests for affected routes/modules
- Current and target versions

### Technical benefit

The output helps balance security urgency against engineering effort and makes remediation plans more actionable than a version number alone.

### Limitations

Semantic versioning is not always followed. Release notes can be incomplete, and API compatibility does not guarantee behavioral compatibility. The predictor does not replace compilation, integration tests, runtime tests, or manual review.

## 7. Security Confidence score

### Problem

Risk data can be incomplete or contradictory. A high score based on one weak advisory is materially different from a high score supported by multiple agreeing sources and an observed application path.

### Existing baseline

Many dashboards display severity without a separate indication of evidence completeness or source agreement.

### Proposed method

DepShield calculates Confidence independently from risk. Confidence measures the completeness and agreement of the evidence used to form a finding, not the likelihood that an attack succeeds.

### Inputs

- Reported CVSS availability
- Exact installed version
- Known dependency path
- Completed reachability assessment
- Established fix status
- Exploit-evidence assessment
- Agreement across vulnerability sources
- Provider failures and incomplete analysis warnings

### Algorithm

Each evidence-quality property contributes a documented number of confidence points. Unknown values contribute zero confidence rather than being converted into negative risk. Contradictory sources prevent source-agreement credit. The total is clamped to 0–100 and grouped into low, medium, or high confidence.

### Outputs

- Confidence percentage and band
- Per-factor confidence explanation
- Source coverage and warning indicators
- Clear distinction between “high risk, low confidence” and “high risk, high confidence”

### Technical benefit

Reviewers can prioritize both remediation and evidence collection. The score prevents missing data from being presented as certainty.

### Limitations

Confidence measures evidence coverage, not evidence truth. Multiple databases may repeat the same upstream record and therefore are not always independent corroboration. Weighting requires validation against expert assessments.

## 8. Structured before/after security validation

### Problem

Count-only comparisons can hide which findings changed, whether a critical issue returned, and whether an upgrade removed an application-reachable path.

### Existing baseline

Basic before/after views compare total vulnerabilities, severity counts, or a top-level security score.

### Proposed method

DepShield creates a structured security diff using stable identities for dependency instances, canonical vulnerability identifiers, and attack paths. It records removed, introduced, changed, upgraded, downgraded, and unchanged evidence.

### Inputs

- Two persisted scans of the same project
- Dependency identities and versions
- Canonical CVE/GHSA mappings
- Risk, severity, range, fix, and provenance fields
- Reachability and attack-path identities
- Earlier project history for regression detection

### Algorithm

Versions are removed from normalized dependency path identities so ordinary upgrades can be matched across scans. Findings are keyed by dependency identity plus canonical vulnerability identifier. Matching findings are compared field by field. Attack paths use stable node/finding identities. An anomaly layer applies configurable thresholds for dependency surges, critical increases, score drops, high-risk additions, graph expansion, new attack paths, and previously observed findings returning.

### Outputs

- Removed, introduced, changed, and unchanged findings
- Dependency version changes
- Attack paths removed and added
- Score and reachable-critical changes
- Evidence-backed regression alerts

### Technical benefit

The system can test the claim that a remediation reduced security risk rather than merely showing that package versions changed.

### Limitations

Stable identity matching is difficult when dependency paths are reorganized or packages are renamed. Changes in vulnerability databases between scans can appear as project regressions even when code did not change. Comparisons across different projects or scanner-model versions require caution.

## 9. Safe local Attack Replay validation

### Problem

Advisory data and static paths remain abstract during demonstrations. A controlled replay can show observable vulnerable behavior and confirm its disappearance after remediation without targeting a real system.

### Existing baseline

Security demonstrations may rely on generic exploit scripts, arbitrary targets, or destructive payloads, which are inappropriate for a dependency assessment product and unsafe for public deployment.

### Proposed method

DepShield uses a separate, intentionally vulnerable localhost-only fixture with a pinned historical package version, one fixed route, one fixed in-memory proof, and explicit cleanup. The replay API accepts no target, command, file path, arbitrary URL, or attacker-provided payload.

### Inputs

- Allowlisted fixture dependency and version
- Allowlisted CVE
- Fixed localhost route
- Fixed non-destructive in-memory test data
- Before and after scan snapshots

### Algorithm

The fixture binds to loopback, rejects non-local traffic, prepares a constant demonstration object, invokes the vulnerable behavior, records a temporary observable marker, removes that marker, and reports cleanup. After a manual version upgrade, the identical replay is repeated and compared.

### Outputs

- Dependency/CVE/version evidence
- Fixed replay stages
- Observable result and cleanup confirmation
- Before/after replay difference
- Remediation and rescan instructions

### Technical benefit

The replay links advisory evidence, dependency version, observable behavior, remediation, and verification in a controlled educational workflow.

### Limitations

One fixture does not generalize to arbitrary CVEs or production architectures. Observable behavior in a teaching application is not proof that the user’s application is exploitable. The fixture must remain local and disabled on public deployments.

## 10. Multi-source vulnerability provenance

### Problem

Vulnerability sources can use different identifiers, severity values, ranges, and fix metadata. Naive aggregation duplicates findings and hides disagreements or provider failure.

### Existing baseline

Scanners often present a merged advisory without preserving how each source contributed to the result.

### Proposed method

DepShield normalizes npm audit, OSV, and optional NVD/GitHub advisory records into canonical findings while retaining each source record, identifier mapping, retrieval time, status, and confidence.

### Inputs

- Provider advisory identifiers and aliases
- CVE/GHSA mappings
- CVSS vectors and severity metadata
- Affected ranges and fixed versions
- Publication/modification timestamps
- Provider status, retrieval time, and raw identifier mapping

### Algorithm

Normalized identifiers form equivalence groups across providers. A transitive grouping method merges all connected aliases rather than only the first matching pair. The merged finding retains the strongest reported evidence and all unique references while preserving per-provider provenance and disagreement. Provider failures remain explicit and do not terminate the entire scan.

### Outputs

- Deduplicated canonical finding
- Source checklist and retrieval timestamps
- Identifier aliases and references
- Reported versus estimated score metadata
- Provider status and source-agreement evidence

### Technical benefit

The finding remains traceable to its evidence, supports Confidence scoring, and degrades gracefully when an external service fails.

### Limitations

Alias mappings can be absent or wrong. Sources may not be independent because they can share upstream records. NVD product mapping is not always precise for npm packages. A merged record can still contain unresolved conflicts that require manual review.

## 11. Scan-grounded DepShield Analyst

### Problem

A generic chatbot can invent package versions, CVEs, dependency paths, and fixes. Security explanations need to remain constrained to the selected scan and should fail closed when evidence is missing.

### Existing baseline

Natural-language summaries are often generated from broad prompts or unstructured vulnerability text, with limited evidence enforcement.

### Proposed method

DepShield Analyst is an intent-aware evidence interface rather than an open-ended chatbot. It answers supported questions about ranking, fix priority, transitive parents, CVEs, scan changes, internet-facing evidence, sprint remediation, and dependency paths. A deterministic engine always remains available. An optional external model receives only a bounded structured evidence projection.

### Inputs

- Current persisted scan
- Optional comparison scan and project history
- Normalized dependencies, findings, scores, paths, reachability, remediation, and provenance
- User question classified into an allowlisted intent
- Exact allowlist of internal citations

### Algorithm

The deterministic layer retrieves matching scan objects and builds an answer with citations such as `[Dependency: name@version]`, `[CVE: CVE-…]`, `[Path: …]`, and `[Scan: #…]`. Unsupported questions return exactly `Not enough evidence in the current scan.` Requests for exploit generation, external targeting, or arbitrary commands are rejected.

When configured, Google Gemini receives normalized facts through its fixed server-side endpoint, not source-file contents, manifests, the API key, or the complete raw scan object. A backwards-compatible custom OpenAI-compatible provider can be used when Gemini is absent. Returned citations must exactly match the evidence allowlist. Output containing invented CVE identifiers, URLs, commands, unsafe instructions, or unknown citations is rejected, and the deterministic answer is used instead.

### Outputs

- Evidence-grounded natural-language answer
- Internal citation list
- Supported/unsupported status
- Deterministic, Gemini, or custom-provider marker
- Safe deterministic fallback

### Technical benefit

The analyst makes complex dependency evidence easier to explain while retaining traceability and remaining functional without AI credentials.

### Limitations

Citation validation prevents unknown identifiers but cannot formally prove that every sentence is a valid inference. External models remain probabilistic. Intent coverage is deliberately narrow, and unsupported questions may require new deterministic handlers. Sensitive deployments should review what normalized metadata is allowed to leave the environment.

## Combined research hypothesis

The potentially distinctive research direction is the closed evidence loop:

```text
inventory
→ normalized vulnerability provenance
→ application reachability
→ contextual and propagated risk
→ attack path and blast radius
→ remediation and compatibility estimate
→ simulated result
→ actual upgrade and rescan
→ structured security diff
→ safe replay evidence
→ grounded explanation
```

This loop attempts to connect detection, application context, remediation prediction, and post-remediation validation through shared evidence identifiers. Its technical value should be evaluated as a system, while prior-art analysis must also examine every component independently.

## Research limitations and recommended evaluation

The present system should be treated as an engineering prototype. A defensible research evaluation would require:

- A labelled corpus of real Node.js projects with expert-reviewed reachability
- Benchmarks for precision, recall, and `UNKNOWN`/`NOT_OBSERVED` calibration
- Sensitivity analysis for risk and propagation weights
- Comparisons with CVSS-only, manifest-only, and existing reachability-aware baselines
- Controlled studies of remediation ranking quality and developer effort
- Validation of compatibility estimates against real upgrade test failures
- Provider disagreement and outage experiments
- Reproducibility tests across scanner and vulnerability-database versions
- Security review of file upload, local replay, AI prompting, and evidence export boundaries
- Independent prior-art review across academic papers, standards, public products, and technical disclosures

Until such evaluation is completed, DepShield scores, attack paths, blast radius, compatibility risk, simulations, and AI explanations must remain clearly labelled as contextual estimates supported by the evidence available at scan time.

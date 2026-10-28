# Logic audit — 7 October 2026

## Verified and corrected

- Input: reject invalid dependency maps, non-lockfile JSON and missing required root dependencies instead of reporting a clean empty scan.
- Graph: bound path traversal and stop cyclic paths; retain direct/transitive evidence.
- Providers: reject malformed/truncated OSV batches; do not cache incomplete detail fetches as complete evidence.
- Failure semantics: if both vulnerability sources fail for a nonempty graph, return 503 without saving a 100/A scan. Both interactive and CI endpoints handle this.
- Version filtering: unsupported prerelease comparisons retain findings rather than falsely excluding them.
- Upgrade preview: partial contextual assessments no longer switch silently to the legacy risk formula.
- Regression suite covers parsing, graph paths, merging, scoring, policies, simulation, comparison, reachability, exports and API boundaries.
- Live API scan of the existing fixture manifests: npm audit and OSV succeeded; 70 packages, 5 vulnerable packages, score 77/C. Saved scan: e2009648-279b-491a-85e8-f0ea484efcf8. No dependency installation or project remediation was performed.

## Real capabilities versus limitations

Scanning uses real manifests, npm audit, OSV, and SQLite. Existing UI results are persisted scan data, not fabricated metrics. A successful scan means sources were queried, not that an application is secure.

Upgrade plans are advisory recommendations. Simulation does not install packages, run application tests, resolve the new dependency graph, or verify remediation. Actual before/after evidence requires applying upgrades to the project and uploading a fresh lockfile.

Attack Replay is intentionally limited to the separate local fixture. It cannot establish exploitability of uploaded applications. Static reachability and attack paths are estimates, not runtime traces. NVD and GitHub enrichment adapters are not implemented.

This is a targeted correctness audit, not an exhaustive production-security certification. Remaining review areas include full npm alias/workspace/peer semantics, OSV multi-branch fixes and withdrawn advisories, full SemVer/CVSS-version coverage, provider-wide deadlines, and deployment authentication/tenant isolation. Existing historical snapshots were not rewritten; rerun scans for current evidence.

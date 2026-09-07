# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary users are inferred from the supplied brief: Node.js developers and application-security engineers reviewing dependency exposure during development or remediation. A secondary audience is an interviewer or reviewer who needs the architecture and risk model to be easy to explain.

## Product Purpose

DepShield AI continuously assesses the security risk of a Node.js application's open-source dependency graph. It combines manifests, vulnerability intelligence, bounded application-source evidence, and remediation simulation into prioritized, explainable work and measurable before/after security posture.

## Positioning

DepShield AI is a context-aware open-source dependency risk intelligence and remediation platform. It joins dependency topology, vulnerability provenance, conservative static reachability, transparent contextual scoring, graph-aware propagation, compatibility estimates, and remediation comparison. Its scores are explicit DepShield heuristics—not industry standards—and unknown evidence lowers confidence rather than becoming a false claim of safety.

## Operating Context

Users provide `package.json` and `package-lock.json`, optionally add a bounded JS/TS source bundle, review direct and transitive dependencies, inspect CVEs and evidence-backed attack-path estimates, simulate an upgrade, remediate the project, then compare a later scan with the baseline. Attack Replay remains a separate localhost-only educational fixture.

## Capabilities and Constraints

- Next.js and TypeScript with a simple modular Node.js backend.
- Tailwind CSS, semantic shadcn-style primitives, Recharts, and React Flow.
- SQLite scan history.
- npm audit plus OSV enrichment; NVD remains optional.
- The legacy risk formula remains available for compatibility. New scans use versioned DepShield contextual technical, exploitability, exposure, remediation-difficulty, final-priority, and confidence scores with factor ledgers.
- A project security score out of 100 and an A–F grade summarize posture.
- Architecture and copy should remain beginner-friendly and interview-ready.

## Brand Commitments

The product name is “DepShield AI,” positioned as a “Context-Aware Open-Source Dependency Risk Intelligence and Remediation Platform.” The voice is precise, calm, transparent, and action-oriented. Security severity must never rely on color alone.

## Evidence on Hand

No production customer data, benchmarks, or brand assets were supplied. Every product metric must come from a live or persisted scan; simulated results and estimates must be labeled explicitly.

## Product Principles

- Explain every risk score.
- Turn findings into a clear next upgrade.
- Preserve the dependency graph, not just a flat CVE list.
- Make progress visible across scans.
- Prefer understandable architecture over abstraction.

## Accessibility & Inclusion

Use semantic landmarks, visible keyboard focus, adequate contrast, reduced-motion support, and text/icon labels in addition to severity colors.

# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary users are inferred from the supplied brief: Node.js developers and application-security engineers reviewing dependency exposure during development or remediation. A secondary audience is an interviewer or reviewer who needs the architecture and risk model to be easy to explain.

## Product Purpose

DepShield continuously assesses the security risk of a Node.js application's open-source dependency graph. It turns package manifests, npm audit output, and public vulnerability intelligence into prioritized remediation work and measurable before/after security posture.

## Positioning

DepShield joins dependency topology, vulnerability evidence, a transparent risk formula, and remediation comparison in one console. Every risk score remains explainable from CVSS, dependency depth, fix availability, and CVE count.

## Operating Context

Users provide `package.json` and `package-lock.json`, review direct and transitive dependencies, inspect CVEs and upgrade guidance, replay likely dependency attack paths, remediate the project, then compare a later scan with the baseline.

## Capabilities and Constraints

- Next.js and TypeScript with a simple modular Node.js backend.
- Tailwind CSS, semantic shadcn-style primitives, Recharts, and React Flow.
- SQLite scan history.
- npm audit plus OSV enrichment; NVD remains optional.
- Risk is `CVSS × 10`, `+5` when direct, `+5` when no fix exists or `-5` when a fix exists, plus `+2` for each additional CVE capped at `+10`, clamped to `0–100`.
- A project security score out of 100 and an A–F grade summarize posture.
- Architecture and copy should remain beginner-friendly and interview-ready.

## Brand Commitments

The product name is “DepShield – Dependency Risk Console.” The voice is precise, calm, transparent, and action-oriented. Security severity must never rely on color alone.

## Evidence on Hand

No production customer data, benchmarks, brand assets, or real scan history were supplied. Seeded demonstration data must be labeled as such and remain replaceable by a live scan.

## Product Principles

- Explain every risk score.
- Turn findings into a clear next upgrade.
- Preserve the dependency graph, not just a flat CVE list.
- Make progress visible across scans.
- Prefer understandable architecture over abstraction.

## Accessibility & Inclusion

Use semantic landmarks, visible keyboard focus, adequate contrast, reduced-motion support, and text/icon labels in addition to severity colors.

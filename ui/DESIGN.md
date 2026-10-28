---
name: Security System Layer
colors:
  canvas: '#000000'
  ink: '#ffffff'
  secondary: '#e6e6e6'
  label: '#949494'
  action: '#c81b1c'
  action-hover: '#b01617'
rounded:
  control: '0px'
---

## Overview
The homepage uses the supplied fullscreen visual reference, with real DepShield copy and saved-scan metrics. Native components live in `src/components/security`, rendered by `src/app/page.tsx`. Operational routes remain functional and use AppShell; `/dashboard` shows the latest scan and `/?scan=...` preserves existing result links. Never rewrite feature routes to the homepage. Backend APIs are unchanged.

## Typography
Embedded WOFF2 Space Grotesk is aliased SG; JetBrains Mono is aliased JB. The homepage text describes dependency scanning, CVEs, upgrades and comparisons rather than generic business claims.

## Layout
Homepage: black stage, left-locked headline, right-side CloudFront video atmosphere. Feature pages: scrollable operational console with navigation, evidence tables and real controls. Landing CSS is scoped to `.security-stage`. Small/zoomed screens reflow instead of indefinitely shrinking text.

## Components
Three synchronized video elements use the supplied LUT filters. One-shot WAAPI entrance obeys reduced motion and has a hard reveal timeout. Navigation has keyboard-operable disclosures; the mobile overlay traps focus and closes on Escape, navigation or desktop resize. A pause control is available for moving video.

## Do's and Don'ts
Do preserve the black/red visual direction. Keep product copy factual and statistics backed by SQLite. Every navigation item must reach a working feature. Preserve selected scan IDs across operational navigation. Do not reintroduce sample clients, revenue, placeholder action messages, or the old Three.js hero. No deployment is authorized by this local request.

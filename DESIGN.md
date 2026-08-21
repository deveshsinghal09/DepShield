---
name: DepShield Threat Ledger
description: Premium dark dependency-risk operations console.
colors:
  canvas: "#090B0F"
  rail: "#0C0F14"
  surface: "#11151C"
  surface-raised: "#171C24"
  ink: "#F3F0E8"
  muted-ink: "#9299A6"
  line: "#272D37"
  accent: "#E87B3E"
  danger: "#F05252"
  warning: "#E5A93D"
  safe: "#35A58A"
  unknown: "#737B88"
typography:
  display:
    fontFamily: "Manrope, Segoe UI, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(2rem, 4vw, 3.75rem)"
    fontWeight: 700
    lineHeight: 1
  body:
    fontFamily: "Manrope, Segoe UI, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 450
    lineHeight: 1.55
  data:
    fontFamily: "IBM Plex Mono, Cascadia Code, ui-monospace, monospace"
    fontSize: "0.75rem"
    fontWeight: 500
    lineHeight: 1.4
rounded:
  sm: "8px"
  md: "12px"
  lg: "16px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.canvas}"
    rounded: "{rounded.sm}"
    padding: "10px 16px"
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "20px"
---

# Design System: DepShield Threat Ledger

## Overview

**Creative North Star: “Threat Ledger”**

DepShield reads like a signed incident dossier built for engineers working under normal office or operations-room light. Carbon fields and graphite ledgers hold the evidence; warm ivory type stays humane; copper marks deliberate action. It refuses neon hacker theater and decorative glass while preserving the precision expected of a premium security product.

## Colors

Carbon and graphite own the page. Copper is the single interaction accent. Red, amber, and teal are state-only signals and always pair with text or icons.

**The Evidence Rule.** Color never implies severity without a written label, number, or icon.

## Typography

Manrope is the workhorse interface face. IBM Plex Mono is reserved for CVEs, versions, scores, timestamps, commands, and trace output. Headings use restrained negative tracking and never exceed 3.75rem.

## Layout

A 248px desktop rail frames a fluid 1480px workspace. Surfaces follow a 12-column grid and 24px desktop rhythm. The dashboard opens with a wide audit-verdict composition, not a row of generic hero cards. Dense tables own horizontal scrolling on small screens.

## Elevation & Depth

Depth comes from tonal layering first. Raised panels may use one low offset shadow; borders and shadows do not compete on the same surface.

## Shapes

Controls use 8px corners, panels 12px, and major verdict surfaces 16px. Pills remain exclusive to compact filters and status badges.

## Components

Reusable boundaries include AppShell, PageHeader, ScanButton, MetricStrip, SecurityScore, SeverityChart, RiskTrendChart, DependencyRiskTable, EmptyState, Skeleton, DependencyGraph, AttackReplayConsole, ComparisonPanel, and ScanHistoryTable. Stable `data-ui` attributes identify major refinement targets.

## Do's and Don'ts

- Do let real scan evidence drive every number.
- Do create designed empty, loading, warning, and error states.
- Do keep console styling confined to actual replay output.
- Don't use neon, ambient glow, gradient text, or decorative glass.
- Don't hardcode page-specific colors when a semantic token exists.

---
name: DepShield AI Signal Grid
description: A cyber-brutalist dependency-risk console built as an operational scan field.
colors:
  canvas: "#0A0A0A"
  rail: "#0D0D0D"
  surface: "#141414"
  surface-active: "#1A1A1A"
  ink: "#F5F5F0"
  muted-ink: "#8A8A85"
  line: "#343432"
  accent: "#D4FF00"
  danger: "#FF3B3B"
  warning: "#FFB020"
  unknown: "#73736E"
typography:
  scale:
    micro: "0.5625rem"
    hud: "0.625rem"
    caption: "0.6875rem"
    data: "0.75rem"
    body: "0.875rem"
    control: "1rem"
    title: "1.125rem"
    section: "1.5rem"
    verdict: "3rem"
    display: "6rem"
  display:
    fontFamily: "Archivo Variable, Arial Narrow, ui-sans-serif, sans-serif"
    fontSize: "clamp(3rem, 7vw, 6rem)"
    fontWeight: 900
    lineHeight: 0.86
    letterSpacing: "-0.04em"
  body:
    fontFamily: "Archivo Variable, Arial, ui-sans-serif, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 450
    lineHeight: 1.55
  data:
    fontFamily: "JetBrains Mono Variable, Cascadia Mono, ui-monospace, monospace"
    fontSize: "0.75rem"
    fontWeight: 500
    lineHeight: 1.45
    letterSpacing: "0.02em"
rounded:
  square: "0px"
  control: "2px"
  panel: "2px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  field: "48px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.canvas}"
    rounded: "{rounded.control}"
    padding: "10px 16px"
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "20px"
---

# Design System: DepShield AI Signal Grid

## Overview

**Creative North Star: “The Active Scan Field”**

DepShield looks like evidence moving through a controlled forensic instrument. The interface is raw, digital, systematic, and intentionally flat: every rule, index, reticle, and status mark explains structure or machine state. It rejects soft SaaS cards and theatrical hacker glow while retaining enough quiet space for dense security evidence.

The signature is a wireframe scan field that begins as a system-profile visualization and resolves into real dependency evidence. The hero may dramatize the mechanism; operational screens keep that language in registration marks, numbered sections, and compact telemetry.

**Key Characteristics:**

- Hard-edged modular grids and 1px evidence dividers.
- One sparse acid-green action signal against near-black surfaces.
- Heavy grotesque headlines paired with monospace machine data.
- Mechanical motion that stops for reduced-motion users.
- Severity always communicated with text or an icon in addition to color.

## Colors

Near-black fields provide the working surface; off-white carries reading hierarchy; acid green marks only actions, selected state, and verified progress. Red is exclusive to critical/high risk or failure, while amber represents medium severity and caution.

**The Signal Scarcity Rule.** Acid green should occupy less than ten percent of an operational viewport. Its rarity identifies the next action.

**The Evidence Rule.** Color never communicates security state without a written label, number, or icon.

## Typography

**Display Font:** Archivo Variable with Arial Narrow fallback

**Body Font:** Archivo Variable with Arial fallback
**Data Font:** JetBrains Mono Variable with Cascadia Mono fallback

Archivo provides a forceful engineering grotesque without making body copy feel like a terminal. JetBrains Mono is reserved for values, identifiers, versions, timestamps, paths, statuses, and compact technical labels.

- **Display:** weight 900, tightly tracked, hero statements only.
- **Headline:** weight 800, compact line height, page and score verdicts.
- **Title:** weight 700, sentence case for panels and controls.
- **Body:** weight 400–500, sentence case, approximately 68 characters per line.
- **Label:** monospace, 10–12px, uppercase only for machine state and section coordinates.

**The Case Discipline Rule.** All caps belongs to section coordinates and short system labels, never explanatory prose.

## Layout

A persistent desktop rail frames a fluid evidence workspace. Major views use a 12-column grid and indexed sections such as `/01`, `/02`, and `/03`. Dense tables may scroll horizontally, but surrounding content must never create viewport overflow. At 768px and below, panels stack and the static scan field simplifies without losing its silhouette or telemetry hierarchy.

Spacing follows an 8px base rhythm with 24–48px between major sections. Registration corners and micro-labels may identify panel bounds but cannot compete with content.

## Elevation & Depth

The system uses no gradients, glass, blur, or box shadows. Depth is encoded only through tonal fields, 1px borders, overlapping grid lines, and state changes.

**The Flat Instrument Rule.** A control may change fill or border on hover and focus; it never lifts off the canvas.

## Shapes

Panels and controls use square or 2px corners. Hairline borders create structure. Circular forms are reserved for true radial data, status pings, reticles, or icon geometry—not containers. Compact labels use rectangular tags rather than rounded pills.

## Components

### Buttons

- Primary actions use acid green with near-black text, a 2px radius, heavy label weight, and a directional arrow when navigation follows.
- Outline actions use the line color and switch to off-white or acid-green borders on interaction.
- Hover motion is a 150–220ms mechanical scanline or one-pixel registration shift; focus always has a visible outer ring.

### Cards / Containers

- Off-black surface, 1px line border, 0–2px corners, and no shadow.
- Headers use a bottom divider and optional indexed micro-label.
- Metric containers prioritize one large value over decorative icon tiles.

### Inputs / Fields

- Near-black fill, 1px border, 2px corners, and explicit label.
- Focus changes the border to acid green and adds a visible two-pixel outline.
- Errors show a red monospace code plus a plain-language recovery message inline.

### Navigation

- Indexed links sit in the dark rail with thin Lucide icons.
- Active state uses an acid-green left rule, coordinate label, and off-white text.
- Mobile navigation keeps the same ordering inside a hard-edged sheet.

### Scan Field

- The hero uses a locally hosted, attributed human head mesh sampled into 18,000 WebGL points, a subtle wireframe, and a dissolving edge. Never substitute a screenshot for this scene.
- Slow rotation and pointer response respect reduced motion and a visible pause control. Dispose GPU resources on unmount and show a useful fallback if WebGL fails.
- The desktop composition combines a narrow navigation rail, hero, and real saved-scan evidence. On mobile, the human scene stacks below the copy and controls.
- Display headlines use the bundled Anton font so typography is consistent across operating systems. Keep operational pages concise; advanced evidence belongs on dedicated detail pages.

## Do's and Don'ts

### Do:

- **Do** let persisted scan evidence drive every metric, timestamp, path, and status.
- **Do** use numbered sections and registration marks to clarify information architecture.
- **Do** keep Attack Replay’s localhost-only and production-disabled warnings visible beside its action.
- **Do** preserve stable `data-ui` hooks on operational regions.

### Don't:

- **Don't** use gradients, glassmorphism, ambient glow, or decorative shadows.
- **Don't** soften the system with large radii, bubbly chips, or generic SaaS icon cards.
- **Don't** animate essential content or ignore `prefers-reduced-motion`.
- **Don't** invent scan data, security claims, or provider status for visual effect.

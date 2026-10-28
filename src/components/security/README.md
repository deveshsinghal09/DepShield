# Active DepShield UI

The approved black/red video design is now native Next.js/React, not an iframe or an HTML injection.

- `security-landing.tsx`: composition, menu state and video lifecycle.
- `navigation.tsx`: desktop navigation and mobile accordion overlay.
- `hero.tsx`: dependency-security headline, scan action and persisted scan summary.
- `primitives.tsx`: reusable buttons, arrows and logo.
- `video-background.tsx` / `video-grade.json`: synchronized video plates and exact reference LUTs.
- `use-stage-motion.ts`: one-shot entrance; cleans up animations and listeners.
- `security.css`: approved reference tokens and responsive layout.
- `content.ts`: feature destinations, navigation labels and video URL.

Add new React components to the composition in `SecurityLanding`. Navigation opens the real scanner, dashboard, dependency analysis, upgrades, replay, comparison, policies and history. Homepage metrics come from SQLite; there are no sample business claims.

`src/app/page.tsx` renders this homepage. `/dashboard` renders the latest saved scan; existing `/?scan=...` result links remain supported. Feature pages use AppShell and their original backend integrations. Landing styles are scoped to `.security-stage` so they cannot hide or restyle operational pages. `/welcome` redirects home. Do not add catch-all feature rewrites.

The original standalone `public/index.html` is retained as a reference export. It is no longer the active app. Edit the React components above for future UI work; do not rerun the one-time asset migration over customized styles.

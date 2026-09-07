"use client";

import { useEffect, useState } from "react";
import { Clock3, GitBranch, PackageSearch } from "lucide-react";
import type { Scan } from "@/lib/types";
import { GradeBadge } from "./grade-badge";

export function ScanOverviewHeader({ scan }: { scan: Scan }) {
  const [score, setScore] = useState(0);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      const reducedFrame = requestAnimationFrame(() => setScore(scan.score));
      return () => cancelAnimationFrame(reducedFrame);
    }
    const started = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const progress = Math.min(1, (now - started) / 720);
      const eased = 1 - Math.pow(1 - progress, 4);
      setScore(Math.round(scan.score * eased));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [scan.id, scan.score]);

  return (
    <section className="surface surface-outline grid gap-px bg-border lg:grid-cols-[minmax(260px,1fr)_auto_auto_auto]" data-ui="security-score">
      <div className="bg-card p-5 sm:p-6">
        <span className="hud-label text-primary">{"// ACTIVE SNAPSHOT"}</span>
        <h2 className="mt-3 text-2xl font-black tracking-[-.03em]">{scan.project}</h2>
        <div className="data mt-4 flex flex-wrap gap-x-5 gap-y-2 text-[10px] text-muted-foreground">
          <span className="flex items-center gap-1.5"><GitBranch size={12} />{scan.branch || "branch unavailable"}</span>
          <span className="flex items-center gap-1.5"><PackageSearch size={12} />{scan.dependencies} packages</span>
          <span className="flex items-center gap-1.5"><Clock3 size={12} />{formatTimestamp(scan.createdAt)}</span>
        </div>
      </div>
      <div className="flex min-w-40 items-center justify-between gap-5 bg-card p-5 sm:p-6 lg:block">
        <span className="hud-label">Security grade</span>
        <div className="lg:mt-4"><GradeBadge grade={scan.grade} large /></div>
      </div>
      <div className="flex min-w-48 items-end justify-between gap-4 bg-card p-5 sm:p-6 lg:block">
        <span className="hud-label">Security score</span>
        <div className="lg:mt-4"><b className="data text-6xl font-black tracking-[-.04em]">{score}</b><span className="data ml-2 text-sm text-muted-foreground">/100</span></div>
      </div>
      <div className="flex min-w-44 items-center justify-between gap-4 bg-background p-5 sm:p-6 lg:block">
        <span className="hud-label">Scan ID</span>
        <span className="data mt-0 block max-w-44 truncate text-xs text-primary lg:mt-4">{scan.id}</span>
        <span className="data mt-2 hidden text-[10px] text-muted-foreground lg:block">DURATION {scan.duration}s</span>
      </div>
    </section>
  );
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC", hour12: false }).format(new Date(value)) + " UTC";
}

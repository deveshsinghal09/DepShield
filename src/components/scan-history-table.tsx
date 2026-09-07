"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { ArrowUpRight, GitCompareArrows } from "lucide-react";
import type { Scan } from "@/lib/types";
import { severityCounts } from "@/lib/scan-selectors";
import { GradeBadge } from "./grade-badge";
import { Button } from "./ui/button";

export function ScanHistoryTable({ scans }: { scans: Scan[] }) {
  const router = useRouter();
  const [selected, setSelected] = useState<string[]>([]);

  function toggle(id: string) {
    setSelected((values) => values.includes(id)
      ? values.filter((value) => value !== id)
      : values.length < 2
        ? [...values, id]
        : [values[1], id]);
  }

  function compare() {
    if (selected.length === 2) {
      const ordered = selected
        .map((id) => scans.find((scan) => scan.id === id))
        .filter((scan): scan is Scan => Boolean(scan))
        .toSorted((left, right) => new Date(left.createdAt).getTime() - new Date(right.createdAt).getTime());
      if (ordered.length !== 2) return;
      router.push(`/comparison?before=${encodeURIComponent(ordered[0].id)}&after=${encodeURIComponent(ordered[1].id)}`);
    }
  }

  return (
    <section className="surface surface-outline" data-ui="scan-history">
      <header className="flex flex-col justify-between gap-4 border-b p-5 sm:flex-row sm:items-center">
        <div>
          <h2 className="font-semibold">Saved scans</h2>
          <p className="mt-1 text-xs text-muted-foreground" aria-live="polite">
            {selected.length}/2 snapshots selected · open any row to inspect its saved evidence.
          </p>
        </div>
        <Button variant="outline" disabled={selected.length !== 2} onClick={compare}>
          <GitCompareArrows size={15} />Compare selected
        </Button>
      </header>

      <div className="scrollbar overflow-x-auto">
        <table className="console-table w-full min-w-[980px] border-collapse text-left">
          <caption className="sr-only">Saved dependency security scans</caption>
          <thead>
            <tr className="border-b bg-background text-[10px] uppercase tracking-[.08em] text-muted-foreground">
              <th className="w-14 px-4 py-3"><span className="sr-only">Select for comparison</span></th>
              <th className="px-4 py-3 font-semibold">Timestamp</th>
              <th className="px-4 py-3 font-semibold">Project</th>
              <th className="px-4 py-3 text-right font-semibold">Score</th>
              <th className="px-4 py-3 font-semibold">Grade</th>
              <th className="px-4 py-3 text-right font-semibold">Critical</th>
              <th className="px-4 py-3 text-right font-semibold">High</th>
              <th className="px-4 py-3 text-right font-semibold">Medium</th>
              <th className="px-4 py-3 font-semibold">Coverage</th>
              <th className="w-14 px-4 py-3"><span className="sr-only">Open scan</span></th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan, index) => {
              const counts = severityCounts(scan);
              const href = `/?scan=${encodeURIComponent(scan.id)}`;
              const incomplete = Boolean(scan.warnings?.length || scan.sourceStatus?.some((source) => source.status === "failed" || source.status === "partial"));

              return (
                <tr key={scan.id} className="group border-b last:border-0 hover:bg-secondary/55">
                  <td className="px-4 py-4">
                    <input
                      type="checkbox"
                      checked={selected.includes(scan.id)}
                      onChange={() => toggle(scan.id)}
                      aria-label={`Select ${scan.project} scan from ${formatTimestamp(scan.createdAt)} for comparison`}
                      className="size-4 rounded-none border border-input accent-primary"
                    />
                  </td>
                  <td><ScanLink href={href}><span className="data text-xs text-muted-foreground">/{String(index + 1).padStart(2, "0")}</span><span className="data mt-1 block text-xs">{formatTimestamp(scan.createdAt)}</span></ScanLink></td>
                  <th scope="row"><ScanLink href={href}><span className="font-bold group-hover:text-primary">{scan.project}</span><span className="data mt-1 block max-w-52 truncate text-[11px] font-normal text-muted-foreground">{scan.branch || "branch unavailable"}</span></ScanLink></th>
                  <td><ScanLink href={href} className="text-right"><span className="data text-xl font-bold">{scan.score}</span><span className="text-xs text-muted-foreground">/100</span></ScanLink></td>
                  <td><ScanLink href={href}><GradeBadge grade={scan.grade} /></ScanLink></td>
                  <td><ScanLink href={href} className="data text-right font-bold text-critical">{counts.critical}</ScanLink></td>
                  <td><ScanLink href={href} className="data text-right font-bold text-high">{counts.high}</ScanLink></td>
                  <td><ScanLink href={href} className="data text-right font-bold text-medium">{counts.medium}</ScanLink></td>
                  <td><ScanLink href={href}><span className={`data inline-flex border px-2 py-1 text-[10px] uppercase ${incomplete ? "border-warning/50 text-warning" : "border-safe/40 text-safe"}`}>{incomplete ? "Partial evidence" : "Complete"}</span></ScanLink></td>
                  <td><ScanLink href={href} className="text-primary"><ArrowUpRight size={16} aria-hidden="true" /><span className="sr-only">Open {scan.project} scan</span></ScanLink></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ScanLink({ href, className = "", children }: { href: string; className?: string; children: ReactNode }) {
  return <Link href={href} className={`block min-h-14 px-4 py-4 ${className}`}>{children}</Link>;
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
    hour12: false,
  }).format(new Date(value)) + " UTC";
}

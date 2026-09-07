"use client";

import Link from "next/link";
import { useState } from "react";
import { ArrowRight, BrainCircuit, CheckCircle2, ListChecks } from "lucide-react";
import type { Scan, UpgradePlanItem } from "@/lib/types";
import { requestFixExplanation } from "@/lib/analyst-events";
import { generateUpgradePlan } from "@/lib/remediation";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

export function UpgradePlan({ scan }: { scan: Scan }) {
  const [generated, setGenerated] = useState(false);
  const plan = generated ? generateUpgradePlan(scan.items) : [];

  return (
    <section className="surface surface-outline" data-ui="upgrade-plan">
      <div className="flex flex-col justify-between gap-4 border-b p-5 sm:flex-row sm:items-center">
        <div>
          <span className="hud-label text-primary">/05 // REMEDIATION QUEUE</span>
          <h2 className="mt-2 font-extrabold">Upgrade plan</h2>
          <p className="mt-1 text-xs text-muted-foreground">Contextual risk dominates priority; lower estimated effort breaks ties.</p>
        </div>
        <Button variant="outline" onClick={() => setGenerated(true)} disabled={generated}>
          <ListChecks size={15} />{generated ? "Plan generated" : "Generate Upgrade Plan"}
        </Button>
      </div>
      {generated ? (
        plan.length ? (
          <ol>
            {plan.slice(0, 8).map((item, index) => (
              <li
                key={`${item.dependency.name}-${item.dependency.path}`}
                className={`grid gap-3 border-b px-5 py-4 last:border-b-0 sm:grid-cols-[3rem_minmax(0,1fr)_auto] sm:items-center ${classificationRail(item.classification)}`}
              >
                <span className="data text-xl font-bold text-muted-foreground">/{String(index + 1).padStart(2, "0")}</span>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Link
                      className="font-semibold hover:text-primary"
                      href={`/dependencies/${encodeURIComponent(item.dependency.name)}?scan=${scan.id}&version=${item.dependency.version}&path=${encodeURIComponent(item.dependency.path)}`}
                    >
                      {item.dependency.name}
                    </Link>
                    <Badge tone={item.classification === "NO FIX" ? "critical" : item.classification === "MAJOR UPGRADE" || item.classification === "MANUAL REVIEW" ? "medium" : "neutral"}>
                      {item.classification ?? item.label}
                    </Badge>
                  </div>
                  <p className="data mt-1 truncate text-xs text-muted-foreground">{planAction(item)}</p>
                </div>
                <div className="flex flex-wrap items-center gap-3 sm:justify-end">
                  <button
                    type="button"
                    data-ui="explain-fix"
                    className="inline-flex h-8 items-center gap-1.5 rounded-[2px] border border-primary/40 px-2.5 text-xs font-semibold text-primary hover:bg-primary/10"
                    onClick={() => requestFixExplanation({
                      name: item.dependency.name,
                      version: item.dependency.version,
                      targetVersion: item.targetVersion ?? undefined,
                    })}
                  >
                    <BrainCircuit size={13} />Explain this fix
                  </button>
                  <div className="text-right">
                    <span className={`data block text-sm font-bold ${item.dependency.risk >= 80 ? "text-destructive" : "text-warning"}`}>
                      risk {item.dependency.risk}
                    </span>
                    <span className="mt-1 block text-xs text-muted-foreground">estimated −{item.expectedRiskReduction ?? 0}</span>
                  </div>
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <div className="flex items-center gap-3 p-5 text-sm text-muted-foreground">
            <CheckCircle2 className="text-safe" size={18} />No vulnerable dependencies require a plan.
          </div>
        )
      ) : (
        <div className="flex items-center justify-between gap-4 p-5 text-sm text-muted-foreground">
          <p>Generate a deterministic remediation queue from the current scan evidence.</p>
          <ArrowRight className="shrink-0 text-primary" size={17} />
        </div>
      )}
    </section>
  );
}

export const UpgradePlanList = UpgradePlan;

function classificationRail(classification?: UpgradePlanItem["classification"]) {
  if (classification === "NO FIX") return "severity-rail-critical";
  if (classification === "MAJOR UPGRADE" || classification === "MANUAL REVIEW") return "severity-rail-high";
  if (classification === "MINOR UPGRADE" || classification === "UPDATE PARENT") return "severity-rail-medium";
  return "severity-rail-safe";
}

function planAction(item: UpgradePlanItem) {
  if (item.targetVersion) return `${item.dependency.version} → ${item.targetVersion}`;
  if (item.classification === "UPDATE PARENT") {
    return `Review ${item.dependency.parentPackages?.join(", ") || "introducing parent"}; do not pin the child in isolation`;
  }
  if (item.classification === "MANUAL REVIEW") return "Partial remediation evidence; review remaining findings";
  return "No reported complete fix · isolate, replace, remove, or accept with controls";
}

import Link from "next/link";
import { ArrowRight, CheckCircle2 } from "lucide-react";
import type { Scan } from "@/lib/types";
import { cveCount, fixableCount } from "@/lib/scan-selectors";

export function RemediationSummary({ scan }: { scan: Scan }) {
  const fixable = fixableCount(scan);
  const total = cveCount(scan);
  const percent = scan.fixableRiskPercent ?? (total ? Math.round(fixable / total * 100) : 100);
  const items = scan.items
    .filter((item) => item.recommendation === "upgrade")
    .toSorted((left, right) => right.risk - left.risk)
    .slice(0, 4);

  return (
    <section className="surface surface-outline" data-ui="remediation-summary">
      <div className="border-b p-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-bold">Remediation summary</h2>
            <p className="mt-1 text-xs text-muted-foreground">Reported targets ordered by contextual risk leverage</p>
          </div>
          <span className="data text-2xl text-primary">{percent}%</span>
        </div>
        <div className="mt-4 h-1.5 overflow-hidden bg-secondary">
          <div className="h-full bg-primary" style={{ width: `${percent}%` }} />
        </div>
      </div>
      {items.length ? (
        <div>
          {items.map((item) => {
            const query = new URLSearchParams({ scan: scan.id, version: item.version, path: item.path });
            return (
              <Link
                key={`${item.name}@${item.version}-${item.path}`}
                href={`/dependencies/${encodeURIComponent(item.name)}?${query}`}
                className="flex items-center justify-between gap-4 border-b px-5 py-3 last:border-0 hover:bg-secondary/50"
              >
                <div className="min-w-0">
                  <b className="truncate text-xs">Review upgrade for {item.name}</b>
                  <span className="data mt-1 block text-xs text-muted-foreground">{item.version} → {item.latest}</span>
                </div>
                <span className="data text-xs text-warning">up to −{item.risk}</span>
              </Link>
            );
          })}
        </div>
      ) : (
        <div className="flex items-center gap-3 p-5 text-sm text-muted-foreground">
          <CheckCircle2 size={18} className="text-safe" />No complete reported-fix upgrades found.
        </div>
      )}
      <Link href={`/remediation?scan=${scan.id}`} className="flex items-center justify-between border-t px-5 py-4 text-xs font-semibold text-primary">
        Open remediation lab <ArrowRight size={14} />
      </Link>
    </section>
  );
}

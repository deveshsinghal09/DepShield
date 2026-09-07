import Link from "next/link";
import { GitBranch, Route } from "lucide-react";
import { orderAttackPathCandidates, resolveAttackPathCandidates } from "@/lib/attack-path-view";
import type { Scan } from "@/lib/types";

export function TopAttackPaths({ scan }: { scan: Scan }) {
  const items = orderAttackPathCandidates(
    resolveAttackPathCandidates(scan.attackPaths ?? [], scan.items),
    "highest",
  ).slice(0, 4);

  return (
    <section className="surface surface-outline" data-ui="top-attack-paths">
      <header className="flex items-start justify-between border-b px-5 py-4">
        <div>
          <h2 className="text-sm font-bold">Top attack paths</h2>
          <p className="mt-1 text-xs text-muted-foreground">Highest propagated risk across persisted CVE-specific paths</p>
        </div>
        <GitBranch className="text-primary" size={17} />
      </header>
      {items.length ? (
        <ol className="divide-y">
          {items.map(({ path, dependency, propagatedRisk }) => (
            <li key={path.id} className="p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <b className="data text-sm">{path.findingId}</b>
                  <p className="mt-1 text-xs font-semibold">{dependency.name}@{dependency.version}</p>
                  <p className="data mt-2 truncate text-xs text-muted-foreground">{path.display}</p>
                </div>
                <div className="shrink-0 text-right" data-ui="propagation-evidence">
                  <span className={`data block text-lg font-bold ${propagatedRisk >= 80 ? "text-destructive" : "text-warning"}`}>
                    {propagatedRisk}
                  </span>
                  <span className="text-xs text-muted-foreground">propagated risk</span>
                  <span className="data mt-1 block text-xs text-muted-foreground">base {dependency.risk}</span>
                </div>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted-foreground">
                <span className="flex items-center gap-2"><Route size={13} />{path.internetExposed ? "Internet-exposed route hint" : "No public route hint"}</span>
                <span>{path.nodes.length} persisted nodes · {path.confidence}% confidence</span>
              </div>
            </li>
          ))}
        </ol>
      ) : (
        <p className="p-5 text-sm leading-6 text-muted-foreground">
          No CVE-specific attack path was persisted for this scan. Run a project-folder scan to add bounded source and lockfile evidence.
        </p>
      )}
      <Link href={`/attack-paths?scan=${scan.id}`} className="flex items-center justify-between border-t px-5 py-4 text-xs font-semibold text-primary">
        Explore all attack paths <span aria-hidden="true">→</span>
      </Link>
    </section>
  );
}

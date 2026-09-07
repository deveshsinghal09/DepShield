import Link from "next/link";
import { ArrowRight, CheckCircle2, FlaskConical, ShieldAlert } from "lucide-react";
import type { Dependency, ReachabilityStatus, Scan } from "@/lib/types";
import { Badge } from "./ui/badge";
import { SeverityBadge } from "./severity";

function detailHref(scan: Scan, dependency: Dependency, simulate = false) {
  if (simulate) return `/remediation?scan=${encodeURIComponent(scan.id)}`;
  const query = new URLSearchParams({ scan: scan.id, version: dependency.version, path: dependency.path });
  return `/dependencies/${encodeURIComponent(dependency.name)}?${query}`;
}

function reachabilityLabel(status: ReachabilityStatus | undefined) {
  if (status === "REACHABLE") return "Reachable";
  if (status === "POSSIBLY_REACHABLE") return "Possibly reachable";
  if (status === "NOT_OBSERVED") return "Not observed statically";
  return "Reachability unknown";
}

function difficulty(dependency: Dependency) {
  if (dependency.contextual) return dependency.contextual.remediationDifficulty;
  if (dependency.compatibility) return dependency.compatibility.score;
  if (dependency.recommendation === "no-fix") return 95;
  if (!dependency.direct) return 60;
  return dependency.latest === dependency.version ? 85 : 25;
}

export function CriticalAction({ scan }: { scan: Scan }) {
  const dependency = scan.items.filter(item => item.vulnerabilities.length > 0).toSorted((a, b) => (b.contextual?.finalPriority ?? b.risk) - (a.contextual?.finalPriority ?? a.risk))[0];
  if (!dependency) return <section className="surface surface-outline flex min-h-48 items-center gap-4 p-6" data-ui="critical-action" data-state="clear"><span className="grid size-11 shrink-0 place-items-center border border-safe/40 text-safe"><CheckCircle2 aria-hidden="true" size={20}/></span><div><h2 className="font-bold">No critical action identified</h2><p className="mt-1 text-sm text-muted-foreground">This scan has no dependency with a known vulnerability.</p></div></section>;

  const priority = dependency.contextual?.finalPriority ?? dependency.risk;
  const highest = dependency.vulnerabilities.toSorted((a, b) => b.cvss - a.cvss)[0];
  const fixAvailable = dependency.vulnerabilities.some(vulnerability => Boolean(vulnerability.fixedVersion)) && dependency.latest !== dependency.version;
  const remediationDifficulty = difficulty(dependency), reachable = dependency.reachability?.status;
  return <section className="surface surface-outline overflow-hidden" data-ui="critical-action" data-state={priority >= 80 ? "critical" : "review"}>
    <header className="flex items-center justify-between gap-4 border-b px-5 py-4"><div><h2 className="text-sm font-bold">{priority >= 80 ? "Critical action required" : "Highest-priority action"}</h2><p className="mt-1 text-xs text-muted-foreground">The strongest combination of risk, evidence, and remediation leverage</p></div><ShieldAlert aria-hidden="true" className={priority >= 80 ? "text-destructive" : "text-warning"} size={18}/></header>
    <div className="grid gap-5 p-5 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2"><Link className="text-lg font-bold tracking-[-.02em] hover:text-primary" href={detailHref(scan, dependency)}>{dependency.name}@{dependency.version}</Link><SeverityBadge severity={highest.severity}/><Badge tone={reachable === "REACHABLE" ? "critical" : reachable === "POSSIBLY_REACHABLE" ? "medium" : "neutral"}>{reachabilityLabel(reachable)}</Badge></div>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">{highest.summary}</p>
        <dl className="mt-4 grid gap-3 sm:grid-cols-4">
          <Datum label={dependency.contextual ? "Final priority" : "Legacy risk"} value={`${priority}/100`} emphasis/>
          <Datum label="Highest CVSS" value={highest.cvssAvailable === false ? "Unavailable" : highest.cvss.toFixed(1)}/>
          <Datum label="Fix" value={fixAvailable ? `Review ${dependency.latest}` : "No reported complete fix"}/>
          <Datum label="Upgrade difficulty" value={`${remediationDifficulty}/100 · estimated`}/>
        </dl>
      </div>
      <div className="flex flex-col gap-2 sm:flex-row md:flex-col">
        <Link className="inline-flex h-10 items-center justify-center gap-2 rounded-sm bg-primary px-4 text-sm font-semibold text-primary-foreground hover:brightness-110" href={detailHref(scan, dependency)}>Investigate <ArrowRight aria-hidden="true" size={15}/></Link>
        {fixAvailable ? <Link className="inline-flex h-10 items-center justify-center gap-2 rounded-sm border px-4 text-sm font-semibold hover:bg-secondary" href={detailHref(scan, dependency, true)}><FlaskConical aria-hidden="true" size={15}/>Simulate upgrade</Link> : <span className="px-2 py-1 text-center text-xs text-muted-foreground">Manual review required</span>}
      </div>
    </div>
    <p className="border-t px-5 py-3 text-xs leading-5 text-muted-foreground">Reachability is conservative static evidence. “Not observed” never means the dependency is proven safe.</p>
  </section>;
}

function Datum({ label, value, emphasis = false }: { label: string; value: string; emphasis?: boolean }) {
  return <div><dt className="text-xs text-muted-foreground">{label}</dt><dd className={`data mt-1 break-words text-xs font-semibold ${emphasis ? "text-warning" : "text-foreground"}`}>{value}</dd></div>;
}

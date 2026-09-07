import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Beaker, ExternalLink, GitBranch, Radar, ShieldAlert, Wrench } from "lucide-react";
import { resolveSavedScan } from "@/server/scan-resolution";
import { EmptyState, SavedScanUnavailable } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/severity";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DependencyGraph } from "@/components/dependency-graph";
import { WhyScore } from "@/components/why-score";
import { remediationLabel } from "@/lib/remediation";
import type { Dependency } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function DependencyDetail({ params, searchParams }: { params: Promise<{ name: string }>; searchParams: Promise<{ scan?: string; version?: string; path?: string }> }) {
  const [{ name }, query] = await Promise.all([params, searchParams]);
  const { resolution } = resolveSavedScan(query.scan);
  if (resolution.status === "missing") return <SavedScanUnavailable scanId={resolution.requestedId} recoveryHref="/dependencies" />;
  const scan = resolution.scan;
  if (!scan) return <EmptyState />;
  const decoded = decodeURIComponent(name);
  const dependency = scan.items.find((item) => item.name === decoded && (!query.version || item.version === query.version) && (!query.path || item.path === query.path));
  if (!dependency) notFound();
  const pathCount = dependency.reachability?.paths.length || dependency.paths?.length || 1;
  const action = remediationLabel(dependency);

  return <><Link href={`/dependencies?scan=${scan.id}`} className="mb-5 inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft size={15} />Dependencies</Link><header className="mb-6 flex flex-col justify-between gap-5 lg:flex-row lg:items-end"><div><div className="flex flex-wrap items-center gap-3"><h1 className="text-3xl font-bold tracking-[-.03em]">{dependency.name}</h1><Badge tone={dependency.direct ? "direct" : "neutral"}>{dependency.direct ? "Direct" : "Transitive"}</Badge><Badge>{dependency.devOnly ? "Dev-only" : "Runtime"}</Badge><Badge tone={dependency.reachability?.status === "REACHABLE" ? "critical" : dependency.reachability?.status === "POSSIBLY_REACHABLE" ? "medium" : "neutral"}>{dependency.reachability?.status.replace("_", " ") ?? "UNKNOWN"}</Badge></div><p className="data mt-2 text-sm text-muted-foreground">{dependency.version} · {dependency.license} · final priority {dependency.risk}/100</p></div><div className="flex flex-wrap gap-2"><span className="inline-flex h-10 items-center gap-2 rounded-sm bg-card px-4 text-sm ring-1 ring-border"><Wrench className="text-primary" size={15} />{action ?? "No remediation required"}</span>{dependency.recommendation === "upgrade" ? <Link href={`/remediation?scan=${scan.id}`} className="inline-flex h-10 items-center gap-2 rounded-sm bg-primary px-4 text-sm font-semibold text-primary-foreground"><Beaker size={15} />Simulate upgrade</Link> : null}</div></header><div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_370px]"><div className="space-y-6"><ContextScores dependency={dependency} /><WhyScore dependency={dependency} defaultOpen /><Card><CardHeader><div><CardTitle>Vulnerability evidence</CardTitle><p className="mt-1 text-xs text-muted-foreground">Merged advisories, aliases, provenance, affected ranges, and reported fixes</p></div><span className="data text-2xl font-bold text-destructive">{dependency.vulnerabilities.length}</span></CardHeader>{dependency.vulnerabilities.length ? <div>{dependency.vulnerabilities.map((value) => <article key={value.id} className="border-b p-5 last:border-0"><div className="flex flex-wrap items-center gap-2"><b className="data">{value.cveAlias ?? value.id}</b><SeverityBadge severity={value.severity} />{(value.sources ?? (value.source ? [value.source] : [])).map((source) => <Badge key={source}>{source}</Badge>)}</div><p className="mt-3 max-w-3xl leading-6 text-muted-foreground">{value.summary}</p><dl className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4"><Datum label="CVSS" value={value.cvssAvailable === false ? "Unavailable" : value.cvss.toFixed(1)} /><Datum label="Affected range" value={value.vulnerableRange ?? "Not published"} /><Datum label="Fixed version" value={value.fixedVersion ?? "No known fix"} /><Datum label="Known exploit evidence" value={value.knownExploit === true ? "Reported" : value.knownExploit === false ? "Not reported" : "Unknown"} /></dl>{value.provenance?.length ? <details className="mt-4"><summary className="cursor-pointer text-xs font-semibold text-primary">Source provenance ({value.provenance.length})</summary><ul className="data mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">{value.provenance.map((source) => <li key={source.source} className="rounded-sm bg-background p-3 ring-1 ring-border"><b className="text-foreground">{source.source}</b> · {source.status} · {source.confidence}%<span className="mt-1 block">Retrieved {new Date(source.retrievedAt).toLocaleString()}</span><span className="mt-1 block break-words">{source.identifiers.join(", ")}</span></li>)}</ul></details> : null}{value.references?.length ? <div className="mt-4 flex flex-wrap gap-3">{value.references.slice(0, 6).map((reference, index) => <a key={`${reference}-${index}`} href={reference} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary">Reference {index + 1}<ExternalLink size={11} /></a>)}</div> : null}</article>)}</div> : <div className="p-10 text-center text-muted-foreground">No known vulnerabilities for this dependency instance.</div>}</Card><Card><CardHeader><div><CardTitle>Evidence-backed dependency graph</CardTitle><p className="mt-1 text-xs text-muted-foreground">{dependency.reachability?.paths.length ? `Showing the shortest of ${pathCount} static evidence paths.` : `Showing a representative lockfile path; source reachability is ${dependency.reachability?.status ?? "UNKNOWN"}.`}</p></div><ShieldAlert size={17} className="text-destructive" /></CardHeader><CardContent><DependencyGraph dependency={dependency} /></CardContent></Card><BlastRadiusPanel dependency={dependency} /><VulnerabilityTimeline dependency={dependency} detectedAt={scan.createdAt} /></div><aside className="space-y-6"><Card><CardHeader><CardTitle>Dependency health profile</CardTitle><Radar size={17} className="text-primary" /></CardHeader><CardContent><dl className="space-y-4"><HealthDatum label="Priority risk" value={`${dependency.risk}/100`} /><HealthDatum label="Confidence" value={dependency.contextual ? `${dependency.contextual.confidence}%` : "Not assessed"} /><HealthDatum label="Reachability" value={dependency.reachability?.status.replace("_", " ") ?? "UNKNOWN"} /><HealthDatum label="CVEs / advisories" value={String(dependency.vulnerabilities.length)} /><HealthDatum label="Fixability" value={action ?? "No action"} /><HealthDatum label="Dependency depth" value={String(dependency.depth ?? "Unknown")} /><HealthDatum label="Runtime usage" value={dependency.devOnly ? "Dev-only" : "Runtime graph"} /><HealthDatum label="Parent count" value={String(dependency.parentCount ?? 0)} /><HealthDatum label="Last observed" value={dependency.lastObservedAt ? new Date(dependency.lastObservedAt).toLocaleString() : "Persisted scan"} /></dl></CardContent></Card><Card><CardHeader><CardTitle>Reachability evidence</CardTitle><GitBranch size={17} className="text-primary" /></CardHeader><CardContent><p className="text-sm leading-6 text-muted-foreground">{dependency.reachability?.explanation ?? "No source evidence was supplied."}</p><dl className="mt-5 grid grid-cols-2 gap-4"><Datum label="Files analyzed" value={String(dependency.reachability?.sourceFilesAnalyzed ?? 0)} /><Datum label="Imported by" value={String(dependency.reachability?.importedBy.length ?? 0)} /><Datum label="Observed APIs" value={String(dependency.reachability?.observedFunctions.length ?? 0)} /><Datum label="Route hints" value={String(dependency.blastRadius?.routes.length ?? 0)} /></dl><details className="mt-5 border-t pt-4"><summary className="cursor-pointer text-xs font-semibold text-primary">Static-analysis limitations</summary><ul className="mt-3 list-disc space-y-2 pl-4 text-xs leading-5 text-muted-foreground">{(dependency.reachability?.limitations ?? ["No source analysis was available for this scan."]).map((item) => <li key={item}>{item}</li>)}</ul></details></CardContent></Card><UpgradeImpact dependency={dependency} /></aside></div></>;
}

function ContextScores({ dependency }: { dependency: Dependency }) {
  const scores = dependency.contextual;
  const propagation = dependency.propagation;
  const items = scores
    ? [
        { label: "Base dependency risk", value: dependency.risk, primary: true },
        { label: "Technical risk", value: scores.technical, primary: false },
        { label: "Exploitability", value: scores.exploitability, primary: false },
        { label: "Exposure", value: scores.exposure, primary: false },
        { label: "Remediation difficulty", value: scores.remediationDifficulty, primary: false },
        { label: "Contextual final priority", value: scores.finalPriority, primary: true },
      ]
    : [{ label: "Base dependency risk", value: dependency.risk, primary: true }];

  return (
    <section className="surface surface-outline" data-ui="context-risk">
      <div className="grid divide-y sm:grid-cols-2 sm:divide-x sm:divide-y-0 xl:grid-cols-6">
        {items.map((item) => (
          <div key={item.label} className="p-5">
            <span className="text-xs text-muted-foreground">{item.label}</span>
            <b className={`data mt-2 block text-3xl ${item.primary ? item.value >= 80 ? "text-destructive" : "text-warning" : ""}`}>
              {item.value}
            </b>
            <span className="text-xs text-muted-foreground">/100</span>
          </div>
        ))}
      </div>
      {scores ? (
        <div className="flex items-center justify-between border-t px-5 py-4" data-ui="confidence-score">
          <span className="text-xs text-muted-foreground">Evidence confidence is separate from severity.</span>
          <b className="data text-sm">{scores.confidence}% confidence</b>
        </div>
      ) : null}
      {propagation ? (
        <div className="border-t" data-ui="propagation-evidence">
          <header className="flex flex-col gap-2 px-5 py-4 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 className="text-sm font-bold">Dependency risk propagation</h2>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                Derived graph context shown alongside—never in place of—the base dependency risk.
              </p>
            </div>
            <span className="text-xs font-semibold text-primary">DepShield Propagation v1</span>
          </header>
          <dl className="grid border-t sm:grid-cols-3 sm:divide-x">
            <PropagationDatum label="Own contextual priority" value={propagation.ownRisk} />
            <PropagationDatum label="Inherited descendant risk" value={propagation.inheritedRisk} />
            <PropagationDatum label="Propagated contextual risk" value={propagation.contextualRisk} />
          </dl>
          <details className="border-t px-5 py-4">
            <summary className="cursor-pointer text-xs font-semibold text-primary">
              Contributors and formula ({propagation.contributors.length})
            </summary>
            {propagation.contributors.length ? (
              <ol className="mt-4 space-y-3">
                {propagation.contributors.map((contributor) => (
                  <li key={`${contributor.dependency}-${contributor.distance}`} className="rounded-sm bg-background p-4 ring-1 ring-border">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <b className="data text-xs">{contributor.dependency}</b>
                      <span className="data text-xs font-semibold text-warning">+{contributor.contribution} contribution</span>
                    </div>
                    <p className="data mt-2 text-xs text-muted-foreground">
                      distance {contributor.distance} · {contributor.pathCount} matching path{contributor.pathCount === 1 ? "" : "s"}
                    </p>
                    <p className="mt-2 text-xs leading-5 text-muted-foreground">{contributor.explanation}</p>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="mt-3 text-xs text-muted-foreground">No vulnerable descendant contributed inherited risk.</p>
            )}
            <p className="data mt-4 text-xs leading-5 text-muted-foreground">{propagation.formula}</p>
          </details>
        </div>
      ) : (
        <p className="border-t px-5 py-4 text-xs text-muted-foreground">Propagation evidence is unavailable for this legacy scan.</p>
      )}
    </section>
  );
}

function PropagationDatum({ label, value }: { label: string; value: number }) {
  return (
    <div className="p-5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="data mt-2 text-2xl font-bold">{value}<span className="text-xs font-normal text-muted-foreground">/100</span></dd>
    </div>
  );
}

function BlastRadiusPanel({ dependency }: { dependency: Dependency }) { const blast = dependency.blastRadius; return <section className="surface surface-outline" data-ui="blast-radius"><header className="border-b p-5"><h2 className="font-bold">Potential blast radius</h2><p className="mt-1 text-xs text-muted-foreground">Evidence-backed estimate, not proof of exploitability.</p></header><div className="grid divide-y sm:grid-cols-2 sm:divide-x sm:divide-y-0 lg:grid-cols-4"><BlastMetric label="Route hints" value={blast?.routes.length ?? 0} /><BlastMetric label="Source modules" value={blast?.modules.length ?? 0} /><BlastMetric label="Parent dependencies" value={blast?.parentDependencies.length ?? dependency.parentCount ?? 0} /><BlastMetric label="Application areas" value={blast?.applicationAreas.length ?? 0} /></div>{blast?.evidence.length ? <details className="border-t p-5"><summary className="cursor-pointer text-xs font-semibold text-primary">Evidence paths ({blast.evidence.length})</summary><ul className="data mt-3 space-y-2 break-words text-xs text-muted-foreground">{blast.evidence.slice(0, 12).map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul></details> : null}</section>; }
function BlastMetric({ label, value }: { label: string; value: number }) { return <div className="p-5"><span className="text-xs text-muted-foreground">{label}</span><b className="data mt-2 block text-2xl">{value}</b></div>; }

function UpgradeImpact({ dependency }: { dependency: Dependency }) { const value = dependency.compatibility; return <Card data-ui="upgrade-impact-preview"><CardHeader><div><CardTitle>Upgrade Impact Preview</CardTitle><p className="mt-1 text-xs text-muted-foreground">Estimated compatibility risk</p></div></CardHeader><CardContent>{value ? <><div className="flex items-end justify-between"><div><span className="text-xs text-muted-foreground">{value.currentVersion} → {value.targetVersion ?? "No target"}</span><b className={`mt-2 block text-2xl ${value.level === "HIGH" ? "text-destructive" : value.level === "MEDIUM" ? "text-warning" : value.level === "LOW" ? "text-safe" : "text-muted-foreground"}`}>{value.level}</b></div><span className="data text-xl">{value.score}/100</span></div><ul className="mt-5 list-disc space-y-2 pl-4 text-xs leading-5 text-muted-foreground">{value.reasons.slice(0, 5).map((reason) => <li key={reason}>{reason}</li>)}</ul><details className="mt-5 border-t pt-4"><summary className="cursor-pointer text-xs font-semibold text-primary">Suggested validation</summary><ul className="mt-3 list-disc space-y-2 pl-4 text-xs text-muted-foreground">{value.suggestedTests.map((test) => <li key={test}>{test}</li>)}</ul></details></> : <p className="text-sm text-muted-foreground">No compatibility estimate is available for this legacy scan.</p>}</CardContent></Card>; }

function VulnerabilityTimeline({ dependency, detectedAt }: { dependency: Dependency; detectedAt: string }) {
  const published = dependency.vulnerabilities
    .map((value) => value.publishedAt)
    .filter((value): value is string => Boolean(value))
    .toSorted()[0];
  const fixed = dependency.vulnerabilities.find((value) => value.fixedVersion)?.fixedVersion;
  const events = [
    { label: "Installed version observed", value: `${dependency.name}@${dependency.version}`, state: "observed" },
    { label: "Package release date", value: "Unavailable in collected package and advisory evidence", state: "unavailable" },
    { label: "Earliest advisory publication", value: published ? new Date(published).toLocaleDateString() : "Unavailable in advisory evidence", state: published ? "observed" : "unavailable" },
    { label: "Reported fixed target", value: fixed ?? "Unavailable — no complete fixed version reported", state: fixed ? "reported" : "unavailable" },
    { label: "Fix release date", value: "Unavailable — a reported version target is not release-date evidence", state: "unavailable" },
    { label: "Issue detected by project scan", value: new Date(detectedAt).toLocaleString(), state: "observed" },
    { label: "Project upgrade event", value: "Unavailable — no package-manager change record is attached", state: "unavailable" },
    { label: "Confirmed risk reduction", value: "Unavailable — requires an upgrade record, validation evidence, and a post-change scan", state: "unavailable" },
  ];
  return <section className="surface surface-outline" data-ui="cve-timeline"><header className="border-b p-5"><h2 className="font-bold">Vulnerability evidence timeline</h2><p className="mt-1 text-xs text-muted-foreground">Observed timestamps, reported version targets, and unavailable lifecycle evidence are separated explicitly. No remediation event is inferred.</p></header><ol className="grid gap-3 p-5 sm:grid-cols-2 xl:grid-cols-4">{events.map((event) => <li key={event.label} className="rounded-sm bg-background p-4 ring-1 ring-border"><div className="flex items-center justify-between gap-3"><span className={`block size-2.5 shrink-0 rounded-full ${event.state === "observed" ? "bg-safe" : event.state === "reported" ? "bg-primary" : "bg-unknown"}`} /><span className={`data text-xs font-bold uppercase tracking-[.08em] ${event.state === "observed" ? "text-safe" : event.state === "reported" ? "text-primary" : "text-muted-foreground"}`}>{event.state}</span></div><b className="mt-3 block text-xs">{event.label}</b><span className="data mt-2 block text-xs leading-5 text-muted-foreground">{event.value}</span></li>)}</ol></section>;
}

function HealthDatum({ label, value }: { label: string; value: string }) { return <div className="flex items-start justify-between gap-4 border-b pb-3 last:border-0"><dt className="text-xs text-muted-foreground">{label}</dt><dd className="data text-right text-xs font-semibold">{value}</dd></div>; }
function Datum({ label, value }: { label: string; value: string }) { return <div><dt className="text-xs text-muted-foreground">{label}</dt><dd className="data mt-1 break-words text-xs font-semibold">{value}</dd></div>; }

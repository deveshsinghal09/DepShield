"use client";

import Link from "next/link";
import { useDeferredValue, useMemo, useState } from "react";
import { ArrowUpDown, ChevronRight, Search } from "lucide-react";
import type { Dependency, ReachabilityStatus, Severity } from "@/lib/types";
import { remediationLabel } from "@/lib/remediation";
import { highestCvss } from "@/lib/scan-selectors";
import { Badge } from "./ui/badge";
import { SeverityBadge } from "./severity";
import { TableEmpty } from "./empty-state";

type Sort = "risk" | "package" | "cvss" | "cves" | "confidence";

function dependencyHref(item: Dependency, scanId?: string) {
  const query = new URLSearchParams({ version: item.version, path: item.path });
  if (scanId) query.set("scan", scanId);
  return `/dependencies/${encodeURIComponent(item.name)}?${query}`;
}

export function DependencyTable({
  items,
  compact = false,
  scanId,
  emptyMessage,
}: {
  items: Dependency[];
  compact?: boolean;
  scanId?: string;
  emptyMessage?: string;
}) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [scope, setScope] = useState("all");
  const [reachability, setReachability] = useState<"all" | ReachabilityStatus>("all");
  const [sort, setSort] = useState<Sort>("risk");
  const deferred = useDeferredValue(query);
  const rows = useMemo(() => items.filter((item) => {
    const needle = deferred.toLowerCase();
    const matchesText = item.name.toLowerCase().includes(needle) || item.vulnerabilities.some((value) =>
      value.id.toLowerCase().includes(needle) || value.cveAlias?.toLowerCase().includes(needle),
    );
    const matchesSeverity = severity === "all" || item.vulnerabilities.some((value) => value.severity === severity);
    const matchesScope = scope === "all" || (scope === "direct" ? item.direct : !item.direct);
    const matchesReachability = reachability === "all" || (item.reachability?.status ?? "UNKNOWN") === reachability;
    return matchesText && matchesSeverity && matchesScope && matchesReachability;
  }).toSorted((left, right) => {
    if (sort === "package") return left.name.localeCompare(right.name);
    if (sort === "cvss") return highestCvss(right) - highestCvss(left);
    if (sort === "cves") return right.vulnerabilities.length - left.vulnerabilities.length;
    if (sort === "confidence") return (right.contextual?.confidence ?? 0) - (left.contextual?.confidence ?? 0);
    // The primary sort remains the original dependency risk; propagated risk is displayed as derived evidence.
    return right.risk - left.risk;
  }), [items, deferred, severity, scope, reachability, sort]);
  const visible = compact ? rows.slice(0, 7) : rows;

  return (
    <section className="surface surface-outline" data-ui="risk-table">
      {compact ? null : (
        <div className="grid gap-3 border-b p-4 lg:grid-cols-[minmax(240px,1fr)_repeat(3,auto)]">
          <label className="relative">
            <span className="sr-only">Search packages or CVEs</span>
            <Search className="absolute left-3 top-2.5 text-muted-foreground" size={16} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search package or CVE…"
              className="h-9 w-full rounded-sm border bg-background pl-9 pr-3 text-sm placeholder:text-muted-foreground"
            />
          </label>
          <Select
            label="Filter severity"
            value={severity}
            onChange={(value) => setSeverity(value as typeof severity)}
            options={[["all", "All severities"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["unknown", "Unknown"]]}
          />
          <Select
            label="Filter relationship"
            value={scope}
            onChange={setScope}
            options={[["all", "Direct + transitive"], ["direct", "Direct only"], ["transitive", "Transitive only"]]}
          />
          <Select
            label="Filter reachability"
            value={reachability}
            onChange={(value) => setReachability(value as typeof reachability)}
            options={[["all", "All reachability"], ["REACHABLE", "Reachable"], ["POSSIBLY_REACHABLE", "Possibly reachable"], ["NOT_OBSERVED", "Not observed"], ["UNKNOWN", "Unknown"]]}
          />
        </div>
      )}
      <div className="scrollbar overflow-x-auto">
        <table className="w-full min-w-[1180px] text-left">
          <thead>
            <tr className="hud-label border-b bg-secondary/50 text-muted-foreground">
              <Header label="Package" value="package" sort={sort} setSort={setSort} />
              <th className="px-4 py-3 font-medium">Installed / scope</th>
              <th className="px-4 py-3 font-medium">Reachability</th>
              <Header label="CVSS / CVEs" value="cvss" sort={sort} setSort={setSort} />
              <Header label="Base / propagated risk" value="risk" sort={sort} setSort={setSort} />
              <Header label="Confidence" value="confidence" sort={sort} setSort={setSort} />
              <th className="px-4 py-3 font-medium">Graph health</th>
              <th className="px-4 py-3 font-medium">Recommended action</th>
              <th className="w-10"><span className="sr-only">Open</span></th>
            </tr>
          </thead>
          <tbody>
            {visible.map((item, index) => (
              <DependencyRow key={`${item.name}@${item.version}-${item.path}-${index}`} item={item} href={dependencyHref(item, scanId)} />
            ))}
          </tbody>
        </table>
      </div>
      {visible.length === 0 ? <TableEmpty message={emptyMessage} /> : null}
      {compact && rows.length > visible.length ? (
        <div className="border-t px-5 py-3 text-xs text-muted-foreground">Showing {visible.length} of {rows.length} risky dependencies</div>
      ) : null}
    </section>
  );
}

function DependencyRow({ item, href }: { item: Dependency; href: string }) {
  const highest = item.vulnerabilities.toSorted((left, right) => right.cvss - left.cvss)[0];
  const action = remediationLabel(item);
  const actionTreatment = remediationTreatment(action);
  const advisoryIds = [...new Set(item.vulnerabilities.map((value) => value.cveAlias ?? value.id))];
  const reachability = item.reachability?.status ?? "UNKNOWN";
  const propagation = item.propagation;
  const baseTone = item.risk >= 80 ? "text-destructive" : item.risk >= 50 ? "text-warning" : "text-safe";

  return (
    <tr className="border-b last:border-0 hover:bg-secondary/60">
      <td className="px-5 py-3">
        <Link href={href} className="font-semibold hover:text-primary">{item.name}</Link>
        <span className="mt-1 block text-xs text-muted-foreground">
          Last observed {item.lastObservedAt ? new Date(item.lastObservedAt).toLocaleDateString("en-GB", { timeZone: "UTC" }) : "in persisted scan"}
        </span>
      </td>
      <td className="px-4 py-3">
        <span className="data block text-xs text-muted-foreground">{item.version}</span>
        <Badge tone={item.direct ? "direct" : "neutral"}>{item.direct ? "Direct" : "Transitive"} · {item.devOnly ? "Dev" : "Runtime"}</Badge>
      </td>
      <td className="px-4 py-3">
        <span className={`text-xs font-semibold ${reachability === "REACHABLE" ? "text-destructive" : reachability === "POSSIBLY_REACHABLE" ? "text-warning" : "text-muted-foreground"}`}>
          {reachability.replace("_", " ")}
        </span>
        <span className="mt-1 block text-xs text-muted-foreground">{item.blastRadius?.routes.length ?? 0} route hints</span>
      </td>
      <td className="px-4 py-3">
        {highest ? (
          <div className="flex items-center gap-2">
            <span className="data font-bold">{highest.cvssAvailable === false ? "—" : highest.cvss.toFixed(1)}</span>
            <SeverityBadge severity={highest.severity} />
          </div>
        ) : <span className="text-muted-foreground">—</span>}
        <span className="data mt-1 block text-xs text-muted-foreground">{item.vulnerabilities.length} CVE/advisory</span>
        {advisoryIds[0] ? <span className="data mt-2 inline-flex border px-1.5 py-0.5 text-[9px] text-muted-foreground">{advisoryIds[0]}{advisoryIds.length > 1 ? ` +${advisoryIds.length - 1}` : ""}</span> : null}
      </td>
      <td className="px-4 py-3" data-ui="propagation-evidence">
        <span className={`data text-base font-bold ${baseTone}`}>{item.risk}</span>
        <span className="ml-1 text-xs text-muted-foreground">base</span>
        {propagation ? (
          <>
            <span className="data mt-1 block text-xs font-semibold">{propagation.contextualRisk} propagated</span>
            <span className="data mt-1 block text-xs text-muted-foreground">
              own {propagation.ownRisk} · inherited {propagation.inheritedRisk}
            </span>
          </>
        ) : (
          <span className="mt-1 block text-xs text-muted-foreground">Propagation not assessed</span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className="data font-semibold">{item.contextual?.confidence ?? "—"}{item.contextual ? "%" : ""}</span>
        <span className="mt-1 block text-xs text-muted-foreground">{item.contextual ? "Evidence quality" : "Not assessed"}</span>
      </td>
      <td className="data px-4 py-3 text-xs">
        <span className="block">Depth {item.depth ?? "—"}</span>
        <span className="mt-1 block text-muted-foreground">{item.parentCount ?? 0} parent{item.parentCount === 1 ? "" : "s"}</span>
        {propagation?.contributors.length ? (
          <span className="mt-1 block text-muted-foreground">{propagation.contributors.length} risk contributor{propagation.contributors.length === 1 ? "" : "s"}</span>
        ) : null}
      </td>
      <td className={`px-4 py-3 ${actionTreatment.rail}`}>
        <span className={`text-xs font-semibold ${actionTreatment.tone}`}>
          {action ?? "No action"}
        </span>
        <span className="data mt-1 block text-xs text-muted-foreground">
          {item.recommendation === "upgrade" ? item.latest : item.recommendation === "partial-fix" ? "Partial coverage" : item.recommendation === "no-fix" ? "Manual review" : "Current"}
        </span>
      </td>
      <td className="px-3">
        <Link href={href} aria-label={`Open ${item.name} ${item.version}`}><ChevronRight size={16} /></Link>
      </td>
    </tr>
  );
}

function remediationTreatment(action: ReturnType<typeof remediationLabel>) {
  if (action === "No Fix Available") return { rail: "severity-rail-critical", tone: "text-critical" };
  if (action === "Major Upgrade") return { rail: "severity-rail-high", tone: "text-high" };
  if (action === "Update Parent Dependency") return { rail: "severity-rail-medium", tone: "text-warning" };
  if (action === "Minor Upgrade") return { rail: "severity-rail-medium", tone: "text-warning" };
  if (action === "Safe Auto Fix") return { rail: "severity-rail-safe", tone: "text-safe" };
  return { rail: "", tone: "text-muted-foreground" };
}

function Select({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<[string, string]>;
}) {
  return (
    <select aria-label={label} value={value} onChange={(event) => onChange(event.target.value)} className="h-9 rounded-[2px] border bg-background px-3 text-sm">
      {options.map(([key, text]) => <option key={key} value={key}>{text}</option>)}
    </select>
  );
}

function Header({
  label,
  value,
  sort,
  setSort,
}: {
  label: string;
  value: Sort;
  sort: Sort;
  setSort: (value: Sort) => void;
}) {
  return (
    <th className="px-4 py-3 font-medium first:pl-5">
      <button className={`flex items-center gap-1 ${sort === value ? "text-foreground" : ""}`} onClick={() => setSort(value)}>
        {label}<ArrowUpDown size={12} />
      </button>
    </th>
  );
}

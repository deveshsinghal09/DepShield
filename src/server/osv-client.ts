import type { RawAdvisory, SourceStatus } from "@/lib/types";
import type { InstalledDependency } from "./dependency-tree";
import { getCachedAdvisories, setCachedAdvisories } from "./db";
import { compareVersions } from "./advisory-merge";
import { parseCvss, severityFromScore } from "./cvss";

const TTL = 24 * 60 * 60 * 1000;
const BATCH = 500;
const DETAIL_CONCURRENCY = 8;

type OsvVulnerability = {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  references?: { url: string }[];
  affected?: {
    package?: { name: string };
    ranges?: {
      type: string;
      repo?: string;
      events: { introduced?: string; fixed?: string; last_affected?: string }[];
    }[];
    versions?: string[];
  }[];
};

export type OsvResult = {
  findings: Map<string, RawAdvisory[]>;
  status: SourceStatus;
  warning?: string;
};

export async function queryOsv(
  dependencies: InstalledDependency[],
  fetcher: typeof fetch = fetch,
): Promise<OsvResult> {
  const findings = new Map<string, RawAdvisory[]>();
  const misses: InstalledDependency[] = [];
  const retrievedAt = new Date().toISOString();
  let cached = 0;
  for (const dependency of uniquePackages(dependencies)) {
    let value: RawAdvisory[] | null = null;
    try {
      value = getCachedAdvisories(dependency.name, dependency.version, TTL);
    } catch {
      // Cache is optional enrichment. A cache read failure must not prevent a
      // live OSV lookup for the exact package/version.
    }
    if (value && usableCachedAdvisories(value)) {
      findings.set(key(dependency), value.map((item) => ({ ...item, retrievedAt: item.retrievedAt ?? retrievedAt })));
      cached++;
    } else misses.push(dependency);
  }

  let fetched = 0;
  let failed = false;
  let message: string | null = null;
  for (let start = 0; start < misses.length; start += BATCH) {
    const batch = misses.slice(start, start + BATCH);
    try {
      const response = await fetcher("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: batch.map((dependency) => ({ package: { ecosystem: "npm", name: dependency.name }, version: dependency.version })) }),
        signal: AbortSignal.timeout(15_000),
      });
      if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}`);
      const body = await response.json() as { results: { vulns?: OsvVulnerability[] }[] };
      const batchVulnerabilities = body.results.flatMap((result) => result?.vulns ?? []);
      const details = await fetchOsvDetails(batchVulnerabilities, fetcher);
      if (details.failed) {
        failed = true;
        message = details.message;
      }
      batch.forEach((dependency, index) => {
        const advisories = (body.results[index]?.vulns ?? []).map((value) =>
          normalizeOsv(details.values.get(value.id) ?? value, dependency.name, retrievedAt),
        );
        findings.set(key(dependency), advisories);
        try {
          setCachedAdvisories(dependency.name, dependency.version, advisories);
        } catch {
          // A full/ephemeral/unavailable cache does not invalidate live OSV data.
        }
        fetched++;
      });
    } catch (error) {
      failed = true;
      message = error instanceof Error ? error.message : "OSV request failed";
      for (const dependency of batch) findings.set(key(dependency), []);
    }
  }
  return {
    findings,
    status: {
      source: "osv",
      status: failed ? cached || fetched ? "partial" : "failed" : "ok",
      message,
      cached,
      fetched,
      retrievedAt,
      confidence: failed ? cached || fetched ? 60 : 0 : 90,
    },
    warning: failed ? `OSV enrichment was incomplete: ${message}` : undefined,
  };
}

async function fetchOsvDetails(values: OsvVulnerability[], fetcher: typeof fetch) {
  const candidates = [...new Map(
    values
      .filter((value) => !hasAdvisoryDetails(value))
      .map((value) => [value.id, value]),
  ).values()];
  const detailed = new Map<string, OsvVulnerability>();
  let failures = 0;

  for (let start = 0; start < candidates.length; start += DETAIL_CONCURRENCY) {
    const slice = candidates.slice(start, start + DETAIL_CONCURRENCY);
    await Promise.all(slice.map(async (candidate) => {
      try {
        const response = await fetcher(`https://api.osv.dev/v1/vulns/${encodeURIComponent(candidate.id)}`, {
          signal: AbortSignal.timeout(15_000),
        });
        if (!response.ok) throw new Error(`OSV detail returned HTTP ${response.status}`);
        detailed.set(candidate.id, await response.json() as OsvVulnerability);
      } catch {
        failures++;
      }
    }));
  }

  return {
    values: detailed,
    failed: failures > 0,
    message: failures > 0
      ? `${failures} OSV advisory detail request${failures === 1 ? "" : "s"} failed; identifier-only evidence was retained.`
      : null,
  };
}

function hasAdvisoryDetails(value: OsvVulnerability) {
  return Boolean(
    value.summary
    || value.details
    || value.aliases?.length
    || value.severity?.length
    || value.references?.length
    || value.affected?.length,
  );
}

function usableCachedAdvisories(values: RawAdvisory[]) {
  if (!values.length) return true;
  return values.every((value) => Boolean(
    value.summary && value.summary !== "Vulnerability reported by OSV."
    || value.vulnerableRange
    || value.references?.length
    || value.aliases?.some((alias) => alias.toUpperCase() !== value.id.toUpperCase())
    || value.publishedAt,
  ));
}

function normalizeOsv(value: OsvVulnerability, name: string, retrievedAt: string): RawAdvisory {
  const vector = value.severity?.find((item) => item.type.startsWith("CVSS"))?.score ?? null;
  const parsed = parseCvss(vector ?? undefined);
  const aliases = [value.id, ...(value.aliases ?? [])];
  const affected = value.affected?.filter((item) => !item.package?.name || item.package.name === name) ?? [];
  const range = affected.flatMap((item) => item.ranges ?? []).map((item) => `${item.type}: ${item.events.map((event) => event.introduced !== undefined ? `>=${event.introduced}` : event.fixed ? `<${event.fixed}` : event.last_affected ? `<=${event.last_affected}` : "").filter(Boolean).join(" ")}`).join("; ") || null;
  const fixed = affected.flatMap((item) => item.ranges ?? []).flatMap((item) => item.events).map((event) => event.fixed).filter((item): item is string => Boolean(item)).toSorted(compareVersions).at(-1) ?? null;
  const cve = aliases.find((item) => item.startsWith("CVE-")) ?? null;
  return {
    id: value.id,
    aliases,
    cveAlias: cve,
    cvss: parsed ?? 0,
    cvssAvailable: parsed !== null,
    cvssVector: vector,
    severity: severityFromScore(parsed, value.database_specific?.severity),
    summary: value.summary ?? value.details ?? "Vulnerability reported by OSV.",
    vulnerableRange: range,
    fixedVersion: fixed,
    references: (value.references ?? []).map((item) => item.url),
    source: "OSV",
    retrievedAt,
    publishedAt: value.published ?? null,
    modifiedAt: value.modified ?? null,
  };
}

function uniquePackages(values: InstalledDependency[]) {
  return [...new Map(values.map((dependency) => [key(dependency), dependency])).values()];
}

function key(dependency: Pick<InstalledDependency, "name" | "version">) {
  return `${dependency.name}@${dependency.version}`;
}

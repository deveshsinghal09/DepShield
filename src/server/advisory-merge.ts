import type {
  RawAdvisory,
  Severity,
  Vulnerability,
  VulnerabilityProvenance,
  VulnerabilitySource,
} from "@/lib/types";

/**
 * Merge advisories by connected identifier components. If A shares an ID with B
 * and B shares another ID with C, all three are one finding even when A and C do
 * not directly share an alias.
 */
export function mergeAdvisories(values: RawAdvisory[]): Vulnerability[] {
  if (!values.length) return [];
  const parent = values.map((_, index) => index);
  const owners = new Map<string, number>();

  const find = (index: number): number => {
    if (parent[index] !== index) parent[index] = find(parent[index]);
    return parent[index];
  };
  const union = (left: number, right: number) => {
    const a = find(left);
    const b = find(right);
    if (a !== b) parent[b] = a;
  };

  values.forEach((advisory, index) => {
    for (const identifier of identifiers(advisory)) {
      const owner = owners.get(identifier);
      if (owner === undefined) owners.set(identifier, index);
      else union(index, owner);
    }
  });

  const groups = new Map<number, RawAdvisory[]>();
  values.forEach((advisory, index) => {
    const root = find(index);
    groups.set(root, [...(groups.get(root) ?? []), advisory]);
  });

  return [...groups.values()].map(mergeGroup).toSorted((a, b) => {
    return b.cvss - a.cvss || a.id.localeCompare(b.id);
  });
}

function mergeGroup(items: RawAdvisory[]): Vulnerability {
  const aliases = unique(items.flatMap((value) => rawIdentifiers(value)));
  const cve = bestSupportedIdentifier(items, "CVE-");
  const scored = items
    .filter((value) => value.cvssAvailable !== false && value.cvss > 0)
    .toSorted((a, b) => b.cvss - a.cvss);
  const primary = scored[0] ?? items.toSorted((a, b) => severityRank(b.severity) - severityRank(a.severity))[0];
  const fixed = items
    .map((value) => value.fixedVersion)
    .filter((value): value is string => Boolean(value))
    .toSorted(compareVersions)
    .at(-1) ?? null;
  const sources = unique(items.map((value) => value.source));
  const provenance = buildProvenance(items, sources);

  return {
    id:
      cve ??
      items.find((value) => value.id.toUpperCase().startsWith("GHSA-"))?.id ??
      primary.id,
    aliases,
    cveAlias: cve,
    cvss: primary.cvssAvailable === false ? 0 : primary.cvss,
    cvssAvailable: scored.length > 0,
    cvssVector: scored.find((value) => value.cvssVector)?.cvssVector ?? null,
    severity: scored.length > 0 ? primary.severity : highestSeverity(items.map((value) => value.severity)),
    summary: items.map((value) => value.summary).find(Boolean) ?? "Known vulnerability.",
    vulnerableRange: unique(
      items.map((value) => value.vulnerableRange).filter((value): value is string => Boolean(value)),
    ).join("; ") || null,
    fixedVersion: fixed,
    references: unique(items.flatMap((value) => value.references ?? [])),
    sources,
    provenance,
    publishedAt: earliest(items.map((value) => value.publishedAt)),
    modifiedAt: latest(items.map((value) => value.modifiedAt)),
    knownExploit: items.some((value) => value.knownExploit === true)
      ? true
      : items.every((value) => value.knownExploit === false)
        ? false
        : null,
  };
}

/**
 * A malformed or bridging source record can connect more than one candidate
 * identifier. Prefer the identifier repeated by the most records/fields so one
 * low-quality alias does not silently become the canonical finding ID.
 */
function bestSupportedIdentifier(items: RawAdvisory[], prefix: string) {
  const support = new Map<string, number>();
  for (const item of items) {
    for (const identifier of rawIdentifiers(item)) {
      const normalized = normalize(identifier);
      if (normalized.startsWith(prefix)) support.set(normalized, (support.get(normalized) ?? 0) + 1);
    }
  }
  return [...support.entries()]
    .toSorted(([leftId, leftCount], [rightId, rightCount]) => rightCount - leftCount || leftId.localeCompare(rightId))[0]?.[0] ?? null;
}

function buildProvenance(
  items: RawAdvisory[],
  sources: VulnerabilitySource[],
): VulnerabilityProvenance[] {
  return sources.map((source) => {
    const evidence = items.filter((item) => item.source === source);
    const hasCvss = evidence.some((item) => item.cvssAvailable !== false && item.cvss > 0);
    const confidence = Math.min(
      98,
      62 + (hasCvss ? 12 : 0) + (sources.length > 1 ? 12 : 0) + (evidence.some((item) => item.fixedVersion) ? 6 : 0),
    );
    return {
      source,
      retrievedAt: latest(evidence.map((item) => item.retrievedAt)) ?? new Date().toISOString(),
      // Multiple providers corroborate the identifier, not necessarily every
      // CVSS/range/fix field. Keep each source record explicitly "reported".
      status: "reported",
      confidence,
      identifiers: unique(evidence.flatMap(rawIdentifiers)),
    };
  });
}

function identifiers(value: RawAdvisory) {
  return rawIdentifiers(value).map(normalize);
}

function rawIdentifiers(value: RawAdvisory) {
  return [value.id, ...(value.aliases ?? []), value.cveAlias]
    .filter((identifier): identifier is string => Boolean(identifier))
    .map((identifier) => identifier.trim());
}

function normalize(value: string) {
  return value.trim().toUpperCase();
}

const severityOrder: Severity[] = ["unknown", "low", "medium", "high", "critical"];
function severityRank(value: Severity) {
  return severityOrder.indexOf(value);
}

function highestSeverity(values: Severity[]) {
  return values.toSorted((a, b) => severityRank(b) - severityRank(a))[0] ?? "unknown";
}

function unique<T>(values: T[]) {
  return [...new Set(values)];
}

function earliest(values: Array<string | null | undefined>) {
  return values.filter((value): value is string => Boolean(value)).toSorted()[0] ?? null;
}

function latest(values: Array<string | null | undefined>) {
  return values.filter((value): value is string => Boolean(value)).toSorted().at(-1) ?? null;
}

export function compareVersions(a: string, b: string) {
  const aa = versionParts(a);
  const bb = versionParts(b);
  for (let index = 0; index < Math.max(aa.length, bb.length); index++) {
    const left = aa[index] ?? 0;
    const right = bb[index] ?? 0;
    if (typeof left === "number" && typeof right === "number" && left !== right) return left - right;
    const difference = String(left).localeCompare(String(right), undefined, { numeric: true });
    if (difference) return difference;
  }
  return 0;
}

function versionParts(value: string) {
  return value
    .replace(/^[^0-9]*/, "")
    .split(/[.+-]/)
    .map((part) => (/^\d+$/.test(part) ? Number(part) : part));
}

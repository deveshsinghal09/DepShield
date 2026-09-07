import type { Vulnerability } from "@/lib/types";

type FunctionRule = {
  packageName: string;
  identifiers: string[];
  functions: string[];
  source: string;
};

/**
 * Deliberately small, reviewed registry. Package-level findings stay UNKNOWN
 * when no reliable function mapping is present; OSV/NVD do not generally
 * provide vulnerable-symbol data.
 */
const RULES: FunctionRule[] = [
  {
    packageName: "lodash",
    identifiers: ["CVE-2019-10744", "GHSA-jf85-cpcp-j695"],
    functions: ["defaultsDeep"],
    source: "Lodash prototype-pollution advisory for defaultsDeep paths",
  },
];

export function vulnerableFunctionsFor(packageName: string, findings: Vulnerability[]) {
  const identifiers = new Set(
    findings.flatMap((finding) => [finding.id, finding.cveAlias, ...(finding.aliases ?? [])])
      .filter((value): value is string => Boolean(value))
      .map((value) => value.toUpperCase()),
  );
  const matching = RULES.filter(
    (rule) =>
      rule.packageName === packageName &&
      rule.identifiers.some((identifier) => identifiers.has(identifier.toUpperCase())),
  );
  return {
    functions: [...new Set(matching.flatMap((rule) => rule.functions))],
    provenance: matching.map((rule) => rule.source),
  };
}

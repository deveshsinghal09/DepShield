import { describe, expect, it } from "vitest";
import type { Dependency, Scan } from "./types";
import { compareScans, validateScanComparison } from "./scan-selectors";

function dependency(version: string): Dependency {
  return {
    name: "lodash",
    version,
    direct: false,
    path: `Application → parent@2.0.0 → lodash@${version}`,
    paths: [{ nodes: ["Application", "parent@2.0.0", `lodash@${version}`], display: `Application → parent@2.0.0 → lodash@${version}` }],
    license: "MIT",
    vulnerabilities: [],
    risk: 0,
    latest: version,
    recommendation: "none",
  };
}

function scan(id: string, createdAt: string, version = "4.17.11", project = "demo"): Scan {
  return {
    id,
    createdAt,
    project,
    branch: "main",
    score: 80,
    grade: "B",
    dependencies: 1,
    vulnerable: 0,
    critical: 0,
    duration: 1,
    items: [dependency(version)],
  };
}

describe("scan comparison selection", () => {
  const before = scan("before", "2026-08-24T10:00:00.000Z");
  const after = scan("after", "2026-08-24T11:00:00.000Z", "4.17.21");

  it("matches an upgraded dependency even when its persisted path contains the installed version", () => {
    expect(compareScans(before, after).upgraded).toBe(1);
  });

  it("rejects cross-project and reverse-chronology comparisons before calculating deltas", () => {
    expect(validateScanComparison(before, { ...after, project: "other" })).toMatchObject({ valid: false, code: "PROJECT_MISMATCH" });
    expect(validateScanComparison(after, before)).toMatchObject({ valid: false, code: "REVERSE_CHRONOLOGY" });
    expect(() => compareScans(after, before)).toThrow("before scan must not be newer");
  });
});

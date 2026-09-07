import { describe, expect, it } from "vitest";
import type { AuditResult } from "./npm-audit";
import type { OsvResult } from "./osv-client";
import { scanProject } from "./scanner";

const packageJson = JSON.stringify({ name: "test-app", dependencies: { parent: "1.0.0" } });
const packageLock = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    "": { dependencies: { parent: "1.0.0" } },
    "node_modules/parent": { version: "1.0.0", dependencies: { child: "1.2.0" } },
    "node_modules/child": { version: "1.2.0" },
  },
});

describe("scan pipeline", () => {
  it("returns structured paths and survives one failed source", async () => {
    const audit: AuditResult = {
      findings: new Map(),
      status: { source: "npm-audit", status: "failed", message: "offline" },
      warning: "offline",
    };
    const osv: OsvResult = {
      findings: new Map([["child@1.2.0", [{
        id: "OSV-1",
        aliases: ["OSV-1", "CVE-2026-1"],
        cveAlias: "CVE-2026-1",
        cvss: 9.8,
        cvssAvailable: true,
        cvssVector: null,
        severity: "critical",
        summary: "critical issue",
        vulnerableRange: ">=1 <1.3",
        fixedVersion: "1.3.0",
        references: ["https://osv.dev/1"],
        source: "OSV",
      }]]]),
      status: { source: "osv", status: "ok", message: null },
    };

    const scan = await scanProject(
      packageJson,
      packageLock,
      { audit: async () => audit, osv: async () => osv },
      [{
        path: "src/app/api/test/route.ts",
        content: 'import parent from "parent"; export async function POST(){ return parent(); }',
      }],
    );

    expect(scan.project).toBe("test-app");
    expect(scan.items.find((value) => value.name === "child")).toMatchObject({
      direct: false,
      recommendation: "upgrade",
      latest: "1.3.0",
      reachability: { status: "POSSIBLY_REACHABLE" },
      contextual: { model: "DepShield Contextual Risk v2" },
    });
    expect(scan.sourceFilesAnalyzed).toBe(1);
    expect(scan.dependencyTree?.some((path) => path.display === "test-app → parent@1.0.0 → child@1.2.0")).toBe(true);
    expect(scan.attackPaths).toHaveLength(1);
    expect(scan.attackPaths?.[0]).toMatchObject({
      dependencyName: "child",
      findingId: "CVE-2026-1",
      reachability: "possibly-reachable",
      evidenceKind: "source-route",
      estimated: true,
    });
    expect(scan.warnings?.[0].code).toBe("NPM_AUDIT_FAILED");
  });

  it("continues when both provider adapters throw unexpectedly", async () => {
    const scan = await scanProject(packageJson, packageLock, {
      audit: async () => { throw new Error("audit adapter crashed"); },
      osv: async () => { throw new Error("cache record was invalid"); },
    });

    expect(scan.dependencies).toBe(2);
    expect(scan.vulnerable).toBe(0);
    expect(scan.sourceStatus?.map((source) => source.status).slice(0, 2)).toEqual(["failed", "failed"]);
    expect(scan.warnings?.map((warning) => warning.code)).toEqual(expect.arrayContaining([
      "NPM_AUDIT_FAILED",
      "OSV_API_FAILED",
    ]));
  });

  it("rejects scans without a lockfile", async () => {
    await expect(scanProject(packageJson, undefined)).rejects.toMatchObject({ code: "NO_LOCKFILE" });
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { InstalledDependency } from "./dependency-tree";

const getCachedAdvisories = vi.fn(() => null);
const setCachedAdvisories = vi.fn();

vi.mock("./db", () => ({ getCachedAdvisories, setCachedAdvisories }));

const dependency: InstalledDependency = {
  key: "node_modules/demo-package",
  name: "demo-package",
  version: "1.0.0",
  direct: true,
  runtime: true,
  devOnly: false,
  optional: false,
  depth: 1,
  parentCount: 0,
  parentPackages: [],
  license: "MIT",
  paths: [{ nodes: ["demo", "demo-package@1.0.0"], display: "demo → demo-package@1.0.0" }],
};

describe("OSV advisory hydration", () => {
  beforeEach(() => {
    getCachedAdvisories.mockReset();
    getCachedAdvisories.mockReturnValue(null);
    setCachedAdvisories.mockReset();
  });

  it("hydrates querybatch stubs before normalizing CVE, CVSS, ranges, and fixed versions", async () => {
    const fetcher = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        return Response.json({ results: [{ vulns: [{ id: "GHSA-aaaa-bbbb-cccc", modified: "2026-08-24T00:00:00Z" }] }] });
      }
      expect(url).toBe("https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc");
      return Response.json({
        id: "GHSA-aaaa-bbbb-cccc",
        aliases: ["CVE-2026-12345"],
        summary: "Detailed advisory",
        published: "2026-08-01T00:00:00Z",
        modified: "2026-08-24T00:00:00Z",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        references: [{ url: "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc" }],
        affected: [{
          package: { ecosystem: "npm", name: "demo-package" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.0" }] }],
        }],
      });
    }) as unknown as typeof fetch;

    const { queryOsv } = await import("./osv-client");
    const result = await queryOsv([dependency], fetcher);
    const finding = result.findings.get("demo-package@1.0.0")?.[0];

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(result.status.status).toBe("ok");
    expect(finding).toMatchObject({
      id: "GHSA-aaaa-bbbb-cccc",
      cveAlias: "CVE-2026-12345",
      cvss: 9.8,
      severity: "critical",
      vulnerableRange: "SEMVER: >=0 <1.2.0",
      fixedVersion: "1.2.0",
    });
    expect(setCachedAdvisories).toHaveBeenCalledWith("demo-package", "1.0.0", expect.any(Array));
  });

  it("retains stub evidence and reports partial status when a detail request fails", async () => {
    const fetcher = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        return Response.json({ results: [{ vulns: [{ id: "OSV-STUB-1", modified: "2026-08-24T00:00:00Z" }] }] });
      }
      return new Response("unavailable", { status: 503 });
    }) as unknown as typeof fetch;

    const { queryOsv } = await import("./osv-client");
    const result = await queryOsv([dependency], fetcher);

    expect(result.status.status).toBe("partial");
    expect(result.warning).toContain("detail request");
    expect(result.findings.get("demo-package@1.0.0")?.[0].id).toBe("OSV-STUB-1");
  });
});

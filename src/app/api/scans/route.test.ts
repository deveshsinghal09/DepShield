import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  sourceUploads: false,
  scanProject: vi.fn(),
  saveScan: vi.fn(),
}));

vi.mock("@/lib/feature-flags", () => ({
  getFeatureFlags: () => ({ sourceUploads: mocks.sourceUploads }),
}));
vi.mock("@/server/db", () => ({
  getScan: vi.fn(),
  listScans: vi.fn(() => []),
  saveScan: mocks.saveScan,
}));
vi.mock("@/server/scanner", () => ({ scanProject: mocks.scanProject }));
vi.mock("@/server/dependency-tree", () => ({
  ManifestError: class ManifestError extends Error {
    code = "INVALID_MANIFEST";
  },
}));
vi.mock("@/server/reachability", () => ({
  DEFAULT_REACHABILITY_LIMITS: {
    maxFiles: 750,
    maxFileBytes: 512 * 1024,
    maxTotalBytes: 8 * 1024 * 1024,
    maxPathLength: 500,
  },
}));

import { POST } from "./route";

describe("scan source-upload boundary", () => {
  beforeEach(() => {
    mocks.sourceUploads = false;
    mocks.scanProject.mockReset();
    mocks.saveScan.mockReset();
  });

  it("rejects source text before scanning when the deployment flag is disabled", async () => {
    const response = await POST(new Request("http://localhost/api/scans", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        packageJson: JSON.stringify({ name: "private-project", version: "1.0.0" }),
        packageLock: JSON.stringify({ name: "private-project", lockfileVersion: 3, packages: {} }),
        sourceFiles: [{ path: "src/index.ts", content: "export const secret = 'never scanned';" }],
      }),
    }));

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
      error: { code: "SOURCE_UPLOADS_DISABLED" },
    });
    expect(mocks.scanProject).not.toHaveBeenCalled();
    expect(mocks.saveScan).not.toHaveBeenCalled();
  });
});

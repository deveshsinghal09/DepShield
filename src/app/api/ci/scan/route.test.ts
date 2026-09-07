import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Scan } from "@/lib/types";

vi.mock("../../../../server/db", () => ({
  getScan: vi.fn(),
  listSecurityPolicies: vi.fn(() => []),
  saveScan: vi.fn((scan: Scan) => scan),
}));

vi.mock("../../../../server/scanner", () => ({
  scanProject: vi.fn(),
}));

import { getScan, saveScan } from "../../../../server/db";
import { scanProject } from "../../../../server/scanner";
import { POST } from "./route";

const cleanScan: Scan = {
  id: "scan-1",
  createdAt: "2026-08-24T12:00:00.000Z",
  project: "ci-demo",
  branch: "uploaded",
  score: 100,
  grade: "A",
  dependencies: 0,
  vulnerable: 0,
  critical: 0,
  duration: 1,
  items: [],
  sourceStatus: [
    { source: "npm-audit", status: "ok", message: null },
    { source: "osv", status: "ok", message: null },
  ],
};

function request(body: unknown) {
  return new Request("http://localhost/api/ci/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("CI scan API", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(scanProject).mockResolvedValue(cleanScan);
    vi.mocked(saveScan).mockImplementation((scan) => scan);
    vi.mocked(getScan).mockReturnValue(null);
  });

  it("returns policy output and exit code zero for a passing scan", async () => {
    const response = await POST(request({ packageJson: "{}", packageLock: "{}", sourceFiles: [] }));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toMatchObject({ data: { id: "scan-1" }, policy: { status: "warning", exitCode: 0 }, exitCode: 0 });
    expect(scanProject).toHaveBeenCalledWith("{}", "{}", {}, []);
    expect(saveScan).toHaveBeenCalledWith(cleanScan);
  });

  it("returns exit code one without turning a policy failure into an HTTP error", async () => {
    vi.mocked(scanProject).mockResolvedValue({ ...cleanScan, score: 40, grade: "F" });
    const response = await POST(request({ packageJson: "{}", packageLock: "{}" }));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toMatchObject({ policy: { status: "fail", exitCode: 1 }, exitCode: 1 });
  });

  it("returns structured exit code two for invalid input and unsafe source paths", async () => {
    const missing = await POST(request({ packageJson: "{}" }));
    expect(await missing.json()).toMatchObject({ exitCode: 2, error: { code: "PACKAGE_LOCK_REQUIRED" } });
    expect(missing.status).toBe(422);

    const unsafe = await POST(request({
      packageJson: "{}",
      packageLock: "{}",
      sourceFiles: [{ path: "../secret.ts", content: "export {};" }],
    }));
    expect(await unsafe.json()).toMatchObject({ exitCode: 2, error: { code: "INVALID_SOURCE_PATH" } });
    expect(scanProject).not.toHaveBeenCalled();
  });

  it("returns structured exit code two when the scanner throws", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.mocked(scanProject).mockRejectedValue(new Error("provider exploded"));
    const response = await POST(request({ packageJson: "{}", packageLock: "{}" }));
    const body = await response.json();

    expect(response.status).toBe(500);
    expect(body).toMatchObject({ data: null, policy: null, exitCode: 2, error: { code: "SCANNER_ERROR" } });
    expect(JSON.stringify(body)).not.toContain("provider exploded");
    errorLog.mockRestore();
  });

  it("rejects a baseline from a different project before persisting the scan", async () => {
    vi.mocked(getScan).mockReturnValue({ ...cleanScan, id: "other-scan", project: "other-project" });

    const response = await POST(request({
      packageJson: "{}",
      packageLock: "{}",
      baselineScanId: "other-scan",
    }));
    const body = await response.json();

    expect(response.status).toBe(409);
    expect(body).toMatchObject({ exitCode: 2, error: { code: "BASELINE_PROJECT_MISMATCH" } });
    expect(saveScan).not.toHaveBeenCalled();
  });

  it("rejects a baseline newer than the new scan before calculating policy impact", async () => {
    vi.mocked(getScan).mockReturnValue({ ...cleanScan, id: "future-scan", createdAt: "2026-08-25T12:00:00.000Z" });

    const response = await POST(request({
      packageJson: "{}",
      packageLock: "{}",
      baselineScanId: "future-scan",
    }));
    const body = await response.json();

    expect(response.status).toBe(409);
    expect(body).toMatchObject({ exitCode: 2, error: { code: "BASELINE_CHRONOLOGY_INVALID" } });
    expect(saveScan).not.toHaveBeenCalled();
  });
});

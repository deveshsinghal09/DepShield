import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Scan } from "@/lib/types";

vi.mock("@/lib/feature-flags", () => ({ getFeatureFlags: () => ({ attackReplay: true }) }));
vi.mock("@/server/db", () => ({ getScan: vi.fn(), saveReplayEvidence: vi.fn() }));

import { getScan, saveReplayEvidence } from "@/server/db";
import { POST } from "./route";

const scan: Scan = {
  id: "scan-local",
  createdAt: "2026-08-24T00:00:00.000Z",
  project: "vulnerable-demo",
  branch: "uploaded",
  score: 20,
  grade: "F",
  dependencies: 1,
  vulnerable: 1,
  critical: 1,
  duration: 1,
  items: [{
    name: "lodash",
    version: "4.17.11",
    direct: true,
    path: "vulnerable-demo → lodash@4.17.11",
    license: "MIT",
    vulnerabilities: [{
      id: "CVE-2019-10744",
      cveAlias: "CVE-2019-10744",
      cvss: 9.1,
      severity: "critical",
      summary: "Prototype pollution",
    }],
    risk: 95,
    latest: "4.17.21",
    recommendation: "upgrade",
  }],
};

function request(body: unknown) {
  return new Request("http://localhost/api/attack-replay", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("safe Attack Replay API", () => {
  beforeEach(() => {
    vi.mocked(getScan).mockReturnValue(scan);
    vi.mocked(saveReplayEvidence).mockReset();
  });

  afterEach(() => vi.unstubAllGlobals());

  it("requires evidence identifiers and accepts no target or payload", async () => {
    const response = await POST(request({ target: "https://example.com", command: "whoami" }));
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: { code: "INVALID_REPLAY_REQUEST" } });
  });

  it("calls only the fixed localhost fixture and records replay evidence", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({
      demo: "fixed demonstration",
      dependency: "lodash@4.17.11",
      vulnerable: true,
      cleanupVerified: true,
      safety: "In-memory only.",
    }), { status: 200, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetcher);

    const response = await POST(request({
      scanId: scan.id,
      dependencyName: "lodash",
      dependencyVersion: "4.17.11",
      vulnerabilityId: "CVE-2019-10744",
    }));

    expect(response.status).toBe(200);
    expect(fetcher).toHaveBeenCalledWith(
      "http://127.0.0.1:4100/demo/prototype-pollution",
      expect.objectContaining({ method: "POST" }),
    );
    expect(saveReplayEvidence).toHaveBeenCalledWith(scan.id, expect.objectContaining({
      vulnerabilityId: "CVE-2019-10744",
      observed: true,
      cleanupVerified: true,
    }));
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Scan } from "../../../../../lib/types";

vi.mock("../../../../../server/db", () => ({
  getScan: vi.fn(),
  listReplayEvidence: vi.fn(() => []),
}));

vi.mock("../../../../../lib/security-exports", () => ({
  createSecurityEvidencePack: vi.fn(() => ({ ok: true })),
}));

import { createSecurityEvidencePack } from "../../../../../lib/security-exports";
import { getScan } from "../../../../../server/db";
import { GET } from "./route";

function scan(id: string, createdAt: string): Scan {
  return {
    id,
    createdAt,
    project: "demo",
    branch: "main",
    score: 100,
    grade: "A",
    dependencies: 0,
    vulnerable: 0,
    critical: 0,
    duration: 1,
    items: [],
  };
}

describe("scan evidence export comparison", () => {
  beforeEach(() => vi.clearAllMocks());

  it("rejects a baseline newer than the exported scan before building impact evidence", async () => {
    const current = scan("current", "2026-08-24T12:00:00.000Z");
    const future = scan("future", "2026-08-25T12:00:00.000Z");
    vi.mocked(getScan).mockImplementation((id) => id === "current" ? current : id === "future" ? future : null);

    const response = await GET(
      new Request("http://localhost/api/scans/current/evidence?before=future"),
      { params: Promise.resolve({ id: "current" }) },
    );

    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: { code: "BASELINE_CHRONOLOGY_INVALID" } });
    expect(createSecurityEvidencePack).not.toHaveBeenCalled();
  });
});

import { describe, expect, it } from "vitest";
import type { Scan } from "./types";
import { resolveScanSelection } from "./scan-resolution";

function scan(id: string): Scan {
  return {
    id,
    createdAt: "2026-08-24T12:00:00.000Z",
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

describe("saved scan resolution", () => {
  it("does not silently fall back when an explicit scan ID is unavailable", () => {
    const result = resolveScanSelection([scan("latest")], "deleted-scan");
    expect(result).toEqual({ status: "missing", scan: null, explicit: true, requestedId: "deleted-scan" });
  });

  it("uses the configured fallback only when no explicit ID was supplied", () => {
    const scans = [scan("latest"), scan("demo")];
    expect(resolveScanSelection(scans, undefined, { fallback: (items) => items[1] })).toMatchObject({
      status: "resolved",
      explicit: false,
      scan: { id: "demo" },
    });
  });

  it("does not replace an intentionally empty custom fallback with the latest scan", () => {
    expect(resolveScanSelection([scan("only")], undefined, { fallback: () => undefined })).toMatchObject({
      status: "empty",
      scan: null,
    });
  });

  it("can resolve an explicit snapshot outside the visible history list", () => {
    const archived = scan("archived");
    expect(resolveScanSelection([scan("latest")], "archived", { lookup: () => archived })).toMatchObject({
      status: "resolved",
      explicit: true,
      scan: { id: "archived" },
    });
  });
});

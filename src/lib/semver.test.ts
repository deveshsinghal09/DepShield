import { describe, expect, it } from "vitest";
import { compareExactVersions, isVersionInRange } from "./semver";

describe("conservative semver helpers", () => {
  it("compares exact versions", () => {
    expect(compareExactVersions("4.17.21", "4.17.11")).toBeGreaterThan(0);
  });

  it("handles common audit ranges", () => {
    expect(isVersionInRange("4.17.11", ">=4.0.0 <4.17.12")).toBe(true);
    expect(isVersionInRange("4.17.21", ">=4.0.0 <4.17.12")).toBe(false);
    expect(isVersionInRange("1.4.0", "1.2.0 - 1.5.0")).toBe(true);
  });

  it("returns unknown for unsupported expressions", () => {
    expect(isVersionInRange("1.0.0", "workspace:*")).toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import { estimateUpgradeImpact } from "./compatibility";

describe("upgrade impact predictor", () => {
  it("keeps a small, observed patch update in the low-risk band", () => {
    const result = estimateUpgradeImpact({
      currentVersion: "4.17.11",
      targetVersion: "4.17.21",
      direct: true,
      importedApis: ["defaultsDeep"],
      relatedRoutes: ["POST /profile"],
    });
    expect(result).toMatchObject({ semverChange: "patch", risk: "low", confidence: "medium" });
    expect(result.score).toBe(22);
  });

  it("classifies a direct major update with broad usage as high risk", () => {
    const result = estimateUpgradeImpact({
      currentVersion: "4.21.2",
      targetVersion: "5.0.0",
      direct: true,
      importedApis: ["Router", "json", "urlencoded", "static", "request", "response"],
      relatedRoutes: ["GET /", "POST /profile", "POST /login"],
    });
    expect(result.semverChange).toBe("major");
    expect(result.risk).toBe("high");
    expect(result.score).toBeGreaterThanOrEqual(90);
  });

  it("labels non-semver input as low-confidence instead of claiming certainty", () => {
    const result = estimateUpgradeImpact({ currentVersion: "workspace:*", targetVersion: "latest", direct: false });
    expect(result).toMatchObject({ semverChange: "unknown", confidence: "low", risk: "medium" });
    expect(result.uncertainty).toContain("not verified");
  });

  it("deduplicates observed APIs and routes", () => {
    const result = estimateUpgradeImpact({
      currentVersion: "1.0.0",
      targetVersion: "1.1.0",
      direct: true,
      importedApis: ["parse", "parse", ""],
      relatedRoutes: ["GET /health", "GET /health"],
    });
    expect(result.reasons).toContain("1 imported API was observed in application code.");
    expect(result.testingFocus).toEqual(["Verify calls to parse.", "Exercise GET /health."]);
  });
});

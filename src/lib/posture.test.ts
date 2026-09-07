import { describe, expect, it } from "vitest";
import type { Dependency } from "./types";
import { calculatePosture, fixableRiskPercent } from "./posture";

const clean: Dependency = {
  name: "clean",
  version: "1.0.0",
  direct: true,
  path: "app → clean@1.0.0",
  license: "MIT",
  vulnerabilities: [],
  risk: 0,
  latest: "1.0.0",
  recommendation: "none",
};

describe("posture radar", () => {
  it("returns a perfect clean posture", () => {
    expect(calculatePosture([clean], 100).knownVulnerabilityRisk).toBe(100);
    expect(fixableRiskPercent([clean])).toBe(100);
  });

  it("makes every dimension a bounded posture score", () => {
    const values = Object.values(calculatePosture([{ ...clean, risk: 100, depth: 12 }], 0));
    expect(values.every((value) => value >= 0 && value <= 100)).toBe(true);
  });
});

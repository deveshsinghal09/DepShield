import { describe, expect, it } from "vitest";
import type { Dependency } from "./types";
import { generateUpgradePlan, remediationLabel } from "./remediation";

const dependency = (values: Partial<Dependency>): Dependency => ({
  name: "lodash",
  version: "4.17.11",
  direct: true,
  path: "app → lodash@4.17.11",
  license: "MIT",
  vulnerabilities: [{
    id: "CVE-2019-10744",
    cvss: 9.1,
    severity: "critical",
    summary: "Prototype pollution",
    fixedVersion: "4.17.12",
  }],
  risk: 100,
  latest: "4.17.12",
  recommendation: "upgrade",
  ...values,
});

describe("remediation labels", () => {
  it("labels patch, minor, major and parent upgrades", () => {
    expect(remediationLabel(dependency({}))).toBe("Safe Auto Fix");
    expect(remediationLabel(dependency({ latest: "4.18.0" }))).toBe("Minor Upgrade");
    expect(remediationLabel(dependency({ latest: "5.0.0" }))).toBe("Major Upgrade");
    expect(remediationLabel(dependency({ direct: false }))).toBe("Update Parent Dependency");
  });

  it("separates no-fix and partial-fix findings", () => {
    expect(remediationLabel(dependency({ recommendation: "no-fix", latest: "4.17.11" }))).toBe("No Fix Available");
    expect(remediationLabel(dependency({ recommendation: "partial-fix", latest: "4.17.11" }))).toBe("Manual Review");
  });
});

describe("upgrade plan", () => {
  it("orders risk first and effort second", () => {
    const plan = generateUpgradePlan([
      dependency({ name: "hard", risk: 90, latest: "5.0.0" }),
      dependency({ name: "easy", risk: 90 }),
      dependency({ name: "lower", risk: 70 }),
    ]);
    expect(plan.map((item) => item.dependency.name)).toEqual(["easy", "hard", "lower"]);
  });

  it("does not present a transitive child version as a safe direct target", () => {
    const [plan] = generateUpgradePlan([dependency({ direct: false, parentPackages: ["parent@1.0.0"] })]);
    expect(plan).toMatchObject({ classification: "UPDATE PARENT", targetVersion: null, expectedRiskReduction: 0 });
    expect(plan.conflicts?.[0]).toContain("parent@1.0.0");
  });

  it("marks partial resolution as manual review and keeps remaining findings", () => {
    const [plan] = generateUpgradePlan([dependency({
      recommendation: "partial-fix",
      latest: "4.17.11",
      vulnerabilities: [
        { id: "CVE-fixed", cvss: 8, severity: "high", summary: "fixed", fixedVersion: "4.17.12" },
        { id: "CVE-open", cvss: 7, severity: "high", summary: "open", fixedVersion: null },
      ],
    })]);
    expect(plan).toMatchObject({
      classification: "MANUAL REVIEW",
      targetVersion: "4.17.12",
      cvesResolved: ["CVE-fixed"],
      remainingCves: ["CVE-open"],
    });
  });
});

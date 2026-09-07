import { describe, expect, it } from "vitest";
import {
  analyzeReachability,
  dependencyReachabilityKey,
  findReachability,
  type DependencyReachabilityInput,
  type SourceFileInput,
} from "./reachability";

const lodash: DependencyReachabilityInput = {
  name: "lodash",
  version: "4.17.11",
  direct: true,
  vulnerableApis: ["defaultsDeep"],
  paths: [{ nodes: ["demo", "lodash@4.17.11"] }],
};

describe("bounded static reachability", () => {
  it("builds route → module → package evidence and matches an observed API", () => {
    const files: SourceFileInput[] = [
      {
        path: "src/app/api/profile/route.ts",
        content: `
          import { mergeProfile } from "../../../lib/merge";
          export async function POST() { return mergeProfile({}); }
        `,
      },
      {
        path: "src/lib/merge.ts",
        content: `
          import defaultsDeep from "lodash/defaultsDeep";
          export const mergeProfile = (value: object) => defaultsDeep({}, value);
        `,
      },
    ];

    const analysis = analyzeReachability(files, [lodash]);
    const finding = findReachability(analysis, "lodash", "4.17.11")!;

    expect(analysis.complete).toBe(true);
    expect(finding.status).toBe("REACHABLE");
    expect(finding.vulnerableApiMatch).toBe("MATCHED");
    expect(finding.matchedVulnerableApis).toEqual(["defaultsDeep"]);
    expect(finding.paths[0].nodes).toEqual([
      "POST /api/profile",
      "src/app/api/profile/route.ts",
      "src/lib/merge.ts",
      "lodash@4.17.11",
    ]);
    expect(finding.blastRadius.counts).toMatchObject({ routes: 1, sourceFiles: 2 });
  });

  it("recognizes literal require calls behind an Express route", () => {
    const analysis = analyzeReachability(
      [
        {
          path: "src/server.ts",
          content: `
            import { handle } from "./handler";
            app.post("/profile", handle);
          `,
        },
        {
          path: "src/handler.ts",
          content: `
            const qs = require("qs");
            export const handle = (request: { query: string }) => qs.parse(request.query);
          `,
        },
      ],
      [{ name: "qs", version: "6.5.2", direct: true, vulnerableApis: ["parse"] }],
    );
    const finding = findReachability(analysis, "qs", "6.5.2")!;

    expect(finding.status).toBe("REACHABLE");
    expect(finding.observedApis).toContain("parse");
    expect(finding.blastRadius.routes[0]).toMatchObject({ method: "POST", route: "/profile" });
  });

  it("classifies an imported-parent transitive path as only possibly reachable", () => {
    const analysis = analyzeReachability(
      [
        {
          path: "src/server.ts",
          content: `
            import express from "express";
            const app = express();
            app.get("/", (_req, res) => res.end("ok"));
          `,
        },
      ],
      [
        {
          name: "qs",
          version: "6.5.2",
          direct: false,
          paths: [{ nodes: ["demo", "express@4.17.1", "body-parser@1.19.0", "qs@6.5.2"] }],
        },
      ],
    );
    const finding = findReachability(analysis, "qs", "6.5.2")!;

    expect(finding.status).toBe("POSSIBLY_REACHABLE");
    expect(finding.paths.some((item) => item.kind === "TRANSITIVE_PARENT")).toBe(true);
    expect(finding.paths[0].nodes).toContain("express@4.17.1");
    expect(finding.blastRadius.parentDependencies).toEqual(["body-parser@1.19.0", "express@4.17.1"]);
  });

  it("uses NOT_OBSERVED without claiming that absence is safe", () => {
    const analysis = analyzeReachability(
      [{ path: "src/index.ts", content: `import "./ready";` }, { path: "src/ready.ts", content: "export const ready = true;" }],
      [{ name: "axios", version: "1.7.0", direct: true }],
    );
    const finding = findReachability(analysis, "axios", "1.7.0")!;

    expect(analysis.complete).toBe(true);
    expect(finding.status).toBe("NOT_OBSERVED");
    expect(finding.explanation.toLowerCase()).toContain("not proof");
    expect(finding.limitations.join(" ").toLowerCase()).toContain("not_observed");
  });

  it("returns UNKNOWN when a dynamic module reference makes the bundle incomplete", () => {
    const analysis = analyzeReachability(
      [{ path: "src/index.ts", content: "const moduleName = process.env.MODULE; require(moduleName);" }],
      [{ name: "axios", version: "1.7.0", direct: true }],
    );

    expect(analysis.complete).toBe(false);
    expect(findReachability(analysis, "axios", "1.7.0")?.status).toBe("UNKNOWN");
    expect(analysis.warnings.some((warning) => warning.code === "DYNAMIC_MODULE_REFERENCE")).toBe(true);
  });

  it("does not treat TypeScript type-only imports as runtime reachability", () => {
    const analysis = analyzeReachability(
      [{ path: "src/index.ts", content: `import type { AxiosRequestConfig } from "axios"; export type Config = AxiosRequestConfig;` }],
      [{ name: "axios", version: "1.7.0", direct: true }],
    );

    expect(findReachability(analysis, "axios", "1.7.0")?.status).toBe("NOT_OBSERVED");
    expect(analysis.stats.packageImports).toBe(0);
  });

  it("downgrades exact-version confidence when multiple instances share a package name", () => {
    const analysis = analyzeReachability(
      [{ path: "src/index.ts", content: `import lodash from "lodash"; lodash.merge({}, {});` }],
      [
        { name: "lodash", version: "4.17.11", direct: false },
        { name: "lodash", version: "3.10.1", direct: false },
      ],
    );

    expect(analysis.findings.map((finding) => finding.status)).toEqual([
      "POSSIBLY_REACHABLE",
      "POSSIBLY_REACHABLE",
    ]);
  });

  it("enforces bundle, file-size, and path boundaries without partial absence claims", () => {
    const tooMany = analyzeReachability(
      [
        { path: "src/a.ts", content: "export {};" },
        { path: "src/b.ts", content: "export {};" },
      ],
      [lodash],
      { maxFiles: 1 },
    );
    expect(tooMany.errors[0].code).toBe("SOURCE_FILE_LIMIT");
    expect(findReachability(tooMany, "lodash", "4.17.11")?.status).toBe("UNKNOWN");

    const unsafe = analyzeReachability(
      [{ path: "../secret.ts", content: "export {};" }],
      [lodash],
    );
    expect(unsafe.errors.some((error) => error.code === "INVALID_SOURCE_PATH")).toBe(true);
    expect(findReachability(unsafe, "lodash", "4.17.11")?.status).toBe("UNKNOWN");

    const oversized = analyzeReachability(
      [{ path: "src/large.ts", content: "x".repeat(25) }],
      [lodash],
      { maxFileBytes: 10 },
    );
    expect(oversized.errors.some((error) => error.code === "SOURCE_FILE_SIZE_LIMIT")).toBe(true);
    expect(findReachability(oversized, "lodash", "4.17.11")?.status).toBe("UNKNOWN");
  });

  it("exports a stable name/version key helper", () => {
    expect(dependencyReachabilityKey("@scope/package", "1.2.3")).toBe("@scope/package@1.2.3");
  });
});

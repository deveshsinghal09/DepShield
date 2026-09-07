import { describe, expect, it, vi } from "vitest";

vi.mock("node:child_process", () => ({ execFile: vi.fn() }));

describe("npm audit error handling", () => {
  it("does not report registry error JSON as a successful clean audit", async () => {
    const childProcess = await import("node:child_process");
    vi.mocked(childProcess.execFile).mockImplementation((...args: unknown[]) => {
      const callback = args.at(-1) as (error: unknown, stdout: string, stderr: string) => void;
      const error = Object.assign(new Error("audit endpoint returned an error"), {
        code: 1,
        stdout: JSON.stringify({ message: "request failed", error: { summary: "registry unavailable" } }),
        stderr: "npm error audit endpoint returned an error",
      });
      callback(error, error.stdout, error.stderr);
      return undefined as never;
    });

    const { runNpmAudit } = await import("./npm-audit");
    const result = await runNpmAudit("{}", "{}");

    expect(result.status.status).toBe("failed");
    expect(result.warning).toContain("registry unavailable");
    expect(result.findings.size).toBe(0);
  });

  it("keeps a severity hint without inventing a CVSS score", async () => {
    const childProcess = await import("node:child_process");
    vi.mocked(childProcess.execFile).mockImplementation((...args: unknown[]) => {
      const callback = args.at(-1) as (error: unknown, stdout: string, stderr: string) => void;
      callback(null, JSON.stringify({ vulnerabilities: { demo: { severity: "high", via: [{ source: 1, title: "advisory", severity: "high", range: "<2.0.0", url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" }], range: "<2.0.0", fixAvailable: false } } }), "");
      return undefined as never;
    });
    const { runNpmAudit } = await import("./npm-audit");
    const result = await runNpmAudit("{}", "{}");
    expect(result.findings.get("demo")?.[0]).toMatchObject({ cvss: 0, cvssAvailable: false, severity: "high" });
  });
});

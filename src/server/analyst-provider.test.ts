import { describe, expect, it, vi } from "vitest";
import { answerScanQuestion, buildAnalystEvidence } from "../lib/analyst";
import type { Dependency, Scan } from "../lib/types";
import { answerWithOptionalAnalystProvider, validateExternalAnalystAnswer } from "./analyst-provider";

const dependency: Dependency = {
  name: "lodash",
  version: "4.17.11",
  direct: true,
  path: "app → lodash@4.17.11",
  paths: [{ nodes: ["app", "lodash@4.17.11"], display: "app → lodash@4.17.11" }],
  license: "MIT",
  vulnerabilities: [{
    id: "CVE-2019-10744",
    cveAlias: "CVE-2019-10744",
    cvss: 9.1,
    severity: "critical",
    summary: "Prototype pollution",
    fixedVersion: "4.17.12",
    sources: ["OSV"],
  }],
  risk: 94,
  latest: "4.17.21",
  recommendation: "upgrade",
};

const scan: Scan = {
  id: "scan-1",
  createdAt: "2026-01-01T00:00:00.000Z",
  project: "app",
  branch: "main",
  score: 55,
  grade: "E",
  dependencies: 1,
  vulnerable: 1,
  critical: 1,
  duration: 1,
  items: [dependency],
};

describe("optional analyst provider", () => {
  it("uses the fixed Gemini endpoint, default model, and server-only key when configured", async () => {
    const question = "Why is lodash ranked first?";
    const deterministic = answerScanQuestion(scan, question);
    const evidence = buildAnalystEvidence(scan, question);
    let requestedUrl = "";
    let requestBody = "";
    let authorization = "";
    const fetcher = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      requestedUrl = String(url);
      requestBody = String(init?.body ?? "");
      authorization = new Headers(init?.headers).get("authorization") ?? "";
      return new Response(JSON.stringify({
        choices: [{ message: { content: JSON.stringify({
          answer: "Lodash is the highest recorded priority. [Dependency: lodash@4.17.11]",
          citations: [{ label: "Dependency", value: "lodash@4.17.11" }],
        }) } }],
      }), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;

    const answer = await answerWithOptionalAnalystProvider({
      question,
      evidence,
      deterministic,
      environment: {
        GEMINI_API_KEY: "gemini-test-key",
        DEPSHIELD_AI_API_KEY: "custom-provider-key",
        DEPSHIELD_AI_BASE_URL: "https://provider.invalid/v1",
      },
      fetcher,
    });

    expect(requestedUrl).toBe("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions");
    expect(authorization).toBe("Bearer gemini-test-key");
    expect(JSON.parse(requestBody)).toMatchObject({
      model: "gemini-3.7-flash",
      temperature: 0,
      response_format: { type: "json_schema" },
    });
    expect(requestBody).not.toContain("gemini-test-key");
    expect(requestBody).not.toContain("custom-provider-key");
    expect(answer).toMatchObject({ provider: "gemini", supported: true });
  });

  it("supports a Gemini model override while preserving deterministic failure fallback", async () => {
    const question = "Why is lodash ranked first?";
    const deterministic = answerScanQuestion(scan, question);
    const evidence = buildAnalystEvidence(scan, question);
    let requestBody = "";
    const fetcher = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      requestBody = String(init?.body ?? "");
      return new Response("rate limited", { status: 429 });
    }) as typeof fetch;

    const answer = await answerWithOptionalAnalystProvider({
      question,
      evidence,
      deterministic,
      environment: { GEMINI_API_KEY: "gemini-test-key", GEMINI_MODEL: "gemini-custom-model" },
      fetcher,
    });

    expect(JSON.parse(requestBody)).toMatchObject({ model: "gemini-custom-model" });
    expect(answer).toEqual(deterministic);
  });

  it("accepts only allowlisted citations and sends normalized evidence", async () => {
    const question = "Why is lodash ranked first?";
    const deterministic = answerScanQuestion(scan, question);
    const evidence = buildAnalystEvidence(scan, question);
    let requestBody = "";
    const fetcher = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      requestBody = String(init?.body ?? "");
      return new Response(JSON.stringify({
        choices: [{ message: { content: JSON.stringify({
          answer: "Lodash leads because its contextual evidence has the highest recorded priority. [Dependency: lodash@4.17.11] [CVE: CVE-2019-10744]",
          citations: [
            { label: "Dependency", value: "lodash@4.17.11" },
            { label: "CVE", value: "CVE-2019-10744" },
          ],
        }) } }],
      }), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;

    const answer = await answerWithOptionalAnalystProvider({
      question,
      evidence,
      deterministic,
      environment: { DEPSHIELD_AI_API_KEY: "test-key", DEPSHIELD_AI_BASE_URL: "https://provider.invalid/v1", DEPSHIELD_AI_MODEL: "test-model" },
      fetcher,
    });
    expect(answer).toMatchObject({ provider: "external", supported: true });
    expect(answer.citations).toHaveLength(2);
    const payload = JSON.parse(requestBody) as { messages: Array<{ role: string; content: string }> };
    const structured = JSON.parse(payload.messages.find(message => message.role === "user")!.content) as Record<string, unknown>;
    expect(structured).toHaveProperty("evidence");
    expect(JSON.stringify(structured)).not.toContain('"sourceFiles"');
    expect(JSON.stringify(structured)).not.toContain("sourceContent");
  });

  it("rejects invented citations and falls back deterministically", async () => {
    const question = "Why is lodash ranked first?";
    const deterministic = answerScanQuestion(scan, question);
    const evidence = buildAnalystEvidence(scan, question);
    const invalid = validateExternalAnalystAnswer({
      answer: "Invented package is first.",
      citations: [{ label: "Dependency", value: "invented@9.9.9" }],
    }, evidence);
    expect(invalid).toBeNull();

    const fetcher = vi.fn(async () => new Response(JSON.stringify({
      choices: [{ message: { content: JSON.stringify({ answer: "Invented package is first.", citations: [{ label: "Dependency", value: "invented@9.9.9" }] }) } }],
    }), { status: 200 })) as unknown as typeof fetch;
    const answer = await answerWithOptionalAnalystProvider({
      question,
      evidence,
      deterministic,
      environment: { DEPSHIELD_AI_API_KEY: "test-key" },
      fetcher,
    });
    expect(answer).toEqual(deterministic);
  });

  it("rejects invented scores even when citations are valid", () => {
    const question = "Why is lodash ranked first?";
    const deterministic = answerScanQuestion(scan, question);
    const evidence = buildAnalystEvidence(scan, question);

    const invalid = validateExternalAnalystAnswer({
      answer: "Lodash has a priority score of 99. [Dependency: lodash@4.17.11]",
      citations: [{ label: "Dependency", value: "lodash@4.17.11" }],
    }, evidence, deterministic);

    expect(invalid).toBeNull();
  });

  it("does not call a provider without credentials", async () => {
    const question = "Why is lodash ranked first?";
    const deterministic = answerScanQuestion(scan, question);
    const evidence = buildAnalystEvidence(scan, question);
    const fetcher = vi.fn() as unknown as typeof fetch;
    const answer = await answerWithOptionalAnalystProvider({ question, evidence, deterministic, environment: {}, fetcher });
    expect(answer).toEqual(deterministic);
    expect(fetcher).not.toHaveBeenCalled();
  });
});

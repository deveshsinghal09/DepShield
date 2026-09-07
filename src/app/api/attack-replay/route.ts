import { NextResponse } from "next/server";
import { getFeatureFlags } from "@/lib/feature-flags";
import { getScan, saveReplayEvidence } from "@/server/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const demoUrl = "http://127.0.0.1:4100/demo/prototype-pollution";

type ReplayRequest = {
  scanId?: unknown;
  dependencyName?: unknown;
  dependencyVersion?: unknown;
  vulnerabilityId?: unknown;
};

type ReplayResult = {
  demo?: string;
  dependency?: string;
  vulnerable?: boolean;
  cleanupVerified?: boolean;
  safety?: string;
  error?: string;
};

export async function POST(request: Request) {
  if (!getFeatureFlags().attackReplay) {
    return invalid(
      "REPLAY_DISABLED",
      "Attack Replay is disabled. Enable it only for a trusted local DepShield and vulnerable-demo session.",
      403,
    );
  }

  let body: ReplayRequest;
  try {
    body = await request.json() as ReplayRequest;
  } catch {
    return invalid("INVALID_REPLAY_REQUEST", "Replay requires selected scan evidence.");
  }
  if (
    typeof body.scanId !== "string"
    || typeof body.dependencyName !== "string"
    || typeof body.dependencyVersion !== "string"
    || typeof body.vulnerabilityId !== "string"
  ) {
    return invalid("INVALID_REPLAY_REQUEST", "scanId, dependencyName, dependencyVersion, and vulnerabilityId are required.");
  }
  const scanId = body.scanId;
  const dependencyName = body.dependencyName;
  const dependencyVersion = body.dependencyVersion;
  const vulnerabilityId = body.vulnerabilityId.toUpperCase();

  const scan = getScan(scanId);
  if (!scan) return invalid("SCAN_NOT_FOUND", "The selected scan does not exist.", 404);
  const dependency = scan.items.find((item) =>
    item.name === dependencyName
    && item.version === dependencyVersion
    && item.name === "lodash"
    && /^4\.17\.(?:11|21)$/.test(item.version));
  if (!dependency) {
    return invalid("UNSUPPORTED_REPLAY", "The fixed local replay supports only lodash 4.17.11 or 4.17.21 recorded in the selected scan.", 422);
  }
  const finding = dependency.vulnerabilities.find((item) =>
    (item.cveAlias ?? item.id).toUpperCase() === vulnerabilityId);
  const remediatedReplay = dependency.version === "4.17.21" && vulnerabilityId === "CVE-2019-10744";
  if (!finding && !remediatedReplay) {
    return invalid("FINDING_NOT_IN_SCAN", "The selected vulnerability is not supported by this scan evidence.", 422);
  }

  try {
    const response = await fetch(demoUrl, {
      method: "POST",
      headers: { accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(5_000),
    });
    const result = await response.json() as ReplayResult;
    if (!response.ok) throw new Error(result.error ?? `Demo returned HTTP ${response.status}`);

    const executedAt = new Date().toISOString();
    saveReplayEvidence(scan.id, {
      dependency: `${dependency.name}@${dependency.version}`,
      vulnerabilityId,
      observed: result.vulnerable === true,
      cleanupVerified: result.cleanupVerified === true,
      executedAt,
      route: "POST 127.0.0.1:4100/demo/prototype-pollution",
      safety: result.safety ?? "Fixed in-memory localhost demonstration.",
    });
    return NextResponse.json({
      data: result,
      meta: {
        target: "fixed-localhost-fixture",
        route: "POST /demo/prototype-pollution",
        evidenceRecordedAt: executedAt,
        scanId: scan.id,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "The local demo did not respond.";
    return invalid(
      "DEMO_UNAVAILABLE",
      `Could not reach the local fixture at 127.0.0.1:4100. Start it with npm run demo:start. ${message}`,
      503,
    );
  }
}

function invalid(code: string, message: string, status = 400) {
  return NextResponse.json({ error: { code, message } }, { status, headers: { "cache-control": "no-store" } });
}

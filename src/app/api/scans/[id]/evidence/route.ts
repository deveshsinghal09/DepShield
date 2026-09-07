import { NextResponse } from "next/server";
import { createSecurityEvidencePack } from "../../../../../lib/security-exports";
import { validateScanComparison } from "../../../../../lib/scan-selectors";
import { getScan, listReplayEvidence } from "../../../../../server/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: RouteContext) {
  const { id } = await context.params;
  if (!validScanId(id)) return invalid("INVALID_SCAN_ID", "The scan identifier is invalid.");
  const scan = getScan(id);
  if (!scan) return missing("SCAN_NOT_FOUND", "The requested scan does not exist.");

  const baselineId = new URL(request.url).searchParams.get("before");
  if (baselineId && !validScanId(baselineId)) return invalid("INVALID_BASELINE_SCAN_ID", "The baseline scan identifier is invalid.");
  const previousScan = baselineId ? getScan(baselineId) : undefined;
  if (baselineId && !previousScan) return missing("BASELINE_SCAN_NOT_FOUND", "The requested baseline scan does not exist.");
  const comparison = previousScan ? validateScanComparison(previousScan, scan) : null;
  if (comparison && !comparison.valid) {
    return NextResponse.json(
      { error: { code: comparison.code === "PROJECT_MISMATCH" ? "BASELINE_PROJECT_MISMATCH" : "BASELINE_CHRONOLOGY_INVALID", message: comparison.message } },
      { status: 409 },
    );
  }

  return NextResponse.json(createSecurityEvidencePack(scan, {
    previousScan: previousScan ?? undefined,
    replayEvidence: listReplayEvidence(scan.id),
  }), {
    headers: {
      "cache-control": "no-store",
      "content-disposition": `attachment; filename="${safeFilename(scan.project)}-evidence-${scan.id.slice(0, 8)}.json"`,
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function invalid(code: string, message: string) {
  return NextResponse.json({ error: { code, message } }, { status: 400 });
}

function missing(code: string, message: string) {
  return NextResponse.json({ error: { code, message } }, { status: 404 });
}

function validScanId(value: string) {
  return value.length > 0 && value.length <= 128 && /^[A-Za-z0-9_-]+$/.test(value);
}

function safeFilename(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "depshield";
}

import { NextResponse } from "next/server";
import { createCycloneDxSbom } from "../../../../../lib/security-exports";
import { getScan } from "../../../../../server/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = { params: Promise<{ id: string }> };

export async function GET(_request: Request, context: RouteContext) {
  const { id } = await context.params;
  if (!validScanId(id)) {
    return NextResponse.json(
      { error: { code: "INVALID_SCAN_ID", message: "The scan identifier is invalid." } },
      { status: 400 },
    );
  }
  const scan = getScan(id);
  if (!scan) {
    return NextResponse.json(
      { error: { code: "SCAN_NOT_FOUND", message: "The requested scan does not exist." } },
      { status: 404 },
    );
  }
  return NextResponse.json(createCycloneDxSbom(scan), {
    headers: {
      "cache-control": "no-store",
      "content-disposition": `attachment; filename="${safeFilename(scan.project)}-sbom.json"`,
      "content-type": "application/vnd.cyclonedx+json; charset=utf-8",
    },
  });
}

function validScanId(value: string) {
  return value.length > 0 && value.length <= 128 && /^[A-Za-z0-9_-]+$/.test(value);
}

function safeFilename(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "depshield";
}

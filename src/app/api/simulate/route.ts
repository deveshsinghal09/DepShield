import { NextResponse } from "next/server";
import { getFeatureFlags } from "@/lib/feature-flags";
import { simulateDependencyUpgrade } from "@/lib/remediation-sandbox";
import { getScan } from "@/server/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    if (!getFeatureFlags().remediationSandbox) {
      return NextResponse.json({ error: { code: "FEATURE_DISABLED", message: "Remediation Sandbox is disabled." } }, { status: 404 });
    }
    const body = await request.json() as {
      scanId?: unknown;
      dependencyName?: unknown;
      installedVersion?: unknown;
      dependencyPath?: unknown;
      targetVersion?: unknown;
    };
    if (typeof body.scanId !== "string" || typeof body.dependencyName !== "string" || typeof body.targetVersion !== "string") {
      return invalid("scanId, dependencyName, and targetVersion are required.");
    }
    const scan = getScan(body.scanId);
    if (!scan) return NextResponse.json({ error: { code: "SCAN_NOT_FOUND", message: "The requested scan does not exist." } }, { status: 404 });
    const data = simulateDependencyUpgrade(scan, {
      dependencyName: body.dependencyName,
      targetVersion: body.targetVersion,
      installedVersion: typeof body.installedVersion === "string" ? body.installedVersion : undefined,
      dependencyPath: typeof body.dependencyPath === "string" ? body.dependencyPath : undefined,
    });
    return NextResponse.json({ data });
  } catch (error) {
    return invalid(error instanceof Error ? error.message : "The simulation could not be completed.", 422);
  }
}

function invalid(message: string, status = 400) {
  return NextResponse.json({ error: { code: "INVALID_SIMULATION", message } }, { status });
}

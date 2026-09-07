import { NextResponse } from "next/server";
import type { SecurityPolicy } from "@/lib/policy";
import { getFeatureFlags } from "@/lib/feature-flags";
import { listSecurityPolicies, saveSecurityPolicy } from "@/server/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  if (!getFeatureFlags().policyEngine) return NextResponse.json({ error: { code: "FEATURE_DISABLED", message: "Policy Engine is disabled." } }, { status: 404 });
  return NextResponse.json({ data: listSecurityPolicies() });
}

export async function POST(request: Request) {
  if (!getFeatureFlags().policyEngine) return NextResponse.json({ error: { code: "FEATURE_DISABLED", message: "Policy Engine is disabled." } }, { status: 404 });
  try {
    const input = await request.json() as Partial<SecurityPolicy>;
    const policy = validate(input);
    return NextResponse.json({ data: saveSecurityPolicy(policy) }, { status: 201 });
  } catch (error) {
    return NextResponse.json({ error: { code: "INVALID_POLICY", message: error instanceof Error ? error.message : "Policy configuration is invalid." } }, { status: 400 });
  }
}

function validate(value: Partial<SecurityPolicy>): SecurityPolicy {
  if (typeof value.id !== "string" || !/^[a-z0-9-]{3,80}$/i.test(value.id)) throw new Error("Policy id must use letters, numbers, and hyphens.");
  if (typeof value.name !== "string" || !value.name.trim() || value.name.length > 120) throw new Error("Policy name is required and limited to 120 characters.");
  const number = (input: unknown, label: string, min: number, max: number, nullable = false) => {
    if (nullable && input === null) return null;
    if (typeof input !== "number" || !Number.isFinite(input) || input < min || input > max) throw new Error(`${label} must be between ${min} and ${max}.`);
    return input;
  };
  if (value.incompleteSourceAction !== "warning" && value.incompleteSourceAction !== "fail") throw new Error("Incomplete source action must be warning or fail.");
  return {
    id: value.id,
    name: value.name.trim(),
    enabled: value.enabled !== false,
    blockReachableCritical: value.blockReachableCritical !== false,
    minimumSecurityScore: number(value.minimumSecurityScore, "Minimum score", 0, 100)!,
    maximumCriticalFindings: number(value.maximumCriticalFindings, "Maximum critical findings", 0, 10_000)!,
    blockNoFixAtOrAboveCvss: number(value.blockNoFixAtOrAboveCvss, "CVSS threshold", 0, 10, true),
    maximumNewCriticalFindings: number(value.maximumNewCriticalFindings, "New critical threshold", 0, 10_000, true),
    incompleteSourceAction: value.incompleteSourceAction,
  };
}

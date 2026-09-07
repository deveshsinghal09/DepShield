import { NextResponse } from "next/server";
import {
  answerScanQuestion,
  buildAnalystEvidence,
  detectAnalystIntent,
  isUnsafeAnalystRequest,
} from "@/lib/analyst";
import { getFeatureFlags } from "@/lib/feature-flags";
import { getScan, listScans } from "@/server/db";
import { answerWithOptionalAnalystProvider } from "@/server/analyst-provider";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

type AnalystRequest = {
  scanId?: unknown;
  question?: unknown;
  compareScanId?: unknown;
};

export async function POST(request: Request) {
  if (!getFeatureFlags().aiAnalyst) {
    return NextResponse.json({ error: { code: "ANALYST_DISABLED", message: "DepShield Analyst is disabled by ENABLE_AI_ANALYST." } }, { status: 403 });
  }

  let body: AnalystRequest;
  try {
    body = await request.json() as AnalystRequest;
  } catch {
    return invalid("INVALID_REQUEST_JSON", "The request body is not valid JSON.");
  }
  if (typeof body.question !== "string" || !body.question.trim()) return invalid("QUESTION_REQUIRED", "A scan-related question is required.");
  if (body.question.length > 1_000) return invalid("QUESTION_TOO_LONG", "Questions are limited to 1,000 characters.", 413);
  if (body.compareScanId !== undefined && typeof body.compareScanId !== "string") return invalid("INVALID_COMPARE_SCAN", "compareScanId must be a scan ID.");

  const scan = typeof body.scanId === "string" && body.scanId.trim()
    ? getScan(body.scanId)
    : listScans(1)[0] ?? null;
  if (!scan) return invalid("SCAN_NOT_FOUND", "The requested scan does not exist.", 404);
  const comparisonScan = typeof body.compareScanId === "string" && body.compareScanId.trim()
    ? getScan(body.compareScanId)
    : null;
  if (typeof body.compareScanId === "string" && body.compareScanId.trim() && !comparisonScan) {
    return invalid("COMPARE_SCAN_NOT_FOUND", "The requested comparison scan does not exist.", 404);
  }
  if (comparisonScan && comparisonScan.project !== scan.project) {
    return invalid("COMPARE_PROJECT_MISMATCH", "Comparison scans must belong to the same project.", 409);
  }

  const history = listScans(50).filter((item) => item.project === scan.project);
  const options = { history, comparisonScan };
  const deterministic = answerScanQuestion(scan, body.question, options);
  const evidence = deterministic.supported && !isUnsafeAnalystRequest(body.question)
    ? buildAnalystEvidence(scan, body.question, options)
    : null;
  const answer = evidence
    ? await answerWithOptionalAnalystProvider({ question: body.question, evidence, deterministic })
    : deterministic;

  return NextResponse.json({
    data: answer,
    meta: {
      scanId: scan.id,
      intent: detectAnalystIntent(body.question),
      provider: answer.provider,
      deterministicFallback: answer.provider === "deterministic",
      evidenceItems: evidence?.items.length ?? 0,
    },
  });
}

function invalid(code: string, message: string, status = 400) {
  return NextResponse.json({ error: { code, message } }, { status });
}

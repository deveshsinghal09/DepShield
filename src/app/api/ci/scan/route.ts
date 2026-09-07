import { NextResponse } from "next/server";
import { DEFAULT_SECURITY_POLICY, evaluateSecurityPolicy } from "../../../../lib/policy";
import { validateScanComparison } from "../../../../lib/scan-selectors";
import { getFeatureFlags } from "../../../../lib/feature-flags";
import type { SourceFileInput } from "../../../../lib/types";
import { getScan, listSecurityPolicies, saveScan } from "../../../../server/db";
import { ManifestError } from "../../../../server/dependency-tree";
import { DEFAULT_REACHABILITY_LIMITS } from "../../../../server/reachability";
import { scanProject } from "../../../../server/scanner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 180;

const MAX_PACKAGE_JSON_BYTES = 1024 * 1024;
const MAX_PACKAGE_LOCK_BYTES = 16 * 1024 * 1024;

class CiInputError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status = 400,
  ) {
    super(message);
    this.name = "CiInputError";
  }
}

export async function POST(request: Request) {
  try {
    const body = await readBody(request);
    const packageJson = requiredText(body.packageJson, "PACKAGE_JSON_REQUIRED", "package.json is required.", MAX_PACKAGE_JSON_BYTES);
    const packageLock = requiredText(
      body.packageLock,
      "PACKAGE_LOCK_REQUIRED",
      "package-lock.json is required for a reproducible CI scan.",
      MAX_PACKAGE_LOCK_BYTES,
      422,
    );
    const sourceFiles = validateSourceFiles(body.sourceFiles);
    const baselineScan = validateBaseline(body.baselineScanId);
    const scan = await scanProject(packageJson, packageLock, {}, sourceFiles);
    const comparison = baselineScan ? validateScanComparison(baselineScan, scan) : null;
    if (comparison && !comparison.valid) {
      throw new CiInputError(
        comparison.code === "PROJECT_MISMATCH" ? "BASELINE_PROJECT_MISMATCH" : "BASELINE_CHRONOLOGY_INVALID",
        comparison.message,
        409,
      );
    }
    saveScan(scan);
    const configuredPolicy = getFeatureFlags().policyEngine
      ? listSecurityPolicies()[0] ?? DEFAULT_SECURITY_POLICY
      : { ...DEFAULT_SECURITY_POLICY, enabled: false };
    const policy = evaluateSecurityPolicy(scan, configuredPolicy, baselineScan ?? undefined);
    return NextResponse.json(
      {
        data: scan,
        policy,
        exitCode: policy.exitCode,
        meta: {
          scanId: scan.id,
          warnings: scan.warnings ?? [],
          sources: scan.sourceStatus ?? [],
          baselineScanId: baselineScan?.id ?? null,
        },
      },
      { status: 200, headers: { "cache-control": "no-store" } },
    );
  } catch (error) {
    if (error instanceof CiInputError) return scannerError(error.code, error.message, error.status);
    if (error instanceof ManifestError) {
      return scannerError(error.code, error.message, error.code === "NO_LOCKFILE" ? 422 : 400);
    }
    if (error instanceof SyntaxError) return scannerError("INVALID_REQUEST_JSON", "The request body is not valid JSON.", 400);
    console.error("DepShield CI scan failed", error);
    return scannerError(
      "SCANNER_ERROR",
      "The CI scan could not be completed. Verify the manifests, provider connectivity, and server logs.",
      500,
    );
  }
}

async function readBody(request: Request) {
  const value = await request.json() as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CiInputError("INVALID_REQUEST", "The request body must be a JSON object.");
  }
  return value as { packageJson?: unknown; packageLock?: unknown; sourceFiles?: unknown; baselineScanId?: unknown };
}

function requiredText(value: unknown, code: string, message: string, maxBytes: number, status = 400) {
  if (typeof value !== "string" || !value.trim()) throw new CiInputError(code, message, status);
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes > maxBytes) throw new CiInputError(`${code}_TOO_LARGE`, `${message.replace(/ is required\.$/, "")} exceeds the ${maxBytes} byte CI limit.`, 413);
  return value;
}

function validateSourceFiles(value: unknown): SourceFileInput[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new CiInputError("INVALID_SOURCE_FILES", "sourceFiles must be an array.");
  if (value.length > DEFAULT_REACHABILITY_LIMITS.maxFiles) {
    throw new CiInputError(
      "SOURCE_FILE_LIMIT",
      `At most ${DEFAULT_REACHABILITY_LIMITS.maxFiles} source files can be analyzed per CI scan.`,
      413,
    );
  }
  let totalBytes = 0;
  const seenPaths = new Set<string>();
  return value.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new CiInputError("INVALID_SOURCE_FILE", `sourceFiles[${index}] must be an object.`);
    }
    const source = item as { path?: unknown; content?: unknown };
    if (typeof source.path !== "string" || typeof source.content !== "string") {
      throw new CiInputError("INVALID_SOURCE_FILE", `sourceFiles[${index}] requires string path and content values.`);
    }
    const normalizedPath = validateSourcePath(source.path, index);
    const canonicalPath = normalizedPath.toLowerCase();
    if (seenPaths.has(canonicalPath)) {
      throw new CiInputError("DUPLICATE_SOURCE_PATH", `sourceFiles[${index}] duplicates the normalized path ${normalizedPath}.`);
    }
    seenPaths.add(canonicalPath);
    const fileBytes = Buffer.byteLength(source.content, "utf8");
    if (fileBytes > DEFAULT_REACHABILITY_LIMITS.maxFileBytes) {
      throw new CiInputError(
        "SOURCE_FILE_SIZE_LIMIT",
        `${source.path} exceeds the ${DEFAULT_REACHABILITY_LIMITS.maxFileBytes} byte per-file limit.`,
        413,
      );
    }
    totalBytes += fileBytes;
    if (totalBytes > DEFAULT_REACHABILITY_LIMITS.maxTotalBytes) {
      throw new CiInputError(
        "SOURCE_TOTAL_SIZE_LIMIT",
        `The source bundle exceeds the ${DEFAULT_REACHABILITY_LIMITS.maxTotalBytes} byte analysis limit.`,
        413,
      );
    }
    return { path: normalizedPath, content: source.content };
  });
}

function validateSourcePath(value: string, index: number) {
  const replaced = value.replaceAll("\\", "/");
  const parts = replaced.split("/").filter((part) => part && part !== ".");
  const normalized = parts.join("/");
  const invalid = !normalized ||
    replaced.length > DEFAULT_REACHABILITY_LIMITS.maxPathLength ||
    replaced.includes("\0") ||
    replaced.startsWith("/") ||
    /^[A-Za-z]:\//.test(replaced) ||
    parts.includes("..");
  if (invalid) throw new CiInputError("INVALID_SOURCE_PATH", `sourceFiles[${index}] contains an unsafe or invalid relative path.`);
  return normalized;
}

function validateBaseline(value: unknown) {
  if (value === undefined) return null;
  if (typeof value !== "string" || !value || value.length > 128 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new CiInputError("INVALID_BASELINE_SCAN_ID", "baselineScanId is invalid.");
  }
  const baseline = getScan(value);
  if (!baseline) throw new CiInputError("BASELINE_SCAN_NOT_FOUND", "The requested baseline scan does not exist.", 404);
  return baseline;
}

function scannerError(code: string, message: string, status: number) {
  return NextResponse.json(
    {
      data: null,
      policy: null,
      exitCode: 2 as const,
      error: { code, message },
    },
    { status, headers: { "cache-control": "no-store" } },
  );
}

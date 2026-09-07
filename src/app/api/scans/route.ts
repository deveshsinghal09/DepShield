import { NextResponse } from "next/server";
import type { SourceFileInput } from "@/lib/types";
import { getFeatureFlags } from "@/lib/feature-flags";
import { getScan, listScans, saveScan } from "@/server/db";
import { ManifestError } from "@/server/dependency-tree";
import { DEFAULT_REACHABILITY_LIMITS } from "@/server/reachability";
import { scanProject } from "@/server/scanner";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 180;

const MAX_PACKAGE_JSON_BYTES = 1024 * 1024;
const MAX_PACKAGE_LOCK_BYTES = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES = 26 * 1024 * 1024;
const MAX_CONCURRENT_SCANS = boundedInteger(process.env.DEPSHIELD_MAX_CONCURRENT_SCANS, 2, 1, 8);
let activeScans = 0;

class ScanInputError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status = 400,
  ) {
    super(message);
    this.name = "ScanInputError";
  }
}

export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get("id");
  if (id) {
    const scan = getScan(id);
    return scan
      ? NextResponse.json({ data: scan }, { headers: { "cache-control": "no-store" } })
      : invalid("SCAN_NOT_FOUND", "The requested scan does not exist.", 404);
  }
  return NextResponse.json({ data: listScans() }, { headers: { "cache-control": "no-store" } });
}

export async function POST(request: Request) {
  if (declaredRequestTooLarge(request)) {
    return invalid("REQUEST_TOO_LARGE", "The scan request exceeds the 26 MB upload limit.", 413);
  }

  try {
    const body = await readBody(request);
    const packageJson = requiredText(
      body.packageJson,
      "PACKAGE_JSON_REQUIRED",
      "package.json is required.",
      MAX_PACKAGE_JSON_BYTES,
    );
    const packageLock = requiredText(
      body.packageLock,
      "PACKAGE_LOCK_REQUIRED",
      "package-lock.json is required. Generate it with npm install --package-lock-only before scanning.",
      MAX_PACKAGE_LOCK_BYTES,
      422,
    );
    const sourceFiles = validateSourceFiles(body.sourceFiles);
    if (sourceFiles.length > 0 && !getFeatureFlags().sourceUploads) {
      return invalid(
        "SOURCE_UPLOADS_DISABLED",
        "Source-file upload is disabled for this deployment. Scan the manifests only, or enable it in a trusted private deployment.",
        403,
      );
    }
    if (activeScans >= MAX_CONCURRENT_SCANS) {
      return invalid("SCAN_BUSY", "The scanner is at its concurrency limit. Try again after the active scan completes.", 429);
    }

    activeScans++;
    try {
      const scan = saveScan(await scanProject(packageJson, packageLock, {}, sourceFiles));
      return NextResponse.json(
        { data: scan, meta: { warnings: scan.warnings ?? [], sources: scan.sourceStatus ?? [] } },
        { status: 201, headers: { "cache-control": "no-store" } },
      );
    } finally {
      activeScans--;
    }
  } catch (error) {
    if (error instanceof ScanInputError) return invalid(error.code, error.message, error.status);
    if (error instanceof ManifestError) {
      return invalid(error.code, error.message, error.code === "NO_LOCKFILE" ? 422 : 400);
    }
    if (error instanceof SyntaxError) return invalid("INVALID_REQUEST", "The request body is not valid JSON.");
    console.error("Dependency scan failed", error);
    return invalid("SCAN_FAILED", "The scan could not be completed. Verify the manifests and try again.", 500);
  }
}

async function readBody(request: Request) {
  const value = await request.json() as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ScanInputError("INVALID_REQUEST", "The request body must be a JSON object.");
  }
  return value as { packageJson?: unknown; packageLock?: unknown; sourceFiles?: unknown };
}

function requiredText(value: unknown, code: string, message: string, maxBytes: number, status = 400) {
  if (typeof value !== "string" || !value.trim()) throw new ScanInputError(code, message, status);
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new ScanInputError(`${code}_TOO_LARGE`, `The uploaded file exceeds the ${maxBytes} byte limit.`, 413);
  }
  return value;
}

function validateSourceFiles(value: unknown): SourceFileInput[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new ScanInputError("INVALID_SOURCE_FILES", "sourceFiles must be an array.");
  if (value.length > DEFAULT_REACHABILITY_LIMITS.maxFiles) {
    throw new ScanInputError("SOURCE_FILE_LIMIT", `At most ${DEFAULT_REACHABILITY_LIMITS.maxFiles} source files can be analyzed.`, 413);
  }

  let totalBytes = 0;
  const seen = new Set<string>();
  return value.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new ScanInputError("INVALID_SOURCE_FILE", `sourceFiles[${index}] must be an object.`);
    }
    const source = item as { path?: unknown; content?: unknown };
    if (typeof source.path !== "string" || typeof source.content !== "string") {
      throw new ScanInputError("INVALID_SOURCE_FILE", `sourceFiles[${index}] requires string path and content values.`);
    }
    const normalizedPath = validateSourcePath(source.path, index);
    const canonicalPath = normalizedPath.toLowerCase();
    if (seen.has(canonicalPath)) throw new ScanInputError("DUPLICATE_SOURCE_PATH", `${normalizedPath} was supplied more than once.`);
    seen.add(canonicalPath);

    const fileBytes = Buffer.byteLength(source.content, "utf8");
    if (fileBytes > DEFAULT_REACHABILITY_LIMITS.maxFileBytes) {
      throw new ScanInputError("SOURCE_FILE_SIZE_LIMIT", `${normalizedPath} exceeds the per-file analysis limit.`, 413);
    }
    totalBytes += fileBytes;
    if (totalBytes > DEFAULT_REACHABILITY_LIMITS.maxTotalBytes) {
      throw new ScanInputError("SOURCE_TOTAL_SIZE_LIMIT", "The source bundle exceeds the 8 MB analysis limit.", 413);
    }
    return { path: normalizedPath, content: source.content };
  });
}

function validateSourcePath(value: string, index: number) {
  const replaced = value.replaceAll("\\", "/");
  const parts = replaced.split("/").filter((part) => part && part !== ".");
  const normalized = parts.join("/");
  if (
    !normalized
    || replaced.length > DEFAULT_REACHABILITY_LIMITS.maxPathLength
    || replaced.includes("\0")
    || replaced.startsWith("/")
    || /^[A-Za-z]:\//.test(replaced)
    || parts.includes("..")
  ) {
    throw new ScanInputError("INVALID_SOURCE_PATH", `sourceFiles[${index}] contains an unsafe or invalid relative path.`);
  }
  return normalized;
}

function declaredRequestTooLarge(request: Request) {
  const value = request.headers.get("content-length");
  if (!value) return false;
  const bytes = Number(value);
  return Number.isFinite(bytes) && bytes > MAX_REQUEST_BYTES;
}

function boundedInteger(value: string | undefined, fallback: number, minimum: number, maximum: number) {
  const parsed = Number(value);
  return Number.isInteger(parsed) ? Math.min(maximum, Math.max(minimum, parsed)) : fallback;
}

function invalid(code: string, message: string, status = 400) {
  return NextResponse.json({ error: { code, message } }, { status, headers: { "cache-control": "no-store" } });
}

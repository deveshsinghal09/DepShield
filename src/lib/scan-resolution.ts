import type { Scan } from "./types";

export type ScanResolution =
  | { status: "resolved"; scan: Scan; explicit: boolean; requestedId: string | null }
  | { status: "missing"; scan: null; explicit: true; requestedId: string }
  | { status: "empty"; scan: null; explicit: false; requestedId: null };

type ScanResolutionOptions = {
  lookup?: (id: string) => Scan | null | undefined;
  fallback?: (scans: readonly Scan[]) => Scan | null | undefined;
};

/**
 * Resolves an optional saved-scan query without ever replacing an explicit,
 * unavailable ID with an unrelated snapshot.
 */
export function resolveScanSelection(
  scans: readonly Scan[],
  requestedId: string | undefined,
  options: ScanResolutionOptions = {},
): ScanResolution {
  if (requestedId !== undefined) {
    const scan = requestedId
      ? options.lookup?.(requestedId) ?? scans.find((item) => item.id === requestedId)
      : null;
    return scan
      ? { status: "resolved", scan, explicit: true, requestedId }
      : { status: "missing", scan: null, explicit: true, requestedId };
  }

  const scan = options.fallback ? options.fallback(scans) : scans[0];
  return scan
    ? { status: "resolved", scan, explicit: false, requestedId: null }
    : { status: "empty", scan: null, explicit: false, requestedId: null };
}

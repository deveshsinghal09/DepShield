import type { Scan } from "@/lib/types";
import { resolveScanSelection } from "@/lib/scan-resolution";
import { getScan, listScans } from "./db";

type SavedScanFallback = (scans: readonly Scan[]) => Scan | null | undefined;

/** Loads the scan list once and applies the shared explicit-ID semantics. */
export function resolveSavedScan(requestedId?: string, fallback?: SavedScanFallback) {
  const scans = listScans();
  const resolution = resolveScanSelection(scans, requestedId, {
    lookup: getScan,
    fallback,
  });
  return { scans, resolution };
}

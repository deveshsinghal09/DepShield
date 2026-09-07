import Link from "next/link";
import { FileWarning, ScanLine } from "lucide-react";
import { ScanButton } from "./scan-button";

type EmptyStateProps = {
  title?: string;
  description?: string;
  compact?: boolean;
};

export function EmptyState({
  title = "No scans yet",
  description = "Upload package.json and package-lock.json to create the first dependency risk assessment.",
  compact = false,
}: EmptyStateProps) {
  return (
    <section className={`surface surface-outline hud-panel grid place-items-center text-center ${compact ? "p-8" : "min-h-[420px] p-10"}`} data-ui="empty-state">
      <div>
        <span className="hud-label text-primary">E_LEDGER_EMPTY // 00</span>
        <span className="mx-auto mt-4 grid size-12 place-items-center border border-primary/40 text-primary"><FileWarning size={21} /></span>
        <h2 className="mt-4 text-lg font-extrabold">{title}</h2>
        <p className="mx-auto mt-2 max-w-md leading-6 text-muted-foreground">{description}</p>
        <div className="mt-5"><ScanButton /></div>
      </div>
    </section>
  );
}

export function SavedScanUnavailable({ scanId, recoveryHref }: { scanId: string; recoveryHref: string }) {
  const reference = scanId ? ` (${scanId.slice(0, 32)}${scanId.length > 32 ? "…" : ""})` : "";
  return (
    <section className="surface surface-outline hud-panel grid min-h-[420px] place-items-center p-10 text-center" data-ui="saved-scan-unavailable">
      <div>
        <span className="hud-label text-warning">E_SNAPSHOT_MISSING // 04</span>
        <span className="mx-auto mt-4 grid size-12 place-items-center border border-warning/50 text-warning"><FileWarning size={21} /></span>
        <h2 className="mt-4 text-lg font-extrabold">Saved scan unavailable</h2>
        <p className="mx-auto mt-2 max-w-lg leading-6 text-muted-foreground">The requested snapshot{reference} no longer exists or is unavailable in this environment. DepShield did not substitute another project scan.</p>
        <div className="mt-5 flex flex-wrap justify-center gap-3">
          <Link href={recoveryHref} className="inline-flex h-10 items-center justify-center rounded-[2px] border bg-transparent px-4 text-sm font-semibold hover:bg-secondary">Open available scan</Link>
          <ScanButton />
        </div>
      </div>
    </section>
  );
}

export function TableEmpty({ message = "No dependencies match these filters." }: { message?: string }) {
  return (
    <div className="grid place-items-center px-6 py-16 text-center">
      <ScanLine className="text-muted-foreground" />
      <span className="hud-label mt-3">QUERY_RESULT // 00</span>
      <b className="mt-2">Nothing to show</b>
      <p className="mt-1 text-sm text-muted-foreground">{message}</p>
    </div>
  );
}

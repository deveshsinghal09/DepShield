"use client";

import Link from "next/link";
import { useRef, useState } from "react";
import {
  ArrowDown,
  ArrowRight,
  Check,
  FileJson,
  Files,
  FolderSearch,
  LoaderCircle,
  TriangleAlert,
} from "lucide-react";
import { choose, ScanFileInputs, useProjectScan, type ScanState } from "@/components/scan-controller";
import { Button } from "@/components/ui/button";
import type { ScanIntakeLedgerItem, ScanIntakeSnapshot } from "@/lib/scan-intake-snapshot";
import type { Severity } from "@/lib/types";

export function ScanIntake({ latestScan }: { latestScan: ScanIntakeSnapshot | null }) {
  const controller = useProjectScan();
  const manifestInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const selected = new Set(controller.state.files ?? []);
  const busy = controller.state.kind === "loading";

  return (
    <div className="bg-background" data-ui="scan-workstation">
      <section
        className="grid border-b xl:grid-cols-[420px_minmax(0,1fr)] 2xl:grid-cols-[520px_minmax(0,1fr)]"
        data-ui="scan-uploader"
        aria-busy={busy}
      >
        <ScanFileInputs
          manifestInput={manifestInput}
          folderInput={folderInput}
          sourceUploads={controller.sourceUploads}
          scanFiles={controller.scanFiles}
        />

        <ManifestBrief
          selected={selected}
          sourceUploads={controller.sourceUploads}
          onChooseFolder={() => choose(folderInput.current)}
        />

        <div className="grid min-w-0">
          <div className="grid min-h-[500px] min-w-0 grid-rows-[minmax(370px,1fr)_auto] border-b xl:border-b-0 xl:border-r">
            <ManifestDropZone
              busy={busy}
              dragging={dragging}
              sourceUploads={controller.sourceUploads}
              onChooseFiles={() => choose(manifestInput.current)}
              onChooseFolder={() => choose(folderInput.current)}
              onDragEnter={() => setDragging(true)}
              onDragLeave={() => setDragging(false)}
              onDrop={(files) => {
                setDragging(false);
                void controller.scanFiles(files, false);
              }}
            />
            <ValidationConsole state={controller.state} />
          </div>

        </div>
      </section>

      <CurrentScanCommandCenter scan={latestScan} />
    </div>
  );
}

function ManifestBrief({
  selected,
  sourceUploads,
  onChooseFolder,
}: {
  selected: Set<string>;
  sourceUploads: boolean;
  onChooseFolder: () => void;
}) {
  return (
    <div className="flex min-h-[500px] flex-col border-b p-5 xl:border-b-0 xl:border-r">
      <h1 className="text-3xl font-extrabold tracking-tight">Scan your project</h1>
      <p className="mt-3 max-w-[34ch] text-sm leading-5 text-muted-foreground">
        Drop reproducible npm manifests to map dependencies, merge advisories, and rank remediation work.
      </p>

      <div className="mt-5">
        <span className="hud-label">Accepted file types</span>
        <div className="mt-3 border">
          <FileStateRow filename="package.json" accepted={selected.has("package.json")} />
          <FileStateRow filename="package-lock.json" accepted={selected.has("package-lock.json")} />
        </div>
        <p className="mt-3 text-xs leading-5 text-muted-foreground">
          A lockfile is required for installed versions and transitive paths.
        </p>
      </div>

      <div className="mt-5 border-t pt-4">
        <div className="flex items-start gap-2 text-xs leading-5 text-muted-foreground">
          <LockBoundaryIcon />
          <p>{sourceUploads ? "Folder analysis is for trusted local/private deployments." : "This deployment accepts manifests only; source files stay on your device."}</p>
        </div>
        {sourceUploads ? (
          <button
            type="button"
            className="mt-4 inline-flex items-center gap-2 text-left text-xs font-bold text-primary hover:text-[var(--primary-active)]"
            onClick={onChooseFolder}
          >
            <FolderSearch size={14} /> Analyze trusted project folder
          </button>
        ) : null}
      </div>
    </div>
  );
}

function ManifestDropZone({
  busy,
  dragging,
  sourceUploads,
  onChooseFiles,
  onChooseFolder,
  onDragEnter,
  onDragLeave,
  onDrop,
}: {
  busy: boolean;
  dragging: boolean;
  sourceUploads: boolean;
  onChooseFiles: () => void;
  onChooseFolder: () => void;
  onDragEnter: () => void;
  onDragLeave: () => void;
  onDrop: (files: FileList) => void;
}) {
  return (
    <div className="p-4 sm:p-6">
      <div
        className={`hud-panel grid h-full min-h-[338px] place-items-center border border-dashed px-5 py-8 text-center transition-colors duration-200 ${dragging ? "border-primary bg-primary/5" : "border-muted-foreground/70 bg-background"}`}
        onDragEnter={(event) => {
          event.preventDefault();
          onDragEnter();
        }}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={(event) => {
          if (event.currentTarget === event.target) onDragLeave();
        }}
        onDrop={(event) => {
          event.preventDefault();
          onDrop(event.dataTransfer.files);
        }}
      >
        <div className="max-w-lg">
          <span className="mx-auto grid size-16 place-items-center border border-dashed text-foreground" aria-hidden="true">
            {busy ? <LoaderCircle className="animate-spin text-primary" size={29} /> : <ArrowDown size={30} strokeWidth={1.4} />}
          </span>
          <h2 className="data mt-6 text-base font-semibold tracking-[-.02em]">
            {busy ? "ANALYZING PROJECT EVIDENCE" : "DRAG & DROP MANIFEST FILES HERE"}
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            {busy ? "Keep this page open while npm and OSV evidence is correlated." : "or choose both files from your computer"}
          </p>
          <div className="mt-6 flex flex-col justify-center gap-3 sm:flex-row">
            <Button data-ui="scan-button" onClick={onChooseFiles} disabled={busy}>
              <Files size={16} /><span><span className="hidden 2xl:inline">Choose </span>manifest files</span>
            </Button>
            {sourceUploads ? <Button variant="outline" onClick={onChooseFolder} disabled={busy}>
              <FolderSearch size={16} /> Project folder
            </Button> : null}
          </div>
          <p className="data mt-5 text-[10px] text-muted-foreground">.JSON ONLY / PACKAGE INSTALL SCRIPTS NEVER EXECUTED</p>
        </div>
      </div>
    </div>
  );
}

function LockBoundaryIcon() {
  return <span className="mt-1 size-2 shrink-0 bg-primary" aria-hidden="true" />;
}

function ValidationConsole({ state }: { state: ScanState }) {
  const tone = state.kind === "error"
    ? "text-destructive"
    : state.kind === "loading"
      ? "text-warning"
      : state.kind === "done"
        ? "text-primary"
        : "text-muted-foreground";
  const role = state.kind === "error" ? "alert" : "status";

  return (
    <div className="border-t px-5 py-4 sm:px-6" data-ui="scan-validation" aria-live="polite" role={role}>
      <div className="flex items-center gap-3">
        <span className="hud-label text-foreground">Validation</span>
        <span className="h-px flex-1 bg-border" aria-hidden="true" />
        <span className={`data text-[10px] ${tone}`}>{state.code ?? "SCN_IDLE"}</span>
      </div>

      {state.kind === "idle" ? (
        <p className="mt-3 text-xs text-muted-foreground">Choose both manifest files to start your scan.</p>
      ) : (
        <div className="mt-3 flex items-start gap-3">
          {state.kind === "loading" ? (
            <LoaderCircle className="mt-0.5 shrink-0 animate-spin text-warning" size={16} />
          ) : state.kind === "error" ? (
            <TriangleAlert className="mt-0.5 shrink-0 text-destructive" size={16} />
          ) : (
            <Check className="mt-0.5 shrink-0 text-primary" size={16} />
          )}
          <p className={`data text-xs leading-5 ${tone}`}>{state.message}</p>
        </div>
      )}
    </div>
  );
}

function CurrentScanCommandCenter({ scan }: { scan: ScanIntakeSnapshot | null }) {
  const counts = scan?.counts ?? { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const findings = scan?.findings ?? 0;
  const fixable = scan?.fixable ?? 0;
  const risky = scan?.items ?? [];
  const exposure = scan ? 100 - scan.score : null;

  return (
    <section className="border-b" data-ui="scan-command-center">
      <div className="flex flex-col justify-between gap-2 border-b px-5 py-3 sm:flex-row sm:items-center sm:px-6">
        <div className="flex items-center gap-3">
          <span className="data text-xs font-semibold text-foreground">/01</span>
          <h2 className="data text-xs font-semibold">CURRENT SCAN COMMAND CENTER</h2>
        </div>
        <div className="data text-[10px] text-muted-foreground">
          {scan ? `${scan.project} / ${formatTimestamp(scan.createdAt)}` : "NO PERSISTED SCAN SELECTED"}
        </div>
      </div>

      <div className="grid min-w-0 xl:grid-cols-[.86fr_1.14fr]">
        <div className="grid min-h-[275px] grid-cols-2 border-b sm:grid-cols-4 xl:border-b-0 xl:border-r">
          <CommandMetric label="Security grade">
            <div className={`data mt-6 grid size-20 place-items-center border text-5xl font-black ${gradeTone(scan?.grade)}`}>
              {scan?.grade ?? "—"}
            </div>
            <span className={`data mt-4 text-[10px] ${gradeTone(scan?.grade, true)}`}>
              {scan ? postureLabel(scan.grade) : "AWAITING SCAN"}
            </span>
          </CommandMetric>

          <CommandMetric label="Risk exposure">
            <div className={`data mt-7 text-5xl font-black ${exposure !== null && exposure >= 60 ? "text-destructive" : exposure !== null && exposure >= 30 ? "text-warning" : "text-primary"}`}>
              {exposure ?? "—"}<span className="ml-1 text-sm font-medium text-muted-foreground">/100</span>
            </div>
            <span className="data mt-5 text-[10px] text-muted-foreground">SECURITY SCORE {scan?.score ?? "—"}/100</span>
          </CommandMetric>

          <CommandMetric label="Active findings">
            <div className={`data mt-7 text-5xl font-black ${findings ? "text-destructive" : "text-primary"}`}>{findings}</div>
            <div className="data mt-4 grid gap-1 text-[10px]">
              <SeverityLine label="Critical" value={counts.critical} severity="critical" />
              <SeverityLine label="High" value={counts.high} severity="high" />
              <SeverityLine label="Medium" value={counts.medium} severity="medium" />
              <SeverityLine label="Low" value={counts.low} severity="low" />
            </div>
          </CommandMetric>

          <CommandMetric label="Fixable findings" last>
            <div className="data mt-7 text-5xl font-black text-primary">{fixable}</div>
            <span className="data mt-5 text-[10px] text-muted-foreground">OF {findings} MERGED FINDINGS</span>
            {scan ? (
              <Link href={`/remediation?scan=${encodeURIComponent(scan.id)}`} className="data mt-auto inline-flex items-center gap-2 pt-4 text-[10px] font-bold text-primary">
                VIEW FIXES <ArrowRight size={13} />
              </Link>
            ) : null}
          </CommandMetric>
        </div>

        <DependencyLedger scan={scan} items={risky} />
      </div>
    </section>
  );
}

function CommandMetric({ label, last = false, children }: { label: string; last?: boolean; children: React.ReactNode }) {
  return (
    <div className={`flex min-w-0 flex-col p-4 sm:p-5 ${last ? "" : "border-r"} max-sm:nth-[2]:border-r-0 max-sm:nth-[-n+2]:border-b`}>
      <span className="hud-label">{label}</span>
      {children}
    </div>
  );
}

function DependencyLedger({ scan, items }: { scan: ScanIntakeSnapshot | null; items: ScanIntakeLedgerItem[] }) {
  return (
    <div className="min-w-0 p-4 sm:p-5" data-ui="risk-table">
      <div className="flex items-center justify-between gap-3 pb-3">
        <span className="hud-label text-foreground">Dependency ledger</span>
        <span className="data text-[10px] text-muted-foreground">TOTAL: {scan?.dependencies ?? 0}</span>
      </div>
      <div className="scrollbar overflow-x-auto border-t">
        <table className="w-full min-w-[680px] border-collapse text-left data text-[10px]">
          <thead className="text-muted-foreground">
            <tr>
              <th className="border-b py-2 pr-4 font-medium">PACKAGE</th>
              <th className="border-b px-3 py-2 font-medium">VERSION</th>
              <th className="border-b px-3 py-2 font-medium">SCOPE</th>
              <th className="border-b px-3 py-2 text-right font-medium">CVES</th>
              <th className="border-b px-3 py-2 text-right font-medium">CVSS</th>
              <th className="border-b px-3 py-2 font-medium">HIGHEST</th>
              <th className="border-b px-3 py-2 font-medium">FIX</th>
              <th className="border-b py-2 pl-3 font-medium">LOCATION</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => {
              return (
                <tr key={`${item.name}@${item.version}:${item.path}`} className="group hover:bg-secondary">
                  <td className="border-b py-2 pr-4 font-semibold text-foreground">
                    <Link href={`/dependencies/${encodeURIComponent(item.name)}?scan=${encodeURIComponent(scan!.id)}&version=${encodeURIComponent(item.version)}`} className="hover:text-primary">
                      {item.name}
                    </Link>
                  </td>
                  <td className="border-b px-3 py-2 text-muted-foreground">{item.version}</td>
                  <td className="border-b px-3 py-2 text-muted-foreground">{item.direct ? "DIRECT" : "TRANSITIVE"}</td>
                  <td className="border-b px-3 py-2 text-right text-foreground">{item.vulnerabilityCount}</td>
                  <td className="border-b px-3 py-2 text-right text-foreground">{item.highestCvss.toFixed(1)}</td>
                  <td className={`border-b px-3 py-2 ${severityTone(item.highestSeverity)}`}>{item.highestSeverity.toUpperCase()}</td>
                  <td className={`border-b px-3 py-2 ${item.hasFix ? "text-primary" : "text-destructive"}`}>{item.hasFix ? "YES" : "NO"}</td>
                  <td className="max-w-48 truncate border-b py-2 pl-3 text-muted-foreground" title={item.path}>{item.path}</td>
                </tr>
              );
            })}
            {!items.length ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-muted-foreground">
                  {scan ? "No vulnerable dependencies in this saved scan." : "Upload manifest files to populate the dependency ledger."}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function FileStateRow({ filename, accepted }: { filename: string; accepted: boolean }) {
  return (
    <div className="flex items-center gap-3 border-b px-3 py-2.5 last:border-b-0">
      <FileJson size={15} className={accepted ? "text-primary" : "text-muted-foreground"} />
      <span className="data text-xs">{filename}</span>
      <span className={`data ml-auto text-[10px] ${accepted ? "text-primary" : "text-muted-foreground"}`}>
        {accepted ? "ACCEPTED ✓" : "REQUIRED"}
      </span>
    </div>
  );
}

function SeverityLine({ label, value, severity }: { label: string; value: number; severity: Severity }) {
  return <span className={severityTone(severity)}><b className="inline-block w-6 font-medium">{String(value).padStart(2, "0")}</b> {label.toUpperCase()}</span>;
}

function severityTone(severity: Severity) {
  if (severity === "critical") return "text-critical";
  if (severity === "high") return "text-high";
  if (severity === "medium") return "text-medium";
  if (severity === "low") return "text-low";
  return "text-muted-foreground";
}

function gradeTone(grade?: string, textOnly = false) {
  if (!grade) return textOnly ? "text-muted-foreground" : "border-border text-muted-foreground";
  if (grade === "A" || grade === "B") return textOnly ? "text-primary" : "border-primary text-primary";
  if (grade === "C") return textOnly ? "text-warning" : "border-warning text-warning";
  return textOnly ? "text-destructive" : "border-destructive text-destructive";
}

function postureLabel(grade: string) {
  if (grade === "A" || grade === "B") return "CONTROLLED RISK";
  if (grade === "C") return "ELEVATED RISK";
  return "HIGH RISK";
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
    hour12: false,
  }).format(new Date(value)) + " UTC";
}

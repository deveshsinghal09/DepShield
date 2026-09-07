"use client";

import { useRef, useState } from "react";
import { Check, Files, FolderSearch, LoaderCircle, LockKeyhole, ScanLine, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { choose, ScanFileInputs, useProjectScan } from "@/components/scan-controller";

export function ScanButton() {
  const controller = useProjectScan();
  const manifestInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const [showModes, setShowModes] = useState(false);
  const loading = controller.state.kind === "loading";
  const label = loading ? controller.state.message ?? "Scanning project" : "Scan Project";

  return (
    <div className="relative" data-ui="scan-button">
      <ScanFileInputs manifestInput={manifestInput} folderInput={folderInput} sourceUploads={controller.sourceUploads} scanFiles={controller.scanFiles} onSelected={() => setShowModes(false)} />
      <Button
        className="min-w-32"
        aria-label={label}
        aria-expanded={showModes}
        disabled={loading}
        onClick={() => setShowModes((value) => !value)}
      >
        {loading ? <LoaderCircle className="animate-spin" size={16} /> : controller.state.kind === "done" ? <Check size={16} /> : controller.state.kind === "error" ? <TriangleAlert size={16} /> : <ScanLine size={16} />}
        {loading ? "Scanning…" : controller.state.kind === "done" ? "Results ready" : "Scan project"}
      </Button>
      {showModes && !loading ? (
        <div className="absolute right-0 top-12 z-50 w-[min(23rem,calc(100vw-2rem))] border bg-card p-2" data-ui="scan-source-mode">
          {controller.sourceUploads ? (
            <button type="button" className="flex w-full items-start gap-3 border border-transparent p-3 text-left hover:border-primary hover:bg-secondary" onClick={() => choose(folderInput.current)}>
              <FolderSearch className="mt-0.5 shrink-0 text-primary" size={18} />
              <span><b className="block text-sm">Project folder</b><small className="mt-1 block leading-5 text-muted-foreground">Trusted local/private mode with bounded JS/TS source evidence.</small></span>
            </button>
          ) : (
            <div className="flex items-start gap-3 border p-3" data-ui="source-upload-disabled">
              <LockKeyhole className="mt-0.5 shrink-0 text-muted-foreground" size={18} />
              <span><b className="block text-sm">Source analysis unavailable</b><small className="mt-1 block leading-5 text-muted-foreground">This deployment accepts manifests only.</small></span>
            </div>
          )}
          <button type="button" className="mt-2 flex w-full items-start gap-3 border border-transparent p-3 text-left hover:border-primary hover:bg-secondary" onClick={() => choose(manifestInput.current)}>
            <Files className="mt-0.5 shrink-0 text-muted-foreground" size={18} />
            <span><b className="block text-sm">Manifest files only</b><small className="mt-1 block leading-5 text-muted-foreground">Choose package.json and package-lock.json. Reachability remains unknown.</small></span>
          </button>
        </div>
      ) : null}
      {controller.state.kind === "error" ? (
        <div role="alert" className="absolute right-0 top-12 z-50 w-80 max-w-[calc(100vw-2rem)] border border-destructive bg-card p-3 text-xs leading-5 text-destructive">
          <span className="data block text-[10px]">{controller.state.code}</span>{controller.state.message}
        </div>
      ) : null}
      {loading && controller.state.message ? <span className="sr-only" role="status">{controller.state.message}</span> : null}
    </div>
  );
}

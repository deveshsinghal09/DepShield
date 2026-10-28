"use client";

import { useEffect, useRef, useState, type InputHTMLAttributes, type RefObject } from "react";
import { useRouter } from "next/navigation";
import { useFeatureFlags } from "@/components/feature-flags-provider";
import { selectUploadFiles, uploadPath } from "@/lib/scan-upload";
import type { SourceFileInput } from "@/lib/types";

export type ScanState = { kind: "idle" | "loading" | "done" | "error"; message?: string; files?: string[] };
export function useProjectScan() {
  const { sourceUploads } = useFeatureFlags();
  const router = useRouter();
  const [state, setState] = useState<ScanState>({ kind: "idle" });
  const selection = useRef<ReturnType<typeof selectUploadFiles> | null>(null);
  const running = useRef(false);
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);

  function reset() {
    if (running.current) return;
    selection.current = null;
    setState({ kind: "idle" });
  }
  function selectionError(message: string) {
    if (!running.current) setState({ kind: "error", message, files: state.files });
  }
  async function scanFiles(fileList: FileList | null, folder: boolean) {
    if (running.current || !fileList?.length) return;
    try {
      let files = Array.from(fileList);
      // Separate manifest selections accumulate; folder selections replace everything.
      if (!folder && selection.current?.root === "") {
        const incoming = new Set(files.map(file => file.name));
        files = [...[selection.current.manifest, selection.current.lock].filter((file): file is File => !!file && !incoming.has(file.name)), ...files];
      }
      const next = selectUploadFiles(files, folder);
      selection.current = next;
      const names = [next.manifest?.name, next.lock?.name].filter((name): name is string => !!name);
      setState({ kind: "idle", files: names, message: !next.manifest ? "Add package.json to continue." : !next.lock ? "Add package-lock.json from the same project to continue." : "Files ready. " + (folder && sourceUploads ? "Eligible JS/TS files will also be analyzed." : "Only the two manifest files will be uploaded.") });
    } catch (error) {
      selection.current = null;
      setState({ kind: "error", message: error instanceof Error ? error.message : "Could not read your selection." });
    }
  }
  async function startScan() {
    const chosen = selection.current;
    if (running.current || !chosen?.manifest || !chosen.lock) return;
    running.current = true;
    const abort = new AbortController();
    request.current = abort;
    const timeout = setTimeout(() => abort.abort(), 180_000);
    const files = [chosen.manifest.name, chosen.lock.name];
    setState({ kind: "loading", message: "Reading project files…", files });
    try {
      const packageJson = await chosen.manifest.text();
      const packageLock = await chosen.lock.text();
      for (const [name, content] of [["package.json", packageJson], ["package-lock.json", packageLock]]) {
        try { const value = JSON.parse(content); if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(); }
        catch { throw new Error(name + " must contain a valid JSON object. Correct the file and select it again."); }
      }
      const sourceFiles: SourceFileInput[] = [];
      let bytes = 0;
      if (sourceUploads && chosen.root) for (const file of chosen.sources) {
        if (bytes + file.size > 8 * 1024 * 1024) break;
        bytes += file.size;
        sourceFiles.push({ path: uploadPath(file).slice(chosen.root.length), content: await file.text() });
      }
      setState({ kind: "loading", message: "Checking dependencies with npm audit and OSV. Keep this page open…", files });
      const response = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, signal: abort.signal, body: JSON.stringify({ packageJson, packageLock, sourceFiles }) });
      const body = await response.json().catch(() => null);
      if (!response.ok || typeof body?.data?.id !== "string") throw new Error(body?.error?.message ?? ("The scanner returned HTTP " + response.status + ". Please try again."));
      setState({ kind: "done", message: "Scan saved. Opening your results…", files });
      router.push("/dashboard?scan=" + encodeURIComponent(body.data.id));
      router.refresh();
    } catch (error) {
      setState({ kind: "error", files, message: abort.signal.aborted ? "The scan timed out. Check Scan history before retrying; the server may still finish this scan." : error instanceof Error ? error.message : "Scan failed. Please retry." });
    } finally {
      clearTimeout(timeout);
      running.current = false;
    }
  }
  return { state, sourceUploads, scanFiles, startScan, reset, selectionError, ready: !!state.files?.includes("package.json") && !!state.files?.includes("package-lock.json") };
}

export function choose(input: HTMLInputElement | null) { if (input) { input.value = ""; input.click(); } }
type FileInputsProps = {
  manifestInput: RefObject<HTMLInputElement | null>;
  folderInput: RefObject<HTMLInputElement | null>;
  sourceUploads: boolean;
  scanFiles: (files: FileList | null, folder: boolean) => Promise<void>;
};
const directoryInputProps = { webkitdirectory: "", directory: "" } as InputHTMLAttributes<HTMLInputElement>;
export function ScanFileInputs({ manifestInput, folderInput, scanFiles }: FileInputsProps) {
  return <>
    <input ref={manifestInput} className="sr-only" type="file" accept="application/json,.json" multiple onChange={event => void scanFiles(event.target.files, false)} aria-label="Choose package.json and package-lock.json" />
    <input ref={folderInput} className="sr-only" type="file" multiple {...directoryInputProps} onChange={event => void scanFiles(event.target.files, true)} aria-label="Choose a project folder" />
  </>;
}

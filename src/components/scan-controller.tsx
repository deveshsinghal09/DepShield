"use client";

import { useState, type InputHTMLAttributes, type RefObject } from "react";
import { useRouter } from "next/navigation";
import { useFeatureFlags } from "@/components/feature-flags-provider";
import type { Scan, SourceFileInput } from "@/lib/types";

export type ScanState = {
  kind: "idle" | "loading" | "done" | "error";
  message?: string;
  code?: string;
  files?: string[];
};

const SOURCE_PATTERN = /\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i;
const EXCLUDED_SEGMENTS = /(^|\/)(?:node_modules|\.next|\.git|dist|build|coverage)(\/|$)/i;

export function useProjectScan() {
  const { sourceUploads } = useFeatureFlags();
  const router = useRouter();
  const [state, setState] = useState<ScanState>({ kind: "idle" });

  async function scanFiles(fileList: FileList | null, includeSource: boolean) {
    if (!fileList?.length) return;
    const fileNames = Array.from(fileList, (file) => file.name);
    if (includeSource && !sourceUploads) {
      setState({
        kind: "error",
        code: "E_SOURCE_DISABLED",
        message: "Source upload is disabled on this deployment. Choose package.json and package-lock.json instead.",
        files: fileNames,
      });
      return;
    }

    const files = Array.from(fileList);
    const candidates = files
      .filter((file) => !EXCLUDED_SEGMENTS.test(relativePath(file)))
      .toSorted((left, right) => relativePath(left).split("/").length - relativePath(right).split("/").length);
    const manifest = candidates.find((file) => file.name === "package.json");
    if (!manifest) {
      setState({
        kind: "error",
        code: "E_MANIFEST_MISSING",
        message: "No package.json was found. Select both npm manifest files or a project folder.",
        files: fileNames,
      });
      return;
    }

    const root = relativePath(manifest).slice(0, -"package.json".length);
    const lock = candidates.find((file) => file.name === "package-lock.json" && relativePath(file).startsWith(root));
    if (!lock) {
      setState({
        kind: "error",
        code: "E_LOCKFILE_REQUIRED",
        message: "package-lock.json is required for reproducible installed versions and transitive dependency paths.",
        files: fileNames,
      });
      return;
    }

    setState({
      kind: "loading",
      code: "SCN_RESOLVE",
      message: includeSource ? "Reading bounded source evidence…" : "Resolving dependency graph…",
      files: [manifest.name, lock.name],
    });

    try {
      const sourceFiles = includeSource ? await readSourceFiles(candidates, root) : [];
      setState({
        kind: "loading",
        code: "SCN_CORRELATE",
        message: sourceFiles.length
          ? `Correlating ${sourceFiles.length} source files with npm and OSV evidence…`
          : "Running npm audit and OSV enrichment…",
        files: [manifest.name, lock.name],
      });
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          packageJson: await manifest.text(),
          packageLock: await lock.text(),
          sourceFiles,
        }),
      });
      const body = await response.json().catch(() => null) as { data?: Scan; error?: { message?: string } } | null;
      if (!response.ok || !body?.data) {
        throw new Error(body?.error?.message ?? `Scan failed with HTTP ${response.status}.`);
      }
      setState({
        kind: "done",
        code: "SCN_SAVED",
        message: `Scan saved · ${body.data.dependencies} dependencies assessed`,
        files: [manifest.name, lock.name],
      });
      router.replace(`/scan?scan=${encodeURIComponent(body.data.id)}`);
      router.refresh();
    } catch (error) {
      setState({
        kind: "error",
        code: "E_SCAN_FAILED",
        message: error instanceof Error ? error.message : "The scan did not complete. Verify both files and retry.",
        files: [manifest.name, lock.name],
      });
    }
  }

  return { state, sourceUploads, scanFiles };
}

export function choose(input: HTMLInputElement | null) {
  if (!input) return;
  input.value = "";
  input.click();
}

type FileInputsProps = {
  manifestInput: RefObject<HTMLInputElement | null>;
  folderInput: RefObject<HTMLInputElement | null>;
  sourceUploads: boolean;
  scanFiles: (files: FileList | null, includeSource: boolean) => Promise<void>;
  onSelected?: () => void;
};

const directoryInputProps = { webkitdirectory: "", directory: "" } as InputHTMLAttributes<HTMLInputElement>;

export function ScanFileInputs({ manifestInput, folderInput, sourceUploads, scanFiles, onSelected }: FileInputsProps) {
  return (
    <>
      <input
        ref={manifestInput}
        className="sr-only"
        type="file"
        accept="application/json,.json"
        multiple
        onChange={(event) => {
          onSelected?.();
          void scanFiles(event.target.files, false);
        }}
        aria-label="Choose package.json and package-lock.json"
      />
      <input
        ref={folderInput}
        className="sr-only"
        type="file"
        multiple
        disabled={!sourceUploads}
        {...directoryInputProps}
        onChange={(event) => {
          onSelected?.();
          void scanFiles(event.target.files, true);
        }}
        aria-label="Choose a project folder for dependency and source reachability analysis"
      />
    </>
  );
}

function relativePath(file: File) {
  return (file.webkitRelativePath || file.name).replaceAll("\\", "/");
}

async function readSourceFiles(files: File[], root: string): Promise<SourceFileInput[]> {
  const selected = files.filter((file) => {
    const value = relativePath(file);
    const projectPath = value.startsWith(root) ? value.slice(root.length) : value;
    return SOURCE_PATTERN.test(projectPath) && !EXCLUDED_SEGMENTS.test(projectPath) && file.size <= 512 * 1024;
  }).slice(0, 750);

  let total = 0;
  const result: SourceFileInput[] = [];
  for (const file of selected) {
    if (total + file.size > 8 * 1024 * 1024) break;
    total += file.size;
    const value = relativePath(file);
    result.push({
      path: value.startsWith(root) ? value.slice(root.length) : value,
      content: await file.text(),
    });
  }
  return result;
}

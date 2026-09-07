#!/usr/bin/env node

import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const args = process.argv.slice(2);
if (args[0] !== "scan") {
  console.error("Usage: depshield scan [--project <directory>] [--url <DepShield URL>] [--with-source] [--baseline <scan id>] [--output <file>]");
  process.exitCode = 2;
} else {
  await run();
}

async function run() {
  try {
    const project = path.resolve(option("--project") ?? process.cwd());
    const baseUrl = (option("--url") ?? process.env.DEPSHIELD_URL ?? "http://127.0.0.1:3000").replace(/\/$/, "");
    const packageJson = await readFile(path.join(project, "package.json"), "utf8");
    const packageLock = await readFile(path.join(project, "package-lock.json"), "utf8");
    const sourceFiles = args.includes("--with-source") ? await sourceBundle(project) : undefined;
    const response = await fetch(`${baseUrl}/api/ci/scan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ packageJson, packageLock, sourceFiles, baselineScanId: option("--baseline") }),
      signal: AbortSignal.timeout(180_000),
    });
    const result = await response.json();
    const output = `${JSON.stringify(result, null, 2)}\n`;
    const outputPath = option("--output");
    if (outputPath) {
      const resolvedOutput = path.resolve(outputPath);
      await writeFile(resolvedOutput, output, "utf8");
      console.error(`DepShield JSON written to ${resolvedOutput}`);
    } else process.stdout.write(output);
    process.exitCode = result.exitCode === 0 || result.exitCode === 1 ? result.exitCode : 2;
  } catch (error) {
    console.error(JSON.stringify({ data: null, policy: null, exitCode: 2, error: { code: "CLI_ERROR", message: error instanceof Error ? error.message : "CLI scan failed." } }, null, 2));
    process.exitCode = 2;
  }
}

function option(name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

async function sourceBundle(project) {
  const result = [];
  let bytes = 0;
  const excluded = new Set(["node_modules", ".next", ".git", "dist", "build", "coverage"]);
  const supported = /\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i;

  async function walk(directory) {
    if (result.length >= 750 || bytes >= 8 * 1024 * 1024) return;
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (result.length >= 750 || bytes >= 8 * 1024 * 1024) break;
      if (entry.isSymbolicLink() || excluded.has(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile() && supported.test(entry.name)) {
        const content = await readFile(absolute, "utf8");
        const size = Buffer.byteLength(content, "utf8");
        if (size > 512 * 1024 || bytes + size > 8 * 1024 * 1024) continue;
        bytes += size;
        result.push({ path: path.relative(project, absolute).replaceAll(path.sep, "/"), content });
      }
    }
  }

  await walk(project);
  return result;
}

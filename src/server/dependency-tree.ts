import type { DependencyPath } from "@/lib/types";

type Manifest = {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

type LockPackage = {
  version?: string;
  license?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  dev?: boolean;
};

type Legacy = {
  version?: string;
  dev?: boolean;
  optional?: boolean;
  dependencies?: Record<string, Legacy>;
};

type PackageLock = {
  lockfileVersion?: number;
  packages?: Record<string, LockPackage>;
  dependencies?: Record<string, Legacy>;
};

export type InstalledDependency = {
  key: string;
  name: string;
  version: string;
  direct: boolean;
  runtime: boolean;
  devOnly: boolean;
  optional: boolean;
  depth: number;
  parentCount: number;
  parentPackages: string[];
  license: string;
  paths: DependencyPath[];
};

export class ManifestError extends Error {
  constructor(
    message: string,
    public readonly code: "INVALID_MANIFEST" | "NO_LOCKFILE",
  ) {
    super(message);
    this.name = "ManifestError";
  }
}

export function parseManifest(text: string): Manifest {
  try {
    const value = JSON.parse(text) as Manifest;
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    throw new ManifestError("package.json is not valid JSON.", "INVALID_MANIFEST");
  }
}

export function parseLockfile(text?: string): PackageLock {
  if (!text?.trim()) {
    throw new ManifestError(
      "package-lock.json is required for a reproducible dependency scan.",
      "NO_LOCKFILE",
    );
  }
  try {
    const value = JSON.parse(text) as PackageLock;
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    throw new ManifestError("package-lock.json is not valid JSON.", "INVALID_MANIFEST");
  }
}

export function extractDependencyGraph(manifest: Manifest, lock: PackageLock) {
  return lock.packages && Object.keys(lock.packages).length
    ? modern(manifest, lock.packages)
    : legacy(manifest, lock.dependencies ?? {});
}

type RootScope = { runtime: boolean; optional: boolean };
type QueueItem = { key: string; chain: string[]; scope: RootScope };
type SeenPath = { chain: string[]; scope: RootScope };

function rootScopes(manifest: Manifest) {
  const scopes = new Map<string, RootScope>();
  for (const name of Object.keys(manifest.devDependencies ?? {})) {
    scopes.set(name, { runtime: false, optional: false });
  }
  for (const name of Object.keys(manifest.dependencies ?? {})) {
    scopes.set(name, { runtime: true, optional: false });
  }
  for (const name of Object.keys(manifest.optionalDependencies ?? {})) {
    scopes.set(name, { runtime: true, optional: true });
  }
  return scopes;
}

function modern(
  manifest: Manifest,
  packages: Record<string, LockPackage>,
): InstalledDependency[] {
  const project = manifest.name ?? "Application";
  const scopes = rootScopes(manifest);
  const paths = new Map<string, SeenPath[]>();
  const queue: QueueItem[] = [];

  for (const [name, scope] of scopes) {
    const key = resolve("", name, packages);
    if (key) {
      queue.push({
        key,
        chain: [project, `${name}@${packages[key]?.version ?? "unknown"}`],
        scope,
      });
    }
  }

  const traversed = new Set<string>();
  while (queue.length) {
    const current = queue.shift()!;
    const known = paths.get(current.key) ?? [];
    const signature = `${current.scope.runtime}:${current.chain.join("\0")}`;
    if (!known.some((value) => `${value.scope.runtime}:${value.chain.join("\0")}` === signature)) {
      known.push({ chain: current.chain, scope: current.scope });
      paths.set(current.key, known.slice(0, 20));
    }

    const children = {
      ...(packages[current.key]?.dependencies ?? {}),
      ...(packages[current.key]?.optionalDependencies ?? {}),
    };
    for (const child of Object.keys(children)) {
      const key = resolve(current.key, child, packages);
      if (!key || current.chain.length > 64) continue;
      const edge = `${current.key}>${key}>${signature}`;
      if (traversed.has(edge)) continue;
      traversed.add(edge);
      queue.push({
        key,
        chain: [...current.chain, `${child}@${packages[key]?.version ?? "unknown"}`],
        scope: {
          runtime: current.scope.runtime && packages[key]?.dev !== true,
          optional:
            current.scope.optional ||
            Object.prototype.hasOwnProperty.call(packages[current.key]?.optionalDependencies ?? {}, child),
        },
      });
    }
  }

  return Object.entries(packages)
    .filter(([key, value]) => paths.has(key) && key.includes("node_modules/") && Boolean(value.version))
    .map(([key, value]) => {
      const name = nameFromKey(key);
      const seen = paths.get(key) ?? [];
      const dependencyPaths = seen.map((item) => toPath(item.chain));
      const parentPackages = unique(
        dependencyPaths
          .map((item) => item.nodes.at(-2))
          .filter((item): item is string => Boolean(item) && item !== project),
      );
      const runtime = seen.some((item) => item.scope.runtime);
      return {
        key,
        name,
        version: value.version!,
        direct: scopes.has(name) && dependencyPaths.some((item) => item.nodes.length === 2),
        runtime,
        devOnly: !runtime,
        optional: seen.every((item) => item.scope.optional),
        depth: Math.min(...dependencyPaths.map((item) => Math.max(1, item.nodes.length - 1))),
        parentCount: parentPackages.length,
        parentPackages,
        license: value.license ?? "Unknown",
        paths: dependencyPaths,
      };
    });
}

function legacy(
  manifest: Manifest,
  dependencies: Record<string, Legacy>,
): InstalledDependency[] {
  const project = manifest.name ?? "Application";
  const scopes = rootScopes(manifest);
  const result: InstalledDependency[] = [];

  const walk = (
    values: Record<string, Legacy>,
    chain: string[],
    parent: string,
    rootScope?: RootScope,
  ) => {
    for (const [name, value] of Object.entries(values)) {
      const key = parent ? `${parent}/node_modules/${name}` : `node_modules/${name}`;
      const node = `${name}@${value.version ?? "unknown"}`;
      const scope = rootScope ?? scopes.get(name) ?? {
        runtime: value.dev !== true,
        optional: value.optional === true,
      };
      const dependencyPath = toPath([...chain, node]);
      const parentPackage = dependencyPath.nodes.at(-2);
      const runtime = scope.runtime && value.dev !== true;
      result.push({
        key,
        name,
        version: value.version ?? "unknown",
        direct: chain.length === 1 && scopes.has(name),
        runtime,
        devOnly: !runtime,
        optional: scope.optional || value.optional === true,
        depth: Math.max(1, dependencyPath.nodes.length - 1),
        parentCount: parentPackage && parentPackage !== project ? 1 : 0,
        parentPackages: parentPackage && parentPackage !== project ? [parentPackage] : [],
        license: "Unknown",
        paths: [dependencyPath],
      });
      walk(value.dependencies ?? {}, [...chain, node], key, {
        runtime,
        optional: scope.optional || value.optional === true,
      });
    }
  };

  walk(dependencies, [project], "");
  return result;
}

function resolve(
  parent: string,
  child: string,
  packages: Record<string, LockPackage>,
) {
  let cursor = parent;
  while (true) {
    const candidate = cursor ? `${cursor}/node_modules/${child}` : `node_modules/${child}`;
    if (packages[candidate]) return candidate;
    const index = cursor.lastIndexOf("/node_modules/");
    if (index < 0) break;
    cursor = cursor.slice(0, index);
  }
  return packages[`node_modules/${child}`] ? `node_modules/${child}` : undefined;
}

function nameFromKey(key: string) {
  const marker = "node_modules/";
  return key.slice(key.lastIndexOf(marker) + marker.length);
}

function toPath(nodes: string[]): DependencyPath {
  return { nodes, display: nodes.join(" → ") };
}

function unique(values: string[]) {
  return [...new Set(values)];
}

import path from "node:path";

export type ReachabilityStatus =
  | "REACHABLE"
  | "POSSIBLY_REACHABLE"
  | "NOT_OBSERVED"
  | "UNKNOWN";

export type SourceFileInput = {
  path: string;
  content: string;
};

export type DependencyReachabilityInput = {
  name: string;
  version: string;
  direct?: boolean;
  instanceId?: string;
  path?: string;
  paths?: ReadonlyArray<{ nodes: ReadonlyArray<string>; display?: string }>;
  /** Optional curated API names for a vulnerability. Absence never implies safety. */
  vulnerableApis?: ReadonlyArray<string>;
};

export type ReachabilityLimits = {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxPathLength: number;
  maxTokensPerFile: number;
  maxRouteHints: number;
  maxEvidencePathsPerDependency: number;
};

export type ReachabilityDiagnostic = {
  level: "warning" | "error";
  code:
    | "SOURCE_FILE_LIMIT"
    | "SOURCE_TOTAL_SIZE_LIMIT"
    | "SOURCE_FILE_SIZE_LIMIT"
    | "SOURCE_TOKEN_LIMIT"
    | "INVALID_SOURCE_PATH"
    | "DUPLICATE_SOURCE_PATH"
    | "UNSUPPORTED_SOURCE_FILE"
    | "NO_ANALYZABLE_SOURCE"
    | "UNRESOLVED_RELATIVE_IMPORT"
    | "UNRESOLVED_PATH_ALIAS"
    | "DYNAMIC_MODULE_REFERENCE"
    | "ROUTE_HINT_LIMIT";
  message: string;
  file?: string;
  line?: number;
};

export type ImportKind = "static-import" | "require" | "dynamic-import" | "re-export";

export type PackageImportEvidence = {
  sourceFile: string;
  line: number;
  specifier: string;
  packageName: string;
  kind: ImportKind;
  importedApis: string[];
  observedApis: string[];
};

export type RouteHint = {
  id: string;
  kind: "next-route" | "express-route";
  file: string;
  method: string;
  route: string;
  exposure: "POSSIBLY_INTERNET_EXPOSED";
};

export type ReachabilityPathEvidence = {
  kind: "DIRECT_IMPORT" | "TRANSITIVE_PARENT";
  certainty: "OBSERVED" | "POSSIBLE";
  nodes: string[];
  sourceFiles: string[];
  packageChain: string[];
  route?: RouteHint;
  explanation: string;
};

export type BlastRadiusEstimate = {
  routes: RouteHint[];
  sourceFiles: string[];
  modules: string[];
  parentDependencies: string[];
  applicationAreas: string[];
  evidencePaths: ReachabilityPathEvidence[];
  counts: {
    routes: number;
    sourceFiles: number;
    parentDependencies: number;
    evidencePaths: number;
  };
  caveat: string;
};

export type ReachabilityEvidence = {
  key: string;
  dependency: { name: string; version: string };
  status: ReachabilityStatus;
  explanation: string;
  packageImports: PackageImportEvidence[];
  importedApis: string[];
  observedApis: string[];
  vulnerableApiMatch: "MATCHED" | "NOT_OBSERVED" | "UNKNOWN" | "NOT_REQUESTED";
  matchedVulnerableApis: string[];
  paths: ReachabilityPathEvidence[];
  blastRadius: BlastRadiusEstimate;
  limitations: string[];
};

export type ReachabilityAnalysis = {
  byDependency: Record<string, ReachabilityEvidence>;
  findings: ReachabilityEvidence[];
  routes: RouteHint[];
  warnings: ReachabilityDiagnostic[];
  errors: ReachabilityDiagnostic[];
  complete: boolean;
  stats: {
    filesReceived: number;
    filesAnalyzed: number;
    filesSkipped: number;
    totalBytes: number;
    moduleEdges: number;
    packageImports: number;
    routeHints: number;
  };
  limitations: string[];
};

export const DEFAULT_REACHABILITY_LIMITS: Readonly<ReachabilityLimits> = {
  maxFiles: 750,
  maxFileBytes: 512 * 1024,
  maxTotalBytes: 8 * 1024 * 1024,
  maxPathLength: 260,
  maxTokensPerFile: 120_000,
  maxRouteHints: 250,
  maxEvidencePathsPerDependency: 25,
};

const SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"]);
const ROUTE_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]);
const EXPRESS_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all", "use"]);
const STATIC_LIMITATIONS = [
  "Static observation is conservative: dynamic module names, reflection, dependency injection, generated code, runtime plugins, and unprovided files may hide paths.",
  "NOT_OBSERVED means no supported static path was seen; it is not a claim that the dependency is unused, unexploitable, or safe.",
  "Route exposure is a hint from framework syntax and does not evaluate authentication, middleware, rewrites, network policy, or runtime configuration.",
  "Function matching is performed only against explicitly supplied curated API names and does not prove that a vulnerable code path executes.",
];

type Token = {
  kind: "identifier" | "string" | "template" | "punctuation";
  value: string;
  line: number;
};

type MutableImport = PackageImportEvidence & {
  imported: Set<string>;
  observed: Set<string>;
};

type Binding = {
  observation: MutableImport;
  api: string;
  namespace: boolean;
  declarationToken: number;
};

type LocalImport = {
  specifier: string;
  line: number;
};

type ParsedFile = {
  path: string;
  tokens: Token[];
  localImports: LocalImport[];
  localEdges: string[];
  packageImports: MutableImport[];
  routes: RouteHint[];
  incomplete: boolean;
};

type RouteSourcePath = {
  route: RouteHint;
  files: string[];
};

export function dependencyReachabilityKey(name: string, version: string, instance?: string) {
  const base = `${name}@${version}`;
  return instance ? `${base}::${encodeURIComponent(instance)}` : base;
}

export function findReachability(
  analysis: ReachabilityAnalysis,
  name: string,
  version: string,
) {
  return analysis.findings.find(
    (finding) => finding.dependency.name === name && finding.dependency.version === version,
  );
}

export function analyzeReachability(
  sourceFiles: ReadonlyArray<SourceFileInput>,
  dependencies: ReadonlyArray<DependencyReachabilityInput>,
  configuredLimits: Partial<ReachabilityLimits> = {},
): ReachabilityAnalysis {
  const limits = mergeLimits(configuredLimits);
  const warnings: ReachabilityDiagnostic[] = [];
  const errors: ReachabilityDiagnostic[] = [];
  const totalBytes = sourceFiles.reduce((total, file) => total + Buffer.byteLength(file.content, "utf8"), 0);

  if (sourceFiles.length > limits.maxFiles) {
    errors.push({
      level: "error",
      code: "SOURCE_FILE_LIMIT",
      message: `Source bundle contains ${sourceFiles.length} files; the limit is ${limits.maxFiles}. No partial result was treated as complete.`,
    });
  }
  if (totalBytes > limits.maxTotalBytes) {
    errors.push({
      level: "error",
      code: "SOURCE_TOTAL_SIZE_LIMIT",
      message: `Source bundle is ${totalBytes} bytes; the limit is ${limits.maxTotalBytes}. No partial result was treated as complete.`,
    });
  }
  if (errors.length) {
    return emptyAnalysis(sourceFiles.length, totalBytes, dependencies, warnings, errors);
  }

  const accepted: SourceFileInput[] = [];
  const seenPaths = new Set<string>();
  for (const source of sourceFiles) {
    const normalized = normalizeInputPath(source.path, limits.maxPathLength);
    if (!normalized) {
      errors.push({
        level: "error",
        code: "INVALID_SOURCE_PATH",
        message: `Rejected unsafe or invalid source path: ${JSON.stringify(source.path)}.`,
        file: source.path,
      });
      continue;
    }
    const canonical = normalized.toLowerCase();
    if (seenPaths.has(canonical)) {
      errors.push({
        level: "error",
        code: "DUPLICATE_SOURCE_PATH",
        message: `Duplicate normalized source path ${normalized} was rejected.`,
        file: normalized,
      });
      continue;
    }
    seenPaths.add(canonical);
    const extension = path.posix.extname(normalized).toLowerCase();
    if (!SOURCE_EXTENSIONS.has(extension)) {
      warnings.push({
        level: "warning",
        code: "UNSUPPORTED_SOURCE_FILE",
        message: `${normalized} was skipped because ${extension || "its extension"} is not a supported JavaScript/TypeScript source type.`,
        file: normalized,
      });
      continue;
    }
    const size = Buffer.byteLength(source.content, "utf8");
    if (size > limits.maxFileBytes) {
      errors.push({
        level: "error",
        code: "SOURCE_FILE_SIZE_LIMIT",
        message: `${normalized} is ${size} bytes; the per-file limit is ${limits.maxFileBytes}.`,
        file: normalized,
      });
      continue;
    }
    accepted.push({ path: normalized, content: source.content });
  }

  if (!accepted.length) {
    warnings.push({
      level: "warning",
      code: "NO_ANALYZABLE_SOURCE",
      message: "No supported JavaScript or TypeScript source files were available for reachability analysis.",
    });
  }

  const knownPaths = new Set(accepted.map((file) => file.path));
  const parsedFiles: ParsedFile[] = [];
  for (const source of accepted) {
    const lexed = tokenize(source.content, limits.maxTokensPerFile);
    if (lexed.exceeded) {
      errors.push({
        level: "error",
        code: "SOURCE_TOKEN_LIMIT",
        message: `${source.path} exceeded the token limit of ${limits.maxTokensPerFile} and was skipped.`,
        file: source.path,
      });
      continue;
    }
    const parsed = parseSourceFile(source.path, lexed.tokens, warnings);
    resolveLocalEdges(parsed, knownPaths, warnings);
    parsedFiles.push(parsed);
  }

  let routeHints = dedupeRoutes(parsedFiles.flatMap((file) => file.routes));
  let routeLimitHit = false;
  if (routeHints.length > limits.maxRouteHints) {
    warnings.push({
      level: "warning",
      code: "ROUTE_HINT_LIMIT",
      message: `Only the first ${limits.maxRouteHints} of ${routeHints.length} route hints were retained.`,
    });
    routeHints = routeHints.slice(0, limits.maxRouteHints);
    routeLimitHit = true;
  }

  const fileMap = new Map(parsedFiles.map((file) => [file.path, file]));
  const routePathsByFile = indexRoutePaths(routeHints, fileMap);
  const packageImports = parsedFiles.flatMap((file) => file.packageImports);
  const packageImportsByName = groupPackageImports(packageImports);
  const incomplete =
    errors.length > 0 ||
    accepted.length === 0 ||
    parsedFiles.some((file) => file.incomplete) ||
    routeLimitHit;
  const nameCounts = new Map<string, number>();
  const directNameCounts = new Map<string, number>();
  for (const dependency of dependencies) {
    nameCounts.set(dependency.name, (nameCounts.get(dependency.name) ?? 0) + 1);
    if (dependency.direct) directNameCounts.set(dependency.name, (directNameCounts.get(dependency.name) ?? 0) + 1);
  }

  const byDependency = Object.create(null) as Record<string, ReachabilityEvidence>;
  const findings: ReachabilityEvidence[] = [];
  const usedKeys = new Set<string>();
  dependencies.forEach((dependency, index) => {
    const requestedInstance = dependency.instanceId ?? dependency.path;
    let key = dependencyReachabilityKey(dependency.name, dependency.version, requestedInstance);
    if (usedKeys.has(key)) key = dependencyReachabilityKey(dependency.name, dependency.version, `${requestedInstance ?? "instance"}-${index + 1}`);
    usedKeys.add(key);
    const evidence = buildDependencyEvidence({
      dependency,
      key,
      packageImportsByName,
      routePathsByFile,
      incomplete,
      limits,
      sameNameCount: nameCounts.get(dependency.name) ?? 1,
      directNameCount: directNameCounts.get(dependency.name) ?? 0,
    });
    byDependency[key] = evidence;
    findings.push(evidence);
  });

  return {
    byDependency,
    findings,
    routes: routeHints,
    warnings: dedupeDiagnostics(warnings),
    errors: dedupeDiagnostics(errors),
    complete: !incomplete,
    stats: {
      filesReceived: sourceFiles.length,
      filesAnalyzed: parsedFiles.length,
      filesSkipped: sourceFiles.length - parsedFiles.length,
      totalBytes,
      moduleEdges: parsedFiles.reduce((total, file) => total + file.localEdges.length, 0),
      packageImports: packageImports.length,
      routeHints: routeHints.length,
    },
    limitations: [...STATIC_LIMITATIONS],
  };
}

function mergeLimits(values: Partial<ReachabilityLimits>): ReachabilityLimits {
  const result = { ...DEFAULT_REACHABILITY_LIMITS };
  for (const key of Object.keys(result) as Array<keyof ReachabilityLimits>) {
    const value = values[key];
    if (typeof value === "number" && Number.isFinite(value) && value > 0) result[key] = Math.floor(value);
  }
  return result;
}

function normalizeInputPath(value: string, maxLength: number) {
  if (!value || value.length > maxLength || value.includes("\0")) return null;
  const replaced = value.replaceAll("\\", "/");
  if (replaced.startsWith("/") || replaced.startsWith("//") || /^[A-Za-z]:\//.test(replaced)) return null;
  const parts = replaced.split("/").filter((part) => part && part !== ".");
  if (!parts.length || parts.some((part) => part === "..")) return null;
  return parts.join("/");
}

function tokenize(source: string, maxTokens: number): { tokens: Token[]; exceeded: boolean } {
  const tokens: Token[] = [];
  let index = 0;
  let line = 1;
  const push = (token: Token) => {
    if (tokens.length <= maxTokens) tokens.push(token);
  };
  while (index < source.length && tokens.length <= maxTokens) {
    const character = source[index];
    if (character === "\n") {
      line++;
      index++;
      continue;
    }
    if (/\s/.test(character)) {
      index++;
      continue;
    }
    if (character === "/" && source[index + 1] === "/") {
      index += 2;
      while (index < source.length && source[index] !== "\n") index++;
      continue;
    }
    if (character === "/" && source[index + 1] === "*") {
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/")) {
        if (source[index] === "\n") line++;
        index++;
      }
      index = Math.min(source.length, index + 2);
      continue;
    }
    if (character === "'" || character === '"') {
      const quote = character;
      const tokenLine = line;
      let value = "";
      index++;
      while (index < source.length) {
        const current = source[index];
        if (current === "\\" && index + 1 < source.length) {
          const escaped = source[index + 1];
          if (escaped === "\n") line++;
          else value += escaped;
          index += 2;
          continue;
        }
        if (current === quote) {
          index++;
          break;
        }
        if (current === "\n") line++;
        value += current;
        index++;
      }
      push({ kind: "string", value, line: tokenLine });
      continue;
    }
    if (character === "`") {
      const tokenLine = line;
      let value = "";
      index++;
      while (index < source.length) {
        const current = source[index];
        if (current === "\\" && index + 1 < source.length) {
          index += 2;
          continue;
        }
        if (current === "`") {
          index++;
          break;
        }
        if (current === "\n") line++;
        value += current;
        index++;
      }
      push({ kind: "template", value, line: tokenLine });
      continue;
    }
    if (/[A-Za-z_$]/.test(character)) {
      const tokenLine = line;
      const start = index++;
      while (index < source.length && /[A-Za-z0-9_$]/.test(source[index])) index++;
      push({ kind: "identifier", value: source.slice(start, index), line: tokenLine });
      continue;
    }
    if (character === "?" && source[index + 1] === ".") {
      push({ kind: "punctuation", value: "?.", line });
      index += 2;
      continue;
    }
    push({ kind: "punctuation", value: character, line });
    index++;
  }
  return { tokens: tokens.slice(0, maxTokens), exceeded: tokens.length > maxTokens };
}

function parseSourceFile(
  filePath: string,
  tokens: Token[],
  warnings: ReachabilityDiagnostic[],
): ParsedFile {
  const localImports: LocalImport[] = [];
  const packageImports: MutableImport[] = [];
  const bindings = new Map<string, Binding[]>();
  let incomplete = false;

  const addObservation = (
    specifier: string,
    kind: ImportKind,
    line: number,
    importedApis: Iterable<string> = [],
  ) => {
    if (specifier.startsWith(".")) {
      localImports.push({ specifier, line });
      return null;
    }
    if (specifier.startsWith("@/") || specifier.startsWith("~/")) {
      warnings.push({
        level: "warning",
        code: "UNRESOLVED_PATH_ALIAS",
        message: `${filePath}:${line} uses path alias ${specifier}; aliases are not resolved by the bounded analyzer.`,
        file: filePath,
        line,
      });
      incomplete = true;
      return null;
    }
    const packageName = packageRoot(specifier);
    if (!packageName || specifier.startsWith("#") || specifier.startsWith("node:")) return null;
    const observation: MutableImport = {
      sourceFile: filePath,
      line,
      specifier,
      packageName,
      kind,
      importedApis: [],
      observedApis: [],
      imported: new Set(importedApis),
      observed: new Set(),
    };
    packageImports.push(observation);
    return observation;
  };

  const addBinding = (name: string, binding: Binding) => {
    const current = bindings.get(name) ?? [];
    current.push(binding);
    bindings.set(name, current);
  };

  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index];
    if (token.value === "import") {
      if (tokens[index + 1]?.value === "(") {
        if (isTypeImportContext(tokens, index)) continue;
        const argument = tokens[index + 2];
        if (argument?.kind === "string" && tokens[index + 3]?.value === ")") {
          addObservation(argument.value, "dynamic-import", token.line);
        } else {
          warnings.push({
            level: "warning",
            code: "DYNAMIC_MODULE_REFERENCE",
            message: `${filePath}:${token.line} contains a non-literal dynamic import that cannot be resolved statically.`,
            file: filePath,
            line: token.line,
          });
          incomplete = true;
        }
        continue;
      }
      if (tokens[index + 1]?.value === ".") continue;
      const statementEnd = findStatementEnd(tokens, index);
      const typeOnly = tokens[index + 1]?.value === "type";
      const immediate = tokens[index + 1];
      let specifierToken = immediate?.kind === "string" ? immediate : undefined;
      let fromIndex = -1;
      if (!specifierToken) {
        for (let cursor = index + 1; cursor <= statementEnd; cursor++) {
          if (tokens[cursor]?.value === "from" && tokens[cursor + 1]?.kind === "string") {
            fromIndex = cursor;
            specifierToken = tokens[cursor + 1];
            break;
          }
        }
      }
      if (!specifierToken || typeOnly) continue;
      const bindingEnd = fromIndex >= 0 ? fromIndex : index + 1;
      const parsedBindings = parseStaticBindings(tokens, index + 1, bindingEnd, specifierToken.value);
      const observation = addObservation(
        specifierToken.value,
        "static-import",
        token.line,
        parsedBindings.map((binding) => binding.api).filter((api) => api !== "*"),
      );
      if (observation) {
        for (const binding of parsedBindings) {
          addBinding(binding.local, {
            observation,
            api: binding.api,
            namespace: binding.namespace,
            declarationToken: binding.tokenIndex,
          });
        }
      }
      continue;
    }

    if (token.value === "export") {
      const statementEnd = findStatementEnd(tokens, index);
      for (let cursor = index + 1; cursor <= statementEnd; cursor++) {
        if (tokens[cursor]?.value === "from" && tokens[cursor + 1]?.kind === "string") {
          const imported = tokens
            .slice(index + 1, cursor)
            .filter((candidate) => candidate.kind === "identifier" && candidate.value !== "type" && candidate.value !== "as")
            .map((candidate) => candidate.value);
          addObservation(tokens[cursor + 1].value, "re-export", token.line, imported);
          break;
        }
      }
    }

    if (token.value === "require" && tokens[index + 1]?.value === "(") {
      const argument = tokens[index + 2];
      if (argument?.kind !== "string" || tokens[index + 3]?.value !== ")") {
        warnings.push({
          level: "warning",
          code: "DYNAMIC_MODULE_REFERENCE",
          message: `${filePath}:${token.line} contains a non-literal require() that cannot be resolved statically.`,
          file: filePath,
          line: token.line,
        });
        incomplete = true;
        continue;
      }
      const member = (tokens[index + 4]?.value === "." || tokens[index + 4]?.value === "?.") && tokens[index + 5]?.kind === "identifier"
        ? tokens[index + 5].value
        : null;
      const observation = addObservation(argument.value, "require", token.line, member ? [member] : []);
      if (!observation) continue;
      if (member) observation.observed.add(member);
      const assignment = findAssignmentBinding(tokens, index);
      if (assignment) {
        for (const binding of assignment) {
          observation.imported.add(binding.api);
          addBinding(binding.local, {
            observation,
            api: binding.api,
            namespace: binding.namespace,
            declarationToken: binding.tokenIndex,
          });
        }
      }
      if (tokens[index + 4]?.value === "(") observation.observed.add("default");
    }
  }

  for (let index = 0; index < tokens.length; index++) {
    const candidates = bindings.get(tokens[index].value);
    if (!candidates) continue;
    for (const binding of candidates) {
      if (binding.declarationToken === index) continue;
      const accessor = tokens[index + 1]?.value === "." || tokens[index + 1]?.value === "?.";
      const member = accessor && tokens[index + 2]?.kind === "identifier" ? tokens[index + 2].value : null;
      if (member && binding.namespace) binding.observation.observed.add(member);
      else if (member && binding.api === "default") binding.observation.observed.add(member);
      else if (!binding.namespace) binding.observation.observed.add(binding.api);
    }
  }

  for (const observation of packageImports) {
    observation.importedApis = [...observation.imported].filter((api) => api !== "*").sort();
    observation.observedApis = [...observation.observed].filter((api) => api !== "*").sort();
  }

  return {
    path: filePath,
    tokens,
    localImports,
    localEdges: [],
    packageImports,
    routes: [...nextRouteHints(filePath, tokens), ...expressRouteHints(filePath, tokens)],
    incomplete,
  };
}

function isTypeImportContext(tokens: Token[], importIndex: number) {
  for (let index = importIndex - 1; index >= 0; index--) {
    if (tokens[index].value === ";" || tokens[index].line < tokens[importIndex].line - 3) break;
    if (tokens[index].value === "type" || tokens[index].value === "interface") return true;
  }
  return false;
}

function findStatementEnd(tokens: Token[], start: number) {
  let depth = 0;
  for (let index = start + 1; index < tokens.length; index++) {
    const value = tokens[index].value;
    if (value === "(" || value === "{" || value === "[") depth++;
    if (value === ")" || value === "}" || value === "]") depth = Math.max(0, depth - 1);
    if (value === ";" && depth === 0) return index;
    if (depth === 0 && tokens[index].line > tokens[start].line + 8) return index - 1;
  }
  return Math.min(tokens.length - 1, start + 80);
}

function parseStaticBindings(tokens: Token[], start: number, end: number, specifier: string) {
  const bindings: Array<{ local: string; api: string; namespace: boolean; tokenIndex: number }> = [];
  const subpathApi = packageSubpathApi(specifier);
  let cursor = start;
  if (tokens[cursor]?.value === "type") cursor++;
  if (tokens[cursor]?.kind === "identifier" && tokens[cursor].value !== "from") {
    bindings.push({
      local: tokens[cursor].value,
      api: subpathApi ?? "default",
      namespace: false,
      tokenIndex: cursor,
    });
  }
  for (let index = cursor; index < end; index++) {
    if (tokens[index]?.value === "*" && tokens[index + 1]?.value === "as" && tokens[index + 2]?.kind === "identifier") {
      bindings.push({ local: tokens[index + 2].value, api: "*", namespace: true, tokenIndex: index + 2 });
    }
    if (tokens[index]?.value !== "{") continue;
    index++;
    while (index < end && tokens[index]?.value !== "}") {
      if (tokens[index]?.value === ",") {
        index++;
        continue;
      }
      if (tokens[index]?.value === "type") {
        while (index < end && tokens[index]?.value !== "," && tokens[index]?.value !== "}") index++;
        continue;
      }
      if (tokens[index]?.kind !== "identifier") {
        index++;
        continue;
      }
      const imported = tokens[index].value;
      let local = imported;
      let declarationToken = index;
      if (tokens[index + 1]?.value === "as" && tokens[index + 2]?.kind === "identifier") {
        local = tokens[index + 2].value;
        declarationToken = index + 2;
        index += 2;
      }
      bindings.push({ local, api: imported, namespace: false, tokenIndex: declarationToken });
      index++;
    }
  }
  return bindings;
}

function findAssignmentBinding(tokens: Token[], requireIndex: number) {
  let equals = -1;
  for (let index = requireIndex - 1; index >= 0 && tokens[index].line >= tokens[requireIndex].line - 2; index--) {
    if (tokens[index].value === ";") break;
    if (tokens[index].value === "=") {
      equals = index;
      break;
    }
  }
  if (equals < 0) return null;
  if (tokens[equals - 1]?.kind === "identifier") {
    return [{ local: tokens[equals - 1].value, api: "*", namespace: true, tokenIndex: equals - 1 }];
  }
  if (tokens[equals - 1]?.value !== "}") return null;
  let open = equals - 2;
  while (open >= 0 && tokens[open].value !== "{") open--;
  if (open < 0) return null;
  const bindings: Array<{ local: string; api: string; namespace: boolean; tokenIndex: number }> = [];
  for (let index = open + 1; index < equals - 1; index++) {
    if (tokens[index].kind !== "identifier") continue;
    const imported = tokens[index].value;
    let local = imported;
    let tokenIndex = index;
    if (tokens[index + 1]?.value === ":" && tokens[index + 2]?.kind === "identifier") {
      local = tokens[index + 2].value;
      tokenIndex = index + 2;
      index += 2;
    }
    bindings.push({ local, api: imported, namespace: false, tokenIndex });
  }
  return bindings;
}

function packageRoot(specifier: string) {
  if (!specifier || specifier.startsWith("/") || specifier.includes(":")) return null;
  const parts = specifier.split("/");
  if (specifier.startsWith("@")) return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  return parts[0] || null;
}

function packageSubpathApi(specifier: string) {
  const root = packageRoot(specifier);
  if (!root || specifier === root) return null;
  return specifier.slice(root.length + 1).split("/").filter(Boolean).at(-1) ?? null;
}

function resolveLocalEdges(
  file: ParsedFile,
  knownPaths: Set<string>,
  warnings: ReachabilityDiagnostic[],
) {
  for (const local of file.localImports) {
    const resolved = resolveRelativeModule(file.path, local.specifier, knownPaths);
    if (resolved) {
      file.localEdges.push(resolved);
      continue;
    }
    const extension = path.posix.extname(local.specifier).toLowerCase();
    if (extension && !SOURCE_EXTENSIONS.has(extension)) continue;
    warnings.push({
      level: "warning",
      code: "UNRESOLVED_RELATIVE_IMPORT",
      message: `${file.path}:${local.line} imports ${local.specifier}, but the target source file was not supplied.`,
      file: file.path,
      line: local.line,
    });
    file.incomplete = true;
  }
  file.localEdges = [...new Set(file.localEdges)].sort();
}

function resolveRelativeModule(from: string, specifier: string, knownPaths: Set<string>) {
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier));
  if (base === ".." || base.startsWith("../") || base.startsWith("/")) return null;
  const extension = path.posix.extname(base).toLowerCase();
  const candidates = extension
    ? [base]
    : [
        base,
        ...[...SOURCE_EXTENSIONS].map((value) => `${base}${value}`),
        ...[...SOURCE_EXTENSIONS].map((value) => `${base}/index${value}`),
      ];
  return candidates.find((candidate) => knownPaths.has(candidate)) ?? null;
}

function nextRouteHints(filePath: string, tokens: Token[]): RouteHint[] {
  if (!/^route\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i.test(path.posix.basename(filePath))) return [];
  const parts = filePath.split("/");
  const appIndex = parts.lastIndexOf("app");
  if (appIndex < 0) return [];
  const routeParts = parts
    .slice(appIndex + 1, -1)
    .filter((part) => !(part.startsWith("(") && part.endsWith(")")) && !part.startsWith("@"));
  const route = `/${routeParts.join("/")}`.replace(/\/$/, "") || "/";
  const methods = new Set<string>();
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index].value !== "export") continue;
    let cursor = index + 1;
    if (tokens[cursor]?.value === "async") cursor++;
    if (tokens[cursor]?.value === "function") cursor++;
    else if (tokens[cursor]?.value === "const" || tokens[cursor]?.value === "let" || tokens[cursor]?.value === "var") cursor++;
    const candidate = tokens[cursor]?.value?.toUpperCase();
    if (ROUTE_METHODS.has(candidate)) methods.add(candidate);
  }
  return [...methods].sort().map((method) => ({
    id: `next:${method}:${route}:${filePath}`,
    kind: "next-route" as const,
    file: filePath,
    method,
    route,
    exposure: "POSSIBLY_INTERNET_EXPOSED" as const,
  }));
}

function expressRouteHints(filePath: string, tokens: Token[]): RouteHint[] {
  const routes: RouteHint[] = [];
  for (let index = 0; index < tokens.length - 5; index++) {
    const receiver = tokens[index];
    const method = tokens[index + 2];
    const route = tokens[index + 4];
    if (
      receiver.kind !== "identifier" ||
      !/^(?:app|router|server|api|.*router)$/i.test(receiver.value) ||
      (tokens[index + 1].value !== "." && tokens[index + 1].value !== "?.") ||
      method.kind !== "identifier" ||
      !EXPRESS_METHODS.has(method.value.toLowerCase()) ||
      tokens[index + 3].value !== "(" ||
      route.kind !== "string" ||
      !route.value.startsWith("/")
    ) continue;
    const normalizedMethod = method.value.toUpperCase();
    routes.push({
      id: `express:${normalizedMethod}:${route.value}:${filePath}:${method.line}`,
      kind: "express-route",
      file: filePath,
      method: normalizedMethod,
      route: route.value,
      exposure: "POSSIBLY_INTERNET_EXPOSED",
    });
  }
  return routes;
}

function dedupeRoutes(routes: RouteHint[]) {
  return [...new Map(routes.map((route) => [route.id, route])).values()].sort((left, right) =>
    `${left.file}:${left.route}:${left.method}`.localeCompare(`${right.file}:${right.route}:${right.method}`),
  );
}

function indexRoutePaths(routes: RouteHint[], files: Map<string, ParsedFile>) {
  const result = new Map<string, RouteSourcePath[]>();
  for (const route of routes) {
    const queue = [route.file];
    const previous = new Map<string, string | null>([[route.file, null]]);
    while (queue.length) {
      const current = queue.shift()!;
      const values = result.get(current) ?? [];
      if (values.length < 50) values.push({ route, files: rebuildFilePath(previous, current) });
      result.set(current, values);
      for (const target of files.get(current)?.localEdges ?? []) {
        if (previous.has(target)) continue;
        previous.set(target, current);
        queue.push(target);
      }
    }
  }
  return result;
}

function rebuildFilePath(previous: Map<string, string | null>, target: string) {
  const result: string[] = [];
  let cursor: string | null | undefined = target;
  while (cursor) {
    result.push(cursor);
    cursor = previous.get(cursor);
  }
  return result.reverse();
}

function groupPackageImports(imports: MutableImport[]) {
  const result = new Map<string, MutableImport[]>();
  for (const observation of imports) {
    const values = result.get(observation.packageName) ?? [];
    values.push(observation);
    result.set(observation.packageName, values);
  }
  return result;
}

function buildDependencyEvidence(values: {
  dependency: DependencyReachabilityInput;
  key: string;
  packageImportsByName: Map<string, MutableImport[]>;
  routePathsByFile: Map<string, RouteSourcePath[]>;
  incomplete: boolean;
  limits: ReachabilityLimits;
  sameNameCount: number;
  directNameCount: number;
}): ReachabilityEvidence {
  const { dependency } = values;
  const directImports = values.packageImportsByName.get(dependency.name) ?? [];
  const dependencyPaths = normalizedDependencyPaths(dependency);
  const parentDependencies = new Set<string>();
  for (const dependencyPath of dependencyPaths) {
    dependencyPath.slice(1, -1).forEach((node) => parentDependencies.add(node));
  }

  const evidencePaths: ReachabilityPathEvidence[] = [];
  for (const observation of directImports) {
    addSourceEvidencePaths({
      evidencePaths,
      observation,
      routePathsByFile: values.routePathsByFile,
      packageChain: [`${dependency.name}@${dependency.version}`],
      kind: "DIRECT_IMPORT",
      explanation: `A literal ${observation.kind} of ${observation.specifier} was observed in application source.`,
      limit: values.limits.maxEvidencePathsPerDependency,
    });
  }

  for (const dependencyPath of dependencyPaths) {
    for (let index = 1; index < dependencyPath.length - 1; index++) {
      const parentName = packageNameFromDependencyNode(dependencyPath[index]);
      const observations = values.packageImportsByName.get(parentName) ?? [];
      for (const observation of observations) {
        addSourceEvidencePaths({
          evidencePaths,
          observation,
          routePathsByFile: values.routePathsByFile,
          packageChain: dependencyPath.slice(index),
          kind: "TRANSITIVE_PARENT",
          explanation: `${parentName} is imported by the application and the lockfile path continues to ${dependency.name}@${dependency.version}; execution through the parent is only possible, not proven.`,
          limit: values.limits.maxEvidencePathsPerDependency,
        });
      }
    }
  }

  const dedupedPaths = dedupeEvidencePaths(evidencePaths).slice(0, values.limits.maxEvidencePathsPerDependency);
  const exactVersionObserved =
    directImports.length > 0 &&
    (values.sameNameCount === 1 || (dependency.direct === true && values.directNameCount === 1));
  const transitiveObserved = dedupedPaths.some((item) => item.kind === "TRANSITIVE_PARENT");
  let status: ReachabilityStatus;
  let explanation: string;
  if (exactVersionObserved) {
    status = "REACHABLE";
    explanation = `A static runtime import or require of ${dependency.name} was observed. This establishes package-level reachability for the resolved version, not execution of a vulnerable function.`;
  } else if (directImports.length) {
    status = "POSSIBLY_REACHABLE";
    explanation = `A static import of ${dependency.name} was observed, but multiple installed instances make exact version resolution ambiguous.`;
  } else if (transitiveObserved) {
    status = "POSSIBLY_REACHABLE";
    explanation = `An imported parent package can lead to ${dependency.name}@${dependency.version} through the dependency graph. Static source analysis cannot prove the parent executes this transitive package.`;
  } else if (values.incomplete) {
    status = "UNKNOWN";
    explanation = `The bounded source analysis was incomplete, so no reliable absence statement can be made for ${dependency.name}@${dependency.version}.`;
  } else {
    status = "NOT_OBSERVED";
    explanation = `No supported static runtime import path to ${dependency.name}@${dependency.version} was observed in the supplied source bundle. This is not proof that the dependency is unused or safe.`;
  }

  const packageImports = directImports.map(publicImportEvidence);
  const importedApis = uniqueSorted(directImports.flatMap((item) => [...item.imported]));
  const observedApis = uniqueSorted(directImports.flatMap((item) => [...item.observed]));
  const requestedApis = dependency.vulnerableApis?.map(normalizeApiName).filter(Boolean) ?? [];
  const observedNormalized = new Map(observedApis.map((api) => [normalizeApiName(api), api]));
  const matchedVulnerableApis = uniqueSorted(
    requestedApis.flatMap((api) => observedNormalized.get(api) ? [observedNormalized.get(api)!] : []),
  );
  const vulnerableApiMatch = !dependency.vulnerableApis?.length
    ? "NOT_REQUESTED"
    : matchedVulnerableApis.length
      ? "MATCHED"
      : directImports.length
        ? "NOT_OBSERVED"
        : "UNKNOWN";
  const blastRadius = buildBlastRadius(dedupedPaths, parentDependencies);
  return {
    key: values.key,
    dependency: { name: dependency.name, version: dependency.version },
    status,
    explanation,
    packageImports,
    importedApis,
    observedApis,
    vulnerableApiMatch,
    matchedVulnerableApis,
    paths: dedupedPaths,
    blastRadius,
    limitations: [...STATIC_LIMITATIONS],
  };
}

function addSourceEvidencePaths(values: {
  evidencePaths: ReachabilityPathEvidence[];
  observation: MutableImport;
  routePathsByFile: Map<string, RouteSourcePath[]>;
  packageChain: string[];
  kind: ReachabilityPathEvidence["kind"];
  explanation: string;
  limit: number;
}) {
  if (values.evidencePaths.length >= values.limit) return;
  const routePaths = values.routePathsByFile.get(values.observation.sourceFile) ?? [];
  if (!routePaths.length) {
    values.evidencePaths.push({
      kind: values.kind,
      certainty: values.kind === "DIRECT_IMPORT" ? "OBSERVED" : "POSSIBLE",
      nodes: ["Application source", values.observation.sourceFile, ...values.packageChain],
      sourceFiles: [values.observation.sourceFile],
      packageChain: values.packageChain,
      explanation: values.explanation,
    });
    return;
  }
  for (const routePath of routePaths) {
    if (values.evidencePaths.length >= values.limit) break;
    values.evidencePaths.push({
      kind: values.kind,
      certainty: "POSSIBLE",
      nodes: [`${routePath.route.method} ${routePath.route.route}`, ...routePath.files, ...values.packageChain],
      sourceFiles: routePath.files,
      packageChain: values.packageChain,
      route: routePath.route,
      explanation: `${values.explanation} The route-to-module association is an import-graph estimate.`,
    });
  }
}

function normalizedDependencyPaths(dependency: DependencyReachabilityInput) {
  const structured = dependency.paths?.map((item) => [...item.nodes]).filter((nodes) => nodes.length) ?? [];
  if (structured.length) return structured;
  if (dependency.path) return [dependency.path.split(/\s*→\s*/).filter(Boolean)];
  return [["Application", `${dependency.name}@${dependency.version}`]];
}

function packageNameFromDependencyNode(node: string) {
  const separator = node.lastIndexOf("@");
  return separator > 0 ? node.slice(0, separator) : node;
}

function dedupeEvidencePaths(paths: ReachabilityPathEvidence[]) {
  return [...new Map(paths.map((item) => [`${item.kind}:${item.nodes.join("\0")}`, item])).values()];
}

function buildBlastRadius(paths: ReachabilityPathEvidence[], parents: Set<string>): BlastRadiusEstimate {
  const routeMap = new Map<string, RouteHint>();
  const sourceFiles = new Set<string>();
  const applicationAreas = new Set<string>();
  for (const evidence of paths) {
    if (evidence.route) {
      routeMap.set(evidence.route.id, evidence.route);
      const area = evidence.route.route.split("/").filter(Boolean)[0];
      if (area) applicationAreas.add(area);
    }
    evidence.sourceFiles.forEach((file) => {
      sourceFiles.add(file);
      const parts = file.split("/");
      const src = parts.indexOf("src");
      const area = parts[src >= 0 ? src + 1 : 0];
      if (area) applicationAreas.add(area);
    });
  }
  const routes = [...routeMap.values()];
  const files = [...sourceFiles].sort();
  const parentDependencies = [...parents].sort();
  return {
    routes,
    sourceFiles: files,
    modules: files,
    parentDependencies,
    applicationAreas: [...applicationAreas].sort(),
    evidencePaths: paths,
    counts: {
      routes: routes.length,
      sourceFiles: files.length,
      parentDependencies: parentDependencies.length,
      evidencePaths: paths.length,
    },
    caveat: "This blast radius is an evidence-backed estimate from static imports and route hints, not proof of exploitability or runtime execution.",
  };
}

function publicImportEvidence(observation: MutableImport): PackageImportEvidence {
  return {
    sourceFile: observation.sourceFile,
    line: observation.line,
    specifier: observation.specifier,
    packageName: observation.packageName,
    kind: observation.kind,
    importedApis: [...observation.imported].filter((api) => api !== "*").sort(),
    observedApis: [...observation.observed].filter((api) => api !== "*").sort(),
  };
}

function normalizeApiName(value: string) {
  return value.trim().replace(/\(\)$/, "").split(".").at(-1)?.toLowerCase() ?? "";
}

function uniqueSorted(values: string[]) {
  return [...new Set(values.filter(Boolean))].sort();
}

function dedupeDiagnostics(values: ReachabilityDiagnostic[]) {
  return [...new Map(values.map((item) => [`${item.code}:${item.file ?? ""}:${item.line ?? ""}:${item.message}`, item])).values()];
}

function emptyAnalysis(
  filesReceived: number,
  totalBytes: number,
  dependencies: ReadonlyArray<DependencyReachabilityInput>,
  warnings: ReachabilityDiagnostic[],
  errors: ReachabilityDiagnostic[],
): ReachabilityAnalysis {
  const byDependency = Object.create(null) as Record<string, ReachabilityEvidence>;
  const findings = dependencies.map((dependency, index) => {
    const key = dependencyReachabilityKey(
      dependency.name,
      dependency.version,
      dependency.instanceId ?? dependency.path ?? (index ? `instance-${index + 1}` : undefined),
    );
    const evidence: ReachabilityEvidence = {
      key,
      dependency: { name: dependency.name, version: dependency.version },
      status: "UNKNOWN",
      explanation: "Reachability is unknown because the source bundle was rejected by bounded-analysis limits.",
      packageImports: [],
      importedApis: [],
      observedApis: [],
      vulnerableApiMatch: dependency.vulnerableApis?.length ? "UNKNOWN" : "NOT_REQUESTED",
      matchedVulnerableApis: [],
      paths: [],
      blastRadius: buildBlastRadius([], new Set()),
      limitations: [...STATIC_LIMITATIONS],
    };
    byDependency[key] = evidence;
    return evidence;
  });
  return {
    byDependency,
    findings,
    routes: [],
    warnings,
    errors,
    complete: false,
    stats: {
      filesReceived,
      filesAnalyzed: 0,
      filesSkipped: filesReceived,
      totalBytes,
      moduleEdges: 0,
      packageImports: 0,
      routeHints: 0,
    },
    limitations: [...STATIC_LIMITATIONS],
  };
}

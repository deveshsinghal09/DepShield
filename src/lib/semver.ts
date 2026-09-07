export type ExactVersion = readonly [major: number, minor: number, patch: number];

export function parseExactVersion(value: string): ExactVersion | null {
  const match = value.trim().match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+][0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)];
}

export function compareExactVersions(left: string, right: string): number | null {
  const a = parseExactVersion(left);
  const b = parseExactVersion(right);
  if (!a || !b) return null;
  for (let index = 0; index < 3; index++) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return 0;
}

/**
 * Small conservative npm-range evaluator used only to reject clearly
 * inapplicable audit rows. null means the expression was not understood and
 * callers must retain the advisory rather than treating it as safe.
 */
export function isVersionInRange(version: string, expression?: string | null): boolean | null {
  if (!expression?.trim() || expression.trim() === "*") return true;
  if (!parseExactVersion(version)) return null;
  const alternatives = expression.split("||").map((value) => value.trim()).filter(Boolean);
  let unknown = false;
  for (const alternative of alternatives) {
    const result = evaluateConjunction(version, alternative);
    if (result === true) return true;
    if (result === null) unknown = true;
  }
  return unknown ? null : false;
}

function evaluateConjunction(version: string, expression: string): boolean | null {
  const hyphen = expression.match(/^\s*(v?\d+(?:\.\d+){0,2})\s+-\s+(v?\d+(?:\.\d+){0,2})\s*$/);
  if (hyphen) {
    const lower = compareExactVersions(version, hyphen[1]);
    const upper = compareExactVersions(version, hyphen[2]);
    return lower === null || upper === null ? null : lower >= 0 && upper <= 0;
  }

  const normalized = expression
    .replace(/([<>]=?|=|\^|~)\s+(?=v?\d)/g, "$1")
    .replace(/,/g, " ")
    .trim();
  const tokens = normalized.split(/\s+/).filter(Boolean);
  if (!tokens.length) return null;
  for (const token of tokens) {
    const result = evaluateComparator(version, token);
    if (result === null) return null;
    if (!result) return false;
  }
  return true;
}

function evaluateComparator(version: string, token: string): boolean | null {
  if (token === "*" || /^x$/i.test(token)) return true;
  const wildcard = token.match(/^v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?$/i);
  if (wildcard && (wildcard[2] === "x" || wildcard[2] === "*" || wildcard[3] === "x" || wildcard[3] === "*")) {
    const parsed = parseExactVersion(version)!;
    if (parsed[0] !== Number(wildcard[1])) return false;
    return wildcard[2] === undefined || /^(x|\*)$/i.test(wildcard[2]) || parsed[1] === Number(wildcard[2]);
  }
  const match = token.match(/^(<=|>=|<|>|=|\^|~)?(v?\d+(?:\.\d+){0,2})(?:-[0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  const operator = match[1] ?? "=";
  const target = match[2];
  const comparison = compareExactVersions(version, target);
  if (comparison === null) return null;
  if (operator === "<") return comparison < 0;
  if (operator === "<=") return comparison <= 0;
  if (operator === ">") return comparison > 0;
  if (operator === ">=") return comparison >= 0;
  if (operator === "=") return comparison === 0;
  const base = parseExactVersion(target)!;
  const candidate = parseExactVersion(version)!;
  if (comparison < 0) return false;
  if (operator === "~") return candidate[0] === base[0] && candidate[1] === base[1];
  if (base[0] > 0) return candidate[0] === base[0];
  if (base[1] > 0) return candidate[0] === 0 && candidate[1] === base[1];
  return candidate[0] === 0 && candidate[1] === 0 && candidate[2] === base[2];
}

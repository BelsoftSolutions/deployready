/**
 * Minimal .gitignore matcher used by the file walker to avoid scanning build
 * output, generated code and vendored copies.
 *
 * Supported: comments, blank lines, `!` negation, trailing `/` (directories
 * only), leading `/` (anchored), `*`, `?` and `**`.
 *
 * FAIL OPEN: this is a security scanner, so anything not fully understood
 * (character classes, escapes, odd or over-broad patterns) must never cause a
 * file to be skipped. Such patterns are dropped. If a *negation* is not
 * understood the whole file is dropped, because a dropped negation could leave
 * an earlier rule skipping files that git would still track.
 */

export interface IgnoreRule {
  negated: boolean;
  dirOnly: boolean;
  anchored: boolean;
  segments: string[];
}

export interface IgnoreScope {
  /** Directory the .gitignore lives in, relative to the scan root ('' for root). */
  base: string;
  rules: IgnoreRule[];
}

const MAX_PATTERN_LENGTH = 512;
const MAX_WILDCARDS = 8;

export function parseGitignore(text: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/[ \t\r]+$/, '');
    if (!line || line.startsWith('#')) continue;
    const negated = line.startsWith('!');
    const rule = parsePattern(negated ? line.slice(1) : line, negated);
    if (rule) {
      rules.push(rule);
    } else if (negated) {
      return [];
    }
  }
  return rules;
}

function parsePattern(pattern: string, negated: boolean): IgnoreRule | null {
  if (!pattern || pattern.length > MAX_PATTERN_LENGTH) return null;
  if (/[\\[\]\s\x00-\x1f]/.test(pattern)) return null;
  if ((pattern.match(/[*?]/g) ?? []).length > MAX_WILDCARDS) return null;

  const dirOnly = pattern.endsWith('/');
  let body = pattern.replace(/\/+$/, '');
  const leadingSlash = body.startsWith('/');
  if (leadingSlash) body = body.slice(1);
  if (!body) return null;

  const segments: string[] = [];
  for (const seg of body.split('/')) {
    if (!seg) return null;
    const normalized = seg === '**' ? seg : seg.replace(/\*{2,}/g, '*');
    if (normalized === '**' && segments[segments.length - 1] === '**') continue;
    segments.push(normalized);
  }

  // `*`, `**`, `/`, `**/*`, `*/` ... would hide the entire project.
  if (!negated && segments.every((s) => /^\*+$/.test(s))) return null;

  return { negated, dirOnly, anchored: leadingSlash || segments.length > 1, segments };
}

/** True when the innermost matching rule across all scopes ignores the path. */
export function isIgnored(scopes: IgnoreScope[], relPath: string, isDir: boolean): boolean {
  let ignored = false;
  for (const scope of scopes) {
    let sub: string;
    if (scope.base === '') {
      sub = relPath;
    } else if (relPath.startsWith(`${scope.base}/`)) {
      sub = relPath.slice(scope.base.length + 1);
    } else {
      continue;
    }
    const decision = evaluate(scope.rules, sub, isDir);
    if (decision !== null) ignored = decision;
  }
  return ignored;
}

function evaluate(rules: IgnoreRule[], sub: string, isDir: boolean): boolean | null {
  let decision: boolean | null = null;
  let parts: string[] | null = null;
  for (const rule of rules) {
    if (rule.dirOnly && !isDir) continue;
    let hit: boolean;
    if (rule.anchored) {
      parts ??= sub.split('/');
      hit = matchSegments(rule.segments, parts);
    } else {
      hit = globMatch(rule.segments[0]!, sub.slice(sub.lastIndexOf('/') + 1));
    }
    if (hit) decision = !rule.negated;
  }
  return decision;
}

function matchSegments(pattern: string[], parts: string[]): boolean {
  const memo = new Map<number, boolean>();
  const width = parts.length + 1;
  const go = (i: number, j: number): boolean => {
    const key = i * width + j;
    const cached = memo.get(key);
    if (cached !== undefined) return cached;
    let result: boolean;
    if (i === pattern.length) {
      result = j === parts.length;
    } else if (pattern[i] === '**') {
      if (i === pattern.length - 1) {
        result = j < parts.length;
      } else {
        result = false;
        for (let k = j; k <= parts.length && !result; k++) result = go(i + 1, k);
      }
    } else {
      result = j < parts.length && globMatch(pattern[i]!, parts[j]!) && go(i + 1, j + 1);
    }
    memo.set(key, result);
    return result;
  };
  return go(0, 0);
}

/** `*` / `?` glob match on a single path segment, linear-ish (no regex backtracking). */
function globMatch(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let starP = -1;
  let starT = 0;
  while (t < text.length) {
    const c = pattern[p];
    if (c === '*') {
      starP = p++;
      starT = t;
    } else if (c === '?' || c === text[t]) {
      p++;
      t++;
    } else if (starP !== -1) {
      p = starP + 1;
      t = ++starT;
    } else {
      return false;
    }
  }
  while (pattern[p] === '*') p++;
  return p === pattern.length;
}

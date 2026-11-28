/**
 * Baseline fingerprints: collision-resistant, move-stable identities for findings.
 *
 * identity = rule + normalized path + endpoint + enclosing symbol
 *          + normalized context hash + occurrence index (among identical identities in the file)
 *
 * Privacy: the context is the finding line with whitespace collapsed and every string literal
 * replaced by a length class (`"S16"`), so no secret (or hash of a secret) is ever stored.
 * Severity is deliberately NOT part of identity; it is tracked separately by the baseline.
 */
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import type { Finding } from '../types';

const MAX_FILE_BYTES = 2 * 1024 * 1024;

/** Replace string-literal contents with a coarse length class, collapse whitespace. */
export function normalizeContext(line: string): string {
  const cls = (n: number): string => (n === 0 ? '0' : n <= 8 ? '8' : n <= 16 ? '16' : n <= 32 ? '32' : n <= 64 ? '64' : '64+');
  return line
    .replace(/(["'`])((?:\\.|(?!\1)[^\\])*)\1/g, (_m, q: string, body: string) => `${q}S${cls(body.length)}${q}`)
    .replace(/\s+/g, ' ')
    .trim();
}

const SYMBOL_PATTERNS: RegExp[] = [
  /\b(?:app|router|server|api|r)\.(get|post|put|patch|delete|all|use)\s*\(\s*['"`]([^'"`]*)['"`]/i,
  /@(?:\w+\.)?(get|post|put|patch|delete|route)\s*\(\s*['"`]([^'"`]*)['"`]/i,
  /\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)/,
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/,
  /\bdef\s+([A-Za-z_]\w*)/,
  /\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)/,
  /^\s*(?:public|private|protected|static|async)\s+(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(/,
];

/** Nearest preceding function/route declaration at or above `lineNo` (1-based), or ''. */
export function enclosingSymbol(lines: string[], lineNo: number): string {
  for (let i = Math.min(lineNo, lines.length) - 1; i >= 0; i--) {
    const text = lines[i] ?? "";
    for (const re of SYMBOL_PATTERNS) {
      const m = re.exec(text);
      if (m) return m.slice(1).filter(Boolean).join(' ').toLowerCase();
    }
  }
  return '';
}

export function normalizePath(p: string | undefined): string {
  return (p ?? '').replace(/\\/g, '/').replace(/^\.\//, '');
}

const fileCache = new Map<string, string[] | null>();

function readLines(root: string, file: string): string[] | null {
  const abs = path.resolve(root, file);
  const hit = fileCache.get(abs);
  if (hit !== undefined) return hit;
  let lines: string[] | null = null;
  try {
    const st = fs.statSync(abs);
    if (st.isFile() && st.size <= MAX_FILE_BYTES) lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
  } catch {
    lines = null;
  }
  fileCache.set(abs, lines);
  return lines;
}

/** Drop cached file contents (call between scans in long-lived processes and tests). */
export function clearFingerprintCache(): void {
  fileCache.clear();
}

export interface Fingerprinted {
  finding: Finding;
  fingerprint: string;
}

/**
 * Fingerprint every finding. Findings that would otherwise collide (same rule/file/symbol/context)
 * get an occurrence index in source order, so N similar issues in one file stay N distinct entries.
 */
export function fingerprintAll(findings: Finding[], root: string): Fingerprinted[] {
  const ordered = findings
    .map((finding, i) => ({ finding, i }))
    .sort((a, b) => (a.finding.line ?? 0) - (b.finding.line ?? 0) || a.i - b.i);
  const seen = new Map<string, number>();
  const out = new Map<Finding, string>();
  for (const { finding: f } of ordered) {
    const file = normalizePath(f.file);
    const lines = f.file && f.line ? readLines(root, f.file) : null;
    const ctx = lines && f.line && lines[f.line - 1] !== undefined ? normalizeContext(lines[f.line - 1] ?? "") : '';
    const sym = lines && f.line ? enclosingSymbol(lines, f.line) : '';
    const identity = [f.rule, file, (f.endpoint ?? '').toLowerCase(), sym, ctx].join('\u0000');
    const hash = crypto.createHash('sha256').update(identity).digest('hex').slice(0, 20);
    const n = seen.get(hash) ?? 0;
    seen.set(hash, n + 1);
    out.set(f, `${hash}.${n}`);
  }
  return findings.map((finding) => ({ finding, fingerprint: out.get(finding) as string }));
}

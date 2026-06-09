/**
 * Deterministic, single-line auto-fixers keyed by static rule.
 *
 * Each fixer is a pure `(line) => string | null` transform applied to the ONE
 * source line a finding points at. It returns the rewritten line, or `null`
 * when the line doesn't match the fixable shape (e.g. an env-var variant we
 * won't touch) — in which case the caller falls back to an AI diff or guidance.
 *
 * Keep every transform bounded and surgical: flip a flag or swap an algorithm
 * name, never restructure code. Anything ambiguous belongs in the AI path.
 */
export type LineFixer = (line: string) => string | null;

/** Apply `re` to `line`; return the result, or null if nothing changed. */
function sub(line: string, re: RegExp, repl: string): string | null {
  const out = line.replace(re, repl);
  return out === line ? null : out;
}

export const LINE_FIXERS: Record<string, LineFixer> = {
  // crypto.createHash('md5'|'sha1') -> 'sha256' (quote style preserved)
  'weak-hash': (l) => sub(l, /(createHash\(\s*['"])(?:md5|sha1)(['"])/i, '$1sha256$2'),

  // hashlib.md5(/sha1( -> hashlib.sha256(
  'py-weak-hash': (l) => sub(l, /hashlib\.(?:md5|sha1)\(/, 'hashlib.sha256('),

  // yaml.load( -> yaml.safe_load(
  'py-yaml-load': (l) => sub(l, /yaml\.load\(/, 'yaml.safe_load('),

  // rejectUnauthorized: false -> true  (the code form only; env-var form -> null)
  'tls-verification-disabled': (l) => sub(l, /(rejectUnauthorized\s*:\s*)false/, '$1true'),

  // requests verify=False -> verify=True
  'py-requests-noverify': (l) => sub(l, /(verify\s*=\s*)False/, '$1True'),

  // Flask app.run(debug=True) -> debug=False
  'py-flask-debug': (l) => sub(l, /(debug\s*=\s*)True/, '$1False'),
};

/** Fix a single line for `rule`, or null if the rule/line isn't fixable. */
export function fixLine(rule: string, line: string): string | null {
  const fixer = LINE_FIXERS[rule];
  return fixer ? fixer(line) : null;
}

/**
 * Central secret redaction. Anything that gets logged, exported, or sent to an
 * AI model MUST pass through here first. This is the single most important
 * safety primitive in the tool — research shows AI-assisted code leaks secrets
 * at ~2x baseline, and our own tool reads that code, so we never echo it back.
 *
 * Patterns are deliberately bounded/anchored to avoid catastrophic backtracking
 * (ReDoS). Each works on a single line of bounded length.
 */

/** Known high-confidence secret token shapes. */
const TOKEN_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'anthropic', re: /\bsk-ant-[a-zA-Z0-9_-]{20,120}\b/g },
  { name: 'openai', re: /\bsk-(?:proj-)?[a-zA-Z0-9]{20,120}\b/g },
  { name: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'google-api', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { name: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,250}\b/g },
  { name: 'stripe', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}\b/g },
  { name: 'jwt', re: /\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b/g },
  { name: 'private-key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: 'generic-bearer', re: /\bBearer\s+[A-Za-z0-9._-]{16,}\b/gi },
  // Credentials embedded in a connection URL, e.g. postgres://user:pass@host.
  { name: 'url-credentials', re: /\/\/[^/:@\s]+:[^@\s/]{3,}@/g },
];

/** `KEY = "value"` style assignments where the key name implies a secret. */
const ASSIGNMENT_RE =
  /\b([A-Za-z0-9_]*(?:secret|password|passwd|api[_-]?key|apikey|token|auth|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_]*)\b(\s*[:=]\s*)(['"`]?)([^'"`\n]{4,})\3/gi;

/** Values that look like code or obvious placeholders — not real secrets. */
const BENIGN_VALUE_RE =
  /^(?:require|process|import|await|new\s|function|async|null|undefined|true|false|\$\{|=>|demo|test|example|sample|changeme|placeholder|your[-_]|xxx|foo|bar)|^[A-Za-z_$][\w.$]*\s*\(/i;

/**
 * Detection-only assignment pattern (used for FINDINGS, not redaction). Stricter
 * than ASSIGNMENT_RE: drops the over-broad bare `auth` (which matched `author`,
 * `authMode`, …) and requires a 6+ char value, to cut false-positive "secret".
 */
const DETECT_ASSIGNMENT_RE =
  /\b([A-Za-z0-9_]*(?:secret|password|passwd|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|credential|token)[A-Za-z0-9_]*)\b\s*[:=]\s*(['"`]?)([^'"`\n]{6,})\2/gi;

/**
 * Values that are clearly NOT real secrets: config words, log levels, URLs,
 * numbers, env-var references, placeholders. Broader than BENIGN_VALUE_RE
 * because detection should err toward fewer false alarms (redaction still errs
 * toward over-hiding via BENIGN_VALUE_RE — the two have opposite goals).
 */
const DETECT_BENIGN_VALUE_RE =
  /^(?:true|false|null|undefined|none|default|enabled?|disabled?|on|off|yes|no|development|production|staging|local(?:host)?|debug|info|warn(?:ing)?|error|trace|verbose|\d[\d._-]*|https?:\/\/|\$\{|\$[A-Za-z_]|%\(|process\.env|import\.meta|os\.environ|getenv|your[-_]|change[-_]?me|placeholder|example|sample|test|demo|dummy|x{3,}|\*{3,}|<[^>]+>)/i;

const MAX_LINE = 4000;
const PLACEHOLDER = '«REDACTED»';

/** Redact a single string. Safe to call on any text before output. */
export function redact(input: string): string {
  if (!input) return input;
  return input
    .split('\n')
    .map((line) => redactLine(line.length > MAX_LINE ? line.slice(0, MAX_LINE) : line))
    .join('\n');
}

function redactLine(line: string): string {
  let out = line;
  for (const { re } of TOKEN_PATTERNS) {
    out = out.replace(re, PLACEHOLDER);
  }
  out = out.replace(
    ASSIGNMENT_RE,
    (match: string, key: string, sep: string, quote: string, value: string) => {
      // Skip code expressions and obvious placeholders to keep noise low.
      if (BENIGN_VALUE_RE.test(value.trim())) return match;
      return `${key}${sep}${quote}${PLACEHOLDER}${quote}`;
    },
  );
  return out;
}

/** Deep-redact every string value in an arbitrary JSON-able object. */
export function redactObject<T>(value: T): T {
  if (typeof value === 'string') return redact(value) as unknown as T;
  if (Array.isArray(value)) return value.map((v) => redactObject(v)) as unknown as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      // Drop obviously secret-named keys entirely rather than risk partial leaks.
      if (/(secret|password|passwd|api[_-]?key|apikey|token|credential)/i.test(k)) {
        out[k] = PLACEHOLDER;
      } else {
        out[k] = redactObject(v);
      }
    }
    return out as T;
  }
  return value;
}

/** True if the text contains anything that looks like a live secret. */
export function containsSecret(input: string): boolean {
  return redact(input) !== input;
}

export type SecretConfidence = 'high' | 'low';

/**
 * Confidence-tiered secret DETECTION for findings (distinct from `redact`, which
 * is the safety primitive and stays aggressive). Returns:
 *   - 'high'  → matched a known secret/key SHAPE (AKIA…, sk-ant-…, JWT, …): a
 *              real credential with very high confidence.
 *   - 'low'   → a secret-NAMED variable assigned a non-benign literal: likely,
 *              but could be a placeholder/config value (so we flag it as a
 *              warning, not a critical).
 *   - null    → nothing secret-like.
 * Scans every line so it works on both single source lines and response bodies.
 */
export function detectSecret(input: string): SecretConfidence | null {
  if (!input) return null;
  let low = false;
  for (const raw of input.split('\n')) {
    const line = raw.length > MAX_LINE ? raw.slice(0, MAX_LINE) : raw;
    for (const { re } of TOKEN_PATTERNS) {
      re.lastIndex = 0;
      if (re.test(line)) return 'high';
    }
    DETECT_ASSIGNMENT_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DETECT_ASSIGNMENT_RE.exec(line)) !== null) {
      const value = (m[3] ?? '').trim();
      if (value.length >= 6 && !DETECT_BENIGN_VALUE_RE.test(value)) low = true;
    }
  }
  return low ? 'low' : null;
}

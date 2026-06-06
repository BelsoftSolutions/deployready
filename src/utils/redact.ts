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

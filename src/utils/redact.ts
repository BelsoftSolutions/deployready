/**
 * Central secret redaction. Anything that gets logged, exported, or sent to an
 * AI model MUST pass through here first. This is the single most important
 * safety primitive in the tool — research shows AI-assisted code leaks secrets
 * at ~2x baseline, and our own tool reads that code, so we never echo it back.
 *
 * Redaction is CONSERVATIVE: it masks every value the span finder (src/secrets)
 * locates — known key shapes, private-key blocks (multi-line), credentials in
 * URLs / query strings / HTTP headers, and secret-named key-value pairs in code,
 * JSON, YAML, TOML and .env — unless the WHOLE value is a clear placeholder
 * (`changeme`, `<token>`, `${VAR}`, …). Detection (confidence-tiered findings)
 * lives in src/secrets/detect and is deliberately stricter.
 *
 * Patterns are bounded with no nested quantifiers (ReDoS-safe). Line count is
 * always preserved so numbered output still lines up.
 */
import { detectSecretConfidence } from '../secrets/detect';
import { redactBlocks, redactOrphanBody } from '../secrets/multiline';
import { isPlaceholder, isSecretKey } from '../secrets/placeholder';
import { scanLine, shouldRedact } from '../secrets/scan';

export const PLACEHOLDER = '«REDACTED»';
/** Lines longer than this are cut (with a marker) before scanning, bounding regex work. */
const MAX_LINE = 100_000;

/** Redact a single string. Safe to call on any text before output. Idempotent. */
export function redact(input: string): string {
  if (!input) return input;
  const text = redactBlocks(input, PLACEHOLDER);
  return text
    .split('\n')
    .map((line) => redactLine(line.length > MAX_LINE ? `${line.slice(0, MAX_LINE)} «line truncated»` : line))
    .join('\n');
}

function redactLine(line: string): string {
  const spans = scanLine(line)
    .filter(shouldRedact)
    .sort((a, b) => a.start - b.start || b.end - a.end);
  let out = '';
  let pos = 0;
  for (const s of spans) {
    if (s.end <= pos) continue; // fully inside an already-masked span
    const start = Math.max(s.start, pos);
    out += line.slice(pos, start) + (start === s.start ? PLACEHOLDER : '');
    pos = s.end;
  }
  out += line.slice(pos);
  return redactOrphanBody(out, PLACEHOLDER);
}

/**
 * Deep-redact every string value in an arbitrary JSON-able object, and drop
 * secret-named keys entirely rather than risk partial leaks (AI payloads).
 */
export function redactObject<T>(value: T): T {
  if (typeof value === 'string') return redact(value) as unknown as T;
  if (Array.isArray(value)) return value.map((v) => redactObject(v)) as unknown as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
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

/**
 * Output sanitizer for structured results (JSON report, MCP responses, logger objects):
 * redacts every string, and masks string values under secret-named keys unless they are
 * placeholders. Unlike redactObject it keeps the shape (no key is dropped). Errors become
 * their redacted message.
 */
export function redactDeep<T>(value: T, seen: WeakSet<object> = new WeakSet()): T {
  if (typeof value === 'string') return redact(value) as unknown as T;
  if (value instanceof Error) return redact(value.message) as unknown as T;
  if (Array.isArray(value)) {
    if (seen.has(value)) return value;
    seen.add(value);
    return value.map((v) => redactDeep(v, seen)) as unknown as T;
  }
  if (value && typeof value === 'object') {
    if (seen.has(value as object)) return value;
    seen.add(value as object);
    if (value instanceof Date || Buffer.isBuffer(value)) return value;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === 'string' && isSecretKey(k) && !isPlaceholder(v)) out[k] = PLACEHOLDER;
      else out[k] = redactDeep(v, seen);
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
 *   - 'high'  → matched a known secret/key SHAPE (AKIA…, sk-ant-…, github_pat_…,
 *              sb_secret_…, service_role JWT, private key, DB URL credentials, …).
 *   - 'low'   → a secret-NAMED key assigned a non-placeholder literal, a credential
 *              in a URL query / HTTP header: likely, but could be config.
 *   - null    → nothing secret-like. Public keys (sb_publishable_…, pk_live_…,
 *              Supabase anon JWT) are not secrets.
 * Scans every line so it works on both single source lines and response bodies.
 */
export function detectSecret(input: string): SecretConfidence | null {
  if (!input) return null;
  return detectSecretConfidence(input);
}

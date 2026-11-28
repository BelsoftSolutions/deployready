/**
 * Secret span finder: the single source of truth for WHERE secret-like values sit in a
 * line of text. Detection (confidence-tiered findings) and redaction (conservative
 * masking) both build on these spans but apply opposite filters:
 *   - redaction masks every candidate whose value is not a clear placeholder;
 *   - detection reports only spans that survive stricter, confidence-based checks.
 */
import { DETECTORS, type Confidence } from './detectors';
import { entropy, isBenignConfigValue, isCodeLike, isPasswordKey, isPlaceholder, isSecretKey } from './placeholder';

export type SpanKind = 'shape' | 'url-credentials' | 'query' | 'header' | 'kv';

export interface SecretSpan {
  /** Detector id (e.g. `github-fine-grained-pat`, `kv-secret-named`). */
  id: string;
  kind: SpanKind;
  /** Offsets of the sensitive value within the line. */
  start: number;
  end: number;
  value: string;
  confidence: Confidence;
  /** False for public identifiers (publishable keys, anon JWTs). */
  secret: boolean;
  /** For kv spans: the key and whether the value was a quoted literal. */
  key?: string;
  quoted?: boolean;
  /** For kv spans: the line looks like .env / YAML / INI rather than code. */
  configLine?: boolean;
}

/** Scheme://user:password@host — DB, queue, cache and generic URLs. */
const URL_CRED_RE = /\b([a-z][a-z0-9+.-]{1,30}):\/\/([^\s:@/'"`<>]{0,200}):([^\s@/'"`<>]{1,200})@/gi;
/** Scheme://token@host (token as username, e.g. https://ghp_x@github.com). */
const URL_USER_TOKEN_RE = /\bhttps?:\/\/([A-Za-z0-9_-]{20,200})@/g;
const DB_SCHEMES = /^(?:postgres(?:ql)?|mysql|mariadb|mssql|sqlserver|mongodb(?:\+srv)?|redis|rediss|amqps?|kafka|nats|ldaps?|ftp|sftp|smtps?|jdbc|cockroachdb|clickhouse|neo4j|bolt|couchbase|cassandra)$/i;

/** Credentials in a URL query string. */
const QUERY_RE =
  /[?&;](access_token|refresh_token|id_token|auth_token|token|api_key|apikey|api-key|key|password|passwd|pwd|secret|client_secret|sig|signature|x-amz-signature|x-amz-security-token|x-goog-signature|session|sessionid|auth)=([^&#\s'"`<>]{1,2000})/gi;

/** HTTP header lines (raw HTTP, curl -H, logs). */
const HEADER_RE =
  /(?:^|-H\s*['"]?|[\s'"{,])(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-API-KEY|Api-Key|X-Auth-Token|X-Access-Token|X-Amz-Security-Token|apikey)\s*:\s*([^\r\n'"]{1,4000})/gi;

/**
 * key <sep> value pairs: JS/TS/Python assignments and object literals, JSON (`"k":"v"`),
 * YAML (`k: v`), TOML/INI (`k = "v"`), .env (`K=v`), Go (`k := "v"`), Ruby (`k => "v"`).
 * Group 1: optional key quote, 2: key, 3: separator, 4: value quote, 5: quoted value, 6: bare value.
 */
const KV_RE =
  /(["'`]?)([A-Za-z_$@][\w$.@-]{0,80})\1\]?(\s*(?::\s*[A-Za-z_][\w.<>[\]|]{0,40}\s*(?==))?(?::=|=>|:|=(?![=>~]))\s*)(?:(["'`])((?:\\.|(?!\4)[^\\\n]){0,4000})\4|(\$\{\{?[^}\n]{0,200}\}\}?|[^\s'"`,;)}\]]{1,4000}))/g;

const URL_VALUE_RE = /^(?:[a-z][a-z0-9+.-]{1,30}:)?\/\//i;
const ENV_LINE_RE = /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/;
const YAML_LINE_RE = /^\s*(?:-\s+)?["']?[\w.-]+["']?\s*:\s+[^\s,;{}()]+\s*(?:#.*)?$/;

function pushShape(line: string, out: SecretSpan[]): void {
  for (const d of DETECTORS) {
    d.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = d.re.exec(line)) !== null) {
      if (m[0].length === 0) {
        d.re.lastIndex++;
        continue;
      }
      const verdict = d.validate ? d.validate(m) : { confidence: d.confidence, secret: d.secret !== false };
      if (!verdict) continue;
      const value = d.group ? (m[d.group] ?? '') : m[0];
      const start = d.group ? m.index + m[0].lastIndexOf(value) : m.index;
      out.push({
        id: verdict.id ?? d.id,
        kind: 'shape',
        start,
        end: start + value.length,
        value,
        confidence: verdict.confidence,
        secret: verdict.secret,
      });
    }
  }
}

function pushUrlCredentials(line: string, out: SecretSpan[]): void {
  URL_CRED_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = URL_CRED_RE.exec(line)) !== null) {
    const scheme = m[1] ?? '';
    const pass = m[3] ?? '';
    const start = m.index + m[0].length - 1 - pass.length;
    out.push({
      id: DB_SCHEMES.test(scheme) ? 'connection-string-credentials' : 'url-credentials',
      kind: 'url-credentials',
      start,
      end: start + pass.length,
      value: pass,
      confidence: 'high',
      secret: true,
    });
  }
  URL_USER_TOKEN_RE.lastIndex = 0;
  while ((m = URL_USER_TOKEN_RE.exec(line)) !== null) {
    const tok = m[1] ?? '';
    if (entropy(tok) < 3.5) continue;
    const start = m.index + m[0].length - 1 - tok.length;
    out.push({ id: 'url-token', kind: 'url-credentials', start, end: start + tok.length, value: tok, confidence: 'low', secret: true });
  }
}

function pushQuery(line: string, out: SecretSpan[]): void {
  QUERY_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = QUERY_RE.exec(line)) !== null) {
    const value = m[2] ?? '';
    const start = m.index + m[0].length - value.length;
    out.push({ id: 'url-query-credential', kind: 'query', start, end: start + value.length, value, confidence: 'low', secret: true, key: m[1] });
  }
}

function pushHeaders(line: string, out: SecretSpan[]): void {
  HEADER_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HEADER_RE.exec(line)) !== null) {
    const name = (m[1] ?? '').toLowerCase();
    let value = (m[2] ?? '').replace(/[\s`,})\]]+$/, '');
    let offset = m.index + m[0].length - (m[2] ?? '').length;
    if (name === 'authorization' || name === 'proxy-authorization') {
      const scheme = /^(?:Bearer|Basic|Token|Digest|Bot|ApiKey|Api-Key|SSWS|AWS4-HMAC-SHA256|Negotiate|NTLM)\s+/i.exec(value);
      if (scheme) {
        offset += scheme[0].length;
        value = value.slice(scheme[0].length);
      }
    } else if (name === 'set-cookie') {
      const eq = value.indexOf('=');
      const semi = value.indexOf(';');
      if (eq > 0) {
        offset += eq + 1;
        value = value.slice(eq + 1, semi > eq ? semi - eq - 1 : undefined);
      }
    }
    value = value.trim();
    if (!value || /^\$\{|^['"`]?\s*\+|\$\{/.test(value)) continue;
    const start = line.indexOf(value, offset);
    if (start < 0) continue;
    out.push({ id: `http-${name}-header`, kind: 'header', start, end: start + value.length, value, confidence: 'low', secret: true, key: m[1] });
  }
}

function pushKv(line: string, out: SecretSpan[]): void {
  const configLine = ENV_LINE_RE.test(line) || YAML_LINE_RE.test(line);
  KV_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = KV_RE.exec(line)) !== null) {
    const key = m[2] ?? '';
    if (!isSecretKey(key)) {
      // Re-scan from just after the key so a secret pair later on the line is still seen.
      KV_RE.lastIndex = m.index + Math.max(1, (m[1] ?? '').length + key.length);
      continue;
    }
    const quoted = m[5] !== undefined;
    const value = quoted ? (m[5] ?? '') : (m[6] ?? '');
    const start = m.index + m[0].length - value.length - (quoted ? 1 : 0);
    out.push({
      id: 'kv-secret-named',
      kind: 'kv',
      start,
      end: start + value.length,
      value,
      confidence: 'low',
      secret: true,
      key,
      quoted,
      configLine,
    });
  }
}

/** Every candidate secret span on one line (unfiltered; callers apply their own policy). */
export function scanLine(line: string): SecretSpan[] {
  const out: SecretSpan[] = [];
  if (!line) return out;
  pushShape(line, out);
  pushUrlCredentials(line, out);
  pushQuery(line, out);
  pushHeaders(line, out);
  pushKv(line, out);
  return out;
}

/** Redaction policy for one span: mask unless the value is clearly not a secret literal. */
export function shouldRedact(s: SecretSpan): boolean {
  const v = s.value.trim();
  if (isPlaceholder(v)) return false;
  if (s.kind === 'shape') return true;
  if (s.kind === 'url-credentials' || s.kind === 'query' || s.kind === 'header') return true;
  // kv. A URL value is judged by the URL-credentials detector, not masked wholesale.
  if (URL_VALUE_RE.test(v)) return false;
  if (s.quoted) {
    if (v.includes('${')) return false; // template literal with interpolation: not a literal
    if (/^\d{1,5}$/.test(v)) return false;
    if (isPasswordKey(s.key ?? '')) return true;
    // Non-password keys (token*, *_key, cookie, …) holding a single plain word are config, not secrets.
    return !/^[A-Za-z][a-zA-Z]{0,24}$/.test(v);
  }
  if (isCodeLike(v)) return false;
  if (/^\d{1,5}$/.test(v)) return false;
  if (s.configLine) return true;
  // Bare identifiers in code (`password: hashed`) are variables; mask only literal-looking values.
  return /[^A-Za-z_$]/.test(v) || v.length >= 24;
}

/** Detection policy for one span: confidence-based, tuned toward few false alarms. */
export function detectionConfidence(s: SecretSpan): Confidence | null {
  if (!s.secret) return null;
  const v = s.value.trim();
  if (isPlaceholder(v)) return null;
  switch (s.kind) {
    case 'shape':
      return s.confidence;
    case 'url-credentials':
      if (s.id === 'url-token') return 'low';
      return s.id === 'connection-string-credentials' ? 'high' : 'low';
    case 'query':
      return v.length >= 16 && entropy(v) >= 3.5 ? 'low' : null;
    case 'header':
      return v.length >= 8 ? 'low' : null;
    case 'kv': {
      if (v.length < 6 || isBenignConfigValue(v)) return null;
      if (!s.quoted && !s.configLine) return null;
      if (!s.quoted && isCodeLike(v)) return null;
      if (v.includes('${') || URL_VALUE_RE.test(v)) return null;
      return 'low';
    }
  }
}

/** High-entropy literal (generic token) — used to label kv hits. */
export function isHighEntropyToken(v: string): boolean {
  return v.length >= 20 && /^[A-Za-z0-9+/=_.-]+$/.test(v) && entropy(v) >= 3.5;
}

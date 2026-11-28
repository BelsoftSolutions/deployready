/**
 * Verdict engine for an active authorization probe (0.5 semantic verification).
 *
 * Pure: given the tampered request's response and the baselines it can be
 * compared with, decide whether access control held. Whole-response equality is
 * NOT used as the proof any more; it was fooled by changing metadata, missed
 * partial disclosures, trusted status codes, and flagged harmless id echoes.
 *
 * The comparison is semantic and field-level:
 *   - bodies are parsed as JSON and flattened into (path, value) leaves; nested
 *     objects are walked and arrays are compared order-insensitively;
 *   - volatile fields are ignored: paths whose value changes between two
 *     baseline requests of the same identity (learned from >= 2 owner baselines
 *     and >= 2 own baselines), well-known volatile names (requestId, nonce,
 *     timestamp, ...), and any configured `ignoredFields`;
 *   - owner markers are the owner's stable values that never appear in the test
 *     user's own copy (an email, an amount, a name, ...). Disclosure means
 *     markers show up in the tampered response, whatever its status code: a
 *     401/403/404 body is inspected like any other;
 *   - an echo of the requested id alone is not disclosure;
 *   - keys are classified as sensitive by name (email, amount, address, ...).
 *
 * Verdicts:
 *   confirmed-vulnerable  the owner's private data came back (field-level proof)
 *   suspected             something owner-like came back, but too little to prove it
 *   verified-denied       the owner can read it, the test user got none of it
 *   inconclusive          neither proven safe nor proven vulnerable
 *   untested              the check could not run (decided by the runner)
 *   intentionally-public  declared public, or anyone (even anonymous) gets the
 *                         same non-sensitive data
 */
import { redact } from '../utils/redact';

export type AuthzVerdict =
  | 'confirmed-vulnerable'
  | 'suspected'
  | 'verified-denied'
  | 'inconclusive'
  | 'untested'
  | 'intentionally-public';

export interface ObservedResponse {
  status: number;
  bodyText: string;
}

export interface AuthzPolicy {
  /** Extra fields to ignore: a key name (`etag`) or a dotted path (`meta.generatedAt`). Case-insensitive. */
  ignoredFields?: readonly string[];
  /** The route was declared public in the config (`publicRoutes`). */
  declaredPublic?: boolean;
}

export interface AuthzInput {
  /** The tampered request (owner's id swapped in), sent as the test user. */
  tampered: ObservedResponse;
  /** The test user's own resource, fetched as the test user (>= 1; 2 lets volatile fields be learned). */
  ownBaselines: ObservedResponse[];
  /** The tampered resource fetched as its owner ($TOKEN_B) (>= 2 recommended). Empty when unavailable. */
  ownerBaselines: ObservedResponse[];
  /** The tampered resource fetched without credentials, when the runner sent that control. */
  anonymous?: ObservedResponse | null;
  /** The owner's id/tenant value that was swapped in. */
  foreignValue: string | number;
  /** The test user's own value at the same spot. */
  ownValue?: string | number;
  policy?: AuthzPolicy;
}

/** One owner value found in the tampered response. The raw value is never stored. */
export interface DisclosedField {
  /** Path of the field in the owner's own copy, e.g. `customer.email` or `items[].sku`. */
  path: string;
  sensitive: boolean;
  /** Masked + redacted value, safe for reports. */
  masked: string;
}

export interface AuthzResult {
  verdict: AuthzVerdict;
  /** What was observed and why that verdict. */
  reason: string;
  /** How the verdict was established (baselines compared, fields ignored, controls). */
  method: string;
  disclosed: DisclosedField[];
  /** Volatile/ignored field paths that were left out of the comparison. */
  ignored: string[];
  /** True when the tampered response was just the test user's own data (the swapped id was ignored). */
  ownData: boolean;
  /**
   * Raw owner values that matched. NEVER written to a report: the runner uses
   * them only to mask the proof body before it is redacted and stored.
   */
  matchedValues: string[];
  /** True when the decision would change with an anonymous control (runner sends one, then re-assesses). */
  wantsAnonymousControl: boolean;
  /** How many stable owner values (markers) the comparison could look for (0 = no owner data to compare). */
  markerCount: number;
}

// ---------------------------------------------------------------------------
// JSON flattening and comparison
// ---------------------------------------------------------------------------

type LeafKind = 'string' | 'number' | 'boolean' | 'null';

interface Leaf {
  /** Dotted path; array elements use `[]`, so element order does not matter. */
  path: string;
  /** Last key name on the path ('' for a root scalar). */
  key: string;
  value: string;
  kind: LeafKind;
}

function parseJson(text: string): unknown {
  const t = (text ?? '').trim();
  if (!t || !/^[[{"]/.test(t)) return undefined;
  try {
    return JSON.parse(t) as unknown;
  } catch {
    return undefined;
  }
}

function flatten(v: unknown, path = '', key = '', out: Leaf[] = []): Leaf[] {
  if (Array.isArray(v)) {
    for (const el of v) flatten(el, `${path}[]`, key, out);
  } else if (typeof v === 'object' && v !== null) {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) flatten(val, path ? `${path}.${k}` : k, k, out);
  } else {
    const kind: LeafKind = v === null ? 'null' : typeof v === 'number' ? 'number' : typeof v === 'boolean' ? 'boolean' : 'string';
    out.push({ path: path || '$', key, value: v === null ? 'null' : String(v), kind });
  }
  return out;
}

interface Parsed {
  json: boolean;
  leaves: Leaf[];
  text: string;
}

function parse(r: ObservedResponse): Parsed {
  const json = parseJson(r.bodyText);
  return json === undefined
    ? { json: false, leaves: [], text: (r.bodyText ?? '').trim() }
    : { json: true, leaves: flatten(json), text: (r.bodyText ?? '').trim() };
}

/** Names that are volatile by convention (a fresh value on every response). */
const VOLATILE_KEY_RE =
  /^(?:x[-_]?)?(?:request[-_]?id|req[-_]?id|trace[-_]?id|span[-_]?id|correlation[-_]?id|nonce|timestamp|ts|now|served[-_]?at|generated[-_]?at|server[-_]?time|response[-_]?time|duration(?:[-_]?ms)?|took|elapsed(?:[-_]?ms)?|etag|csrf(?:[-_]?token)?|xsrf(?:[-_]?token)?)$/i;

function multiset(leaves: Leaf[]): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const l of leaves) {
    const list = m.get(l.path) ?? [];
    list.push(`${l.kind}:${l.value}`);
    m.set(l.path, list);
  }
  for (const list of m.values()) list.sort();
  return m;
}

/** Paths whose values differ between responses of the same identity for the same resource. */
function learnVolatile(group: Parsed[], into: Set<string>): void {
  const json = group.filter((p) => p.json);
  for (let i = 1; i < json.length; i++) {
    const a = multiset(json[0]!.leaves);
    const b = multiset(json[i]!.leaves);
    for (const path of new Set([...a.keys(), ...b.keys()])) {
      if ((a.get(path) ?? []).join('\u0000') !== (b.get(path) ?? []).join('\u0000')) into.add(path);
    }
  }
}

function makeIgnore(volatile: Set<string>, configured: readonly string[]): (l: Leaf) => boolean {
  const cfg = configured.map((c) => c.trim().toLowerCase()).filter(Boolean);
  return (l) => {
    if (volatile.has(l.path) || VOLATILE_KEY_RE.test(l.key)) return true;
    if (cfg.length === 0) return false;
    const key = l.key.toLowerCase();
    const path = l.path.replace(/\[\]/g, '').toLowerCase();
    return cfg.some((c) => c === key || c === path || path.startsWith(`${c}.`));
  };
}

function signature(p: Parsed, ignore: (l: Leaf) => boolean): string {
  if (!p.json) return `text:${p.text}`;
  return p.leaves
    .filter((l) => !ignore(l))
    .map((l) => `${l.path}=${l.kind}:${l.value}`)
    .sort()
    .join('\u0000');
}

/** Equality of two response bodies: JSON deep-equal ignoring key order, else trimmed text. */
export function bodiesEqual(a: string, b: string): boolean {
  const pa = parse({ status: 200, bodyText: a });
  const pb = parse({ status: 200, bodyText: b });
  if (pa.json !== pb.json) return false;
  if (!pa.json) return pa.text === pb.text;
  return canonical(parseJson(a)) === canonical(parseJson(b));
}

function canonical(v: unknown): string {
  const sort = (x: unknown): unknown =>
    Array.isArray(x)
      ? x.map(sort)
      : typeof x === 'object' && x !== null
        ? Object.fromEntries(
            Object.entries(x as Record<string, unknown>)
              .sort(([k1], [k2]) => (k1 < k2 ? -1 : k1 > k2 ? 1 : 0))
              .map(([k, val]) => [k, sort(val)]),
          )
        : x;
  return JSON.stringify(sort(v));
}

/**
 * Semantic equality: JSON leaves compared as a multiset (key order and array
 * order do not matter), with volatile/configured fields left out.
 */
export function semanticEqual(a: string, b: string, ignoredFields: readonly string[] = []): boolean {
  const ignore = makeIgnore(new Set(), ignoredFields);
  return signature(parse({ status: 200, bodyText: a }), ignore) === signature(parse({ status: 200, bodyText: b }), ignore);
}

// ---------------------------------------------------------------------------
// Sensitivity, masking, markers
// ---------------------------------------------------------------------------

const SENSITIVE_WORDS = new Set([
  'email', 'mail', 'amount', 'total', 'subtotal', 'balance', 'price', 'cost', 'salary', 'income', 'address', 'street',
  'phone', 'mobile', 'tel', 'ssn', 'iban', 'bic', 'card', 'pan', 'cvv', 'cvc', 'token', 'secret', 'password', 'passwd',
  'apikey', 'message', 'messages', 'note', 'notes', 'comment', 'comments', 'dob', 'birthday', 'birthdate', 'passport',
  'diagnosis', 'surname', 'contact', 'zip', 'postcode', 'postal',
]);
const SENSITIVE_PHRASE_RE =
  /(?:first_?name|last_?name|full_?name|given_?name|family_?name|date_?of_?birth|tax_?id|vat_?id|account_?(?:number|no)|api_?key|social_?security|credit_?card|bank_?account|private)/i;
/** Words that turn a "total"/"amount"-like key into pagination metadata. */
const COUNTER_WORDS = new Set(['count', 'page', 'pages', 'results', 'size', 'limit', 'offset']);

function keyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** True when a key name suggests personal, financial, or secret data. */
export function isSensitiveKey(key: string): boolean {
  if (!key) return false;
  const words = keyWords(key);
  if (words.some((w) => COUNTER_WORDS.has(w))) return false;
  return words.some((w) => SENSITIVE_WORDS.has(w)) || SENSITIVE_PHRASE_RE.test(words.join('_'));
}

/** Mask a value for a report (it still passes through `redact()`). Never returns the raw value. */
export function maskValue(value: string, kind: LeafKind | 'text' = 'string'): string {
  let out: string;
  if (kind === 'number') {
    out = value.replace(/\d/g, (d, i: number) => (i === 0 ? d : '•'));
  } else {
    const email = /^([^@\s])[^@\s]*@([^@.\s])[^@\s]*?(\.[A-Za-z]{2,})$/.exec(value);
    if (email) out = `${email[1]}***@${email[2]}***${email[3]}`;
    else if (value.length <= 4) out = '****';
    else out = `${value.slice(0, 2)}… (${value.length} chars)`;
  }
  return redact(out);
}

interface Marker {
  path: string;
  key: string;
  value: string;
  kind: LeafKind | 'text';
  sensitive: boolean;
}

const LINK_KEY_RE = /(?:url|href|link|self|path|uri)$/i;
/** Keys whose (non-marker) values are generic protocol chatter, never data. */
const HARMLESS_KEYS = new Set([
  'error', 'errors', 'message', 'msg', 'detail', 'details', 'status', 'code', 'ok', 'success', 'reason', 'requested',
  'id', 'type', 'title',
]);

function distinctive(value: string, kind: LeafKind | 'text', sensitive: boolean): boolean {
  if (kind === 'boolean' || kind === 'null') return false;
  if (kind === 'number') {
    const n = Number(value);
    return sensitive || !Number.isInteger(n) || Math.abs(n) >= 100;
  }
  const v = value.trim();
  return v.length >= (sensitive ? 2 : 3);
}

function textTokens(text: string): string[] {
  return text.split(/[\s<>"'(),;{}[\]=]+/).filter((t) => t.length >= 4);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Does `marker` appear in the tampered response? Values, then substrings of string values. */
function present(marker: Marker, t: Parsed, ignore: (l: Leaf) => boolean): boolean {
  if (t.json) {
    return t.leaves.some(
      (l) =>
        !ignore(l) &&
        (l.value === marker.value || (l.kind === 'string' && marker.kind !== 'number' && marker.value.length >= 4 && l.value.includes(marker.value))),
    );
  }
  if (!t.text) return false;
  return new RegExp(`(?:^|[^A-Za-z0-9])${escapeRe(marker.value)}(?:$|[^A-Za-z0-9])`).test(t.text);
}

function is2xx(s: number): boolean {
  return s >= 200 && s < 300;
}

function isRefusal(s: number): boolean {
  return s >= 400 && s < 500;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

function describeFields(fields: DisclosedField[]): string {
  return fields.map((f) => `${f.path}${f.sensitive ? ' (sensitive)' : ''} = ${f.masked}`).join(', ');
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

export function assessAuthz(input: AuthzInput): AuthzResult {
  const { tampered, foreignValue } = input;
  const configured = input.policy?.ignoredFields ?? [];
  const foreign = String(foreignValue);
  const own = input.ownValue === undefined ? undefined : String(input.ownValue);

  const ownP = input.ownBaselines.filter((r) => is2xx(r.status)).map(parse);
  const ownerP = input.ownerBaselines.filter((r) => is2xx(r.status)).map(parse);
  const t = parse(tampered);

  // Volatile fields: learned from repeated baselines of the same identity.
  const volatile = new Set<string>();
  learnVolatile(ownerP, volatile);
  learnVolatile(ownP, volatile);
  const ignore = makeIgnore(volatile, configured);
  const ignored = [
    ...new Set(
      [...ownerP, ...ownP, t]
        .flatMap((p) => p.leaves)
        .filter((l) => ignore(l))
        .map((l) => l.path),
    ),
  ].sort();

  const ownValues = new Set<string>();
  for (const p of ownP) {
    for (const l of p.leaves) ownValues.add(l.value);
    if (!p.json) for (const tok of textTokens(p.text)) ownValues.add(tok);
  }
  const ownSig = ownP[0] ? signature(ownP[0], ignore) : undefined;
  const ownData = is2xx(tampered.status) && ownSig !== undefined && signature(t, ignore) === ownSig;

  const method = [
    `Compared field by field against ${plural(ownerP.length, 'owner baseline')} ($TOKEN_B) and ${plural(ownP.length, 'own baseline')} ($TOKEN)`,
    ignored.length ? `ignored volatile/configured fields: ${ignored.join(', ')}` : 'no volatile fields detected',
    input.anonymous ? `anonymous control (no credentials): HTTP ${input.anonymous.status}` : '',
  ]
    .filter(Boolean)
    .join('; ');

  let markerCount = 0;
  const result = (
    verdict: AuthzVerdict,
    reason: string,
    extra: Partial<Pick<AuthzResult, 'disclosed' | 'matchedValues' | 'wantsAnonymousControl'>> = {},
  ): AuthzResult => ({
    markerCount,
    verdict,
    reason,
    method: `${method}.`,
    disclosed: extra.disclosed ?? [],
    ignored,
    ownData,
    matchedValues: extra.matchedValues ?? [],
    wantsAnonymousControl: extra.wantsAnonymousControl ?? false,
  });

  if (input.policy?.declaredPublic) {
    return result('intentionally-public', 'The route is declared public in the config (publicRoutes), so cross-identity reads are expected.');
  }

  // Not an echo of the requested id, and not something the test user already has.
  const isEcho = (value: string) => value === foreign;
  const isTemplated = (key: string, value: string) =>
    own !== undefined && LINK_KEY_RE.test(key) && value.includes(foreign) && ownValues.has(value.split(foreign).join(own));

  // ---- No working owner baseline: field-level proof is impossible. ----
  if (ownerP.length === 0) {
    const ownerNote = input.ownerBaselines.length
      ? `the owner's own request ($TOKEN_B) failed (HTTP ${input.ownerBaselines.map((r) => r.status).join('/')})`
      : 'no owner request ($TOKEN_B) was available';
    if (!is2xx(tampered.status)) {
      return result('inconclusive', `HTTP ${tampered.status} for the test user, but ${ownerNote}, so a refusal proves nothing (the resource may not exist).`);
    }
    if (ownData) {
      return result('verified-denied', `HTTP ${tampered.status} returned only the test user's own data: the swapped id was ignored (${ownerNote}).`);
    }
    const suspicious: DisclosedField[] = [];
    const values: string[] = [];
    for (const l of t.leaves) {
      if (ignore(l) || isEcho(l.value) || ownValues.has(l.value) || !isSensitiveKey(l.key)) continue;
      if (!distinctive(l.value, l.kind, true)) continue;
      suspicious.push({ path: l.path, sensitive: true, masked: maskValue(l.value, l.kind) });
      values.push(l.value);
    }
    if (suspicious.length) {
      return result(
        'suspected',
        `HTTP ${tampered.status} returned sensitive-looking fields that are not in the test user's own data (${describeFields(suspicious)}), but ${ownerNote}, so they cannot be proven to be the owner's.`,
        { disclosed: suspicious, matchedValues: values, wantsAnonymousControl: true },
      );
    }
    return result(
      'inconclusive',
      `HTTP ${tampered.status} returned no sensitive data that is new to the test user${t.leaves.some((l) => isEcho(l.value)) ? ' (it only echoes the requested id, which is not disclosure)' : ''}, and ${ownerNote}.`,
    );
  }

  // ---- Owner markers: stable owner values the test user never sees in its own data. ----
  const markers: Marker[] = [];
  const seenMarker = new Set<string>();
  const owner0 = ownerP[0]!;
  if (owner0.json) {
    const stableIn = ownerP.slice(1).map((p) => new Set(p.leaves.map((l) => `${l.path}=${l.value}`)));
    for (const l of owner0.leaves) {
      if (ignore(l) || isEcho(l.value) || ownValues.has(l.value) || isTemplated(l.key, l.value)) continue;
      if (!stableIn.every((s) => s.has(`${l.path}=${l.value}`))) continue;
      const sensitive = isSensitiveKey(l.key);
      if (!distinctive(l.value, l.kind, sensitive)) continue;
      const k = `${l.path}=${l.value}`;
      if (seenMarker.has(k)) continue;
      seenMarker.add(k);
      markers.push({ path: l.path, key: l.key, value: l.value, kind: l.kind, sensitive });
    }
  } else {
    const stable = ownerP.slice(1).map((p) => new Set(textTokens(p.text)));
    for (const tok of new Set(textTokens(owner0.text))) {
      if (isEcho(tok) || ownValues.has(tok) || !stable.every((s) => s.has(tok))) continue;
      markers.push({ path: '(text)', key: '', value: tok, kind: 'text', sensitive: /@/.test(tok) });
    }
  }

  markerCount = markers.length;
  const matched = markers.filter((m) => present(m, t, ignore));
  const disclosed: DisclosedField[] = matched.map((m) => ({ path: m.path, sensitive: m.sensitive, masked: maskValue(m.value, m.kind) }));
  const matchedValues = matched.map((m) => m.value);
  const fullMatch = is2xx(tampered.status) && signature(t, ignore) === signature(owner0, ignore);
  const sensitiveMatched = matched.filter((m) => m.sensitive);
  const statusNote = is2xx(tampered.status)
    ? ''
    : ` The status code (HTTP ${tampered.status}) claims a refusal, but the body still carries the data — status codes are not proof.`;

  let candidate: AuthzResult | null = null;
  if (matched.length > 0) {
    const strong =
      sensitiveMatched.length > 0 || matched.length >= 2 || (fullMatch && markers.length > 0) || (owner0.json === false && matched.length >= 3);
    candidate = result(
      strong ? 'confirmed-vulnerable' : 'suspected',
      `HTTP ${tampered.status} for the test user contained ${plural(matched.length, 'value')} that appear in the owner's own copy and never in the test user's: ${describeFields(disclosed)}.${
        fullMatch ? ' The response is the same record the owner receives.' : matched.length < markers.length ? ` Partial disclosure: ${matched.length} of the owner's ${markers.length} private values.` : ''
      }${statusNote}${strong ? '' : ' Only one non-sensitive value matched, which is not enough to prove it.'}`,
      { disclosed, matchedValues, wantsAnonymousControl: true },
    );
  } else if (fullMatch && ownSig !== undefined && signature(owner0, ignore) !== ownSig) {
    candidate = result(
      'suspected',
      `HTTP ${tampered.status} returned exactly what the owner receives, but that record has no value unique to the owner beyond its id, so disclosure of private data cannot be proven.`,
      { wantsAnonymousControl: true },
    );
  }

  if (candidate) {
    const anon = input.anonymous;
    if (anon && is2xx(anon.status)) {
      const a = parse(anon);
      const sameData = matched.length > 0 ? matched.every((m) => present(m, a, ignore)) : signature(a, ignore) === signature(owner0, ignore);
      if (sameData) {
        if (sensitiveMatched.length > 0) {
          return {
            ...candidate,
            verdict: 'confirmed-vulnerable',
            reason: `${candidate.reason} The same data is returned even WITHOUT credentials (HTTP ${anon.status}), so this record is not protected at all.`,
          };
        }
        return result(
          'intentionally-public',
          `Anyone, even without credentials, receives the same non-sensitive data (anonymous HTTP ${anon.status}), so this looks like a public resource, not a cross-identity leak. Add it to publicRoutes to record that, or protect it if it should be private.`,
          { disclosed, matchedValues },
        );
      }
    }
    return candidate;
  }

  // ---- Nothing of the owner's came back. ----
  if (isRefusal(tampered.status)) {
    return result(
      'verified-denied',
      `Refused with HTTP ${tampered.status}, the body carries none of the owner's ${plural(markers.length, 'private value')}, and the owner itself can read the resource (HTTP ${input.ownerBaselines.find((r) => is2xx(r.status))?.status}).`,
    );
  }
  if (is2xx(tampered.status) && ownData) {
    return result(
      'verified-denied',
      `HTTP ${tampered.status} returned only the test user's own data: the server ignored the swapped id (it derives the object from the session), so nothing of the owner's was disclosed.`,
    );
  }
  if (is2xx(tampered.status)) {
    const leftover = t.leaves.filter(
      (l) =>
        !ignore(l) &&
        !isEcho(l.value) &&
        !isTemplated(l.key, l.value) &&
        !ownValues.has(l.value) &&
        !HARMLESS_KEYS.has(l.key.toLowerCase()) &&
        l.kind !== 'boolean' &&
        l.kind !== 'null',
    );
    const echoes = t.leaves.some((l) => isEcho(l.value));
    if (t.json && leftover.length === 0 && markers.length > 0) {
      return result(
        'verified-denied',
        `HTTP ${tampered.status}, but none of the owner's ${plural(markers.length, 'private value')} appear in it${echoes ? '; it only echoes the requested id, which is not disclosure' : ''}.`,
      );
    }
    return result(
      'inconclusive',
      `HTTP ${tampered.status} returned data that is neither the owner's nor the test user's own${leftover.length ? ` (fields: ${[...new Set(leftover.map((l) => l.path))].join(', ')})` : ''} — verify manually.`,
    );
  }
  return result('inconclusive', `HTTP ${tampered.status} — neither a refusal nor data; the endpoint may have errored or redirected.`);
}

/**
 * Replace every matched owner value in a body with its masked form, so a proof
 * shows WHERE the owner's data appeared without storing it. The result is still
 * passed through `redact()` by the proof builder.
 */
export function maskBody(bodyText: string, matchedValues: readonly string[]): string {
  let out = bodyText ?? '';
  for (const v of [...matchedValues].sort((a, b) => b.length - a.length)) {
    if (v.length < 2) continue;
    out = out.split(v).join(maskValue(v, /^-?\d+(?:\.\d+)?$/.test(v) ? 'number' : 'string'));
  }
  return out;
}

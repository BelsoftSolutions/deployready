/**
 * Evidence rules C1-C5 for the opt-in common-path probe
 * (docs/COMMON-PATH-PROBE-DESIGN.md section 1.3). A status code alone is never a finding.
 */
import { createHash } from 'crypto';
import type { CommonPathOutcome, Severity } from '../../types';
import { redact } from '../../utils/redact';
import { capSeverity, looksLikeHtml } from './signatures';
import type { PathSignature } from './signatures';

export interface ProbeResponse {
  status: number;
  contentType: string;
  location: string;
  /** At most 256 KB; larger bodies are cut at the cap. */
  body: Buffer;
}

export interface ShapeFingerprint {
  status: number;
  length: number;
  hash: string;
  /** Sorted top-level JSON keys, or normalized HTML title plus first tag names; null for other content. */
  shape: string | null;
}

export interface Verdict {
  outcome: CommonPathOutcome;
  reason: string;
  severity?: Severity;
  /** Redacted; key names and counts only. */
  evidence?: string;
}

const MAX_SHAPE_TAGS = 30;
const LOGIN_REDIRECT = /log-?in|sign-?in|auth|sso/i;
const PASSWORD_INPUT = /<input\b[^>]*\btype\s*=\s*(?:"password"|'password'|password\b)/i;

function textOf(res: ProbeResponse): string {
  return res.body.toString('utf8');
}

function jsonShape(text: string): string | null {
  try {
    const v: unknown = JSON.parse(text);
    if (Array.isArray(v)) return 'json:[]';
    if (v && typeof v === 'object') return `json:{${Object.keys(v).sort().join(',')}}`;
    return 'json:scalar';
  } catch {
    return null;
  }
}

function htmlShape(text: string): string {
  const title = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(text)?.[1] ?? '';
  const normalizedTitle = title.replace(/\s+/g, ' ').trim().toLowerCase();
  const tags: string[] = [];
  for (const m of text.matchAll(/<([a-zA-Z][a-zA-Z0-9-]*)/g)) {
    tags.push((m[1] ?? '').toLowerCase());
    if (tags.length >= MAX_SHAPE_TAGS) break;
  }
  return `html:${normalizedTitle}|${tags.join(',')}`;
}

export function shapeOf(text: string, contentType: string): string | null {
  const trimmed = text.trimStart();
  if (/json/i.test(contentType) || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const s = jsonShape(text);
    if (s) return s;
  }
  if (looksLikeHtml(text, contentType)) return htmlShape(text);
  return null;
}

export function fingerprintResponse(res: ProbeResponse): ShapeFingerprint {
  return {
    status: res.status,
    length: res.body.length,
    hash: createHash('sha256').update(res.body).digest('hex'),
    shape: shapeOf(textOf(res), res.contentType),
  };
}

/** Rule C2: the answer is the same as the app's answer for a path that cannot exist. */
export function sameAsControl(control: ShapeFingerprint, fp: ShapeFingerprint): boolean {
  return fp.hash === control.hash || fp.length === control.length || (fp.shape !== null && fp.shape === control.shape);
}

/**
 * Apply C1-C5 in order to the response for one probed path. `control` is the
 * fingerprint of the random-path control when it returned 2xx, otherwise null.
 */
export function evaluate(sig: PathSignature, res: ProbeResponse, control: ShapeFingerprint | null): Verdict {
  // C1: status
  if (res.status >= 300 && res.status < 400) {
    return LOGIN_REDIRECT.test(res.location)
      ? { outcome: 'protected', reason: 'redirect to login: protected, not exposed' }
      : { outcome: 'protected', reason: 'redirect, not followed' };
  }
  if (res.status === 401 || res.status === 403) {
    return { outcome: 'protected', reason: `HTTP ${res.status}: protected, not exposed` };
  }
  if (res.status !== 200) {
    return { outcome: 'not-found', reason: `HTTP ${res.status}` };
  }

  const text = textOf(res);

  // C2: not a catch-all
  if (control && sameAsControl(control, fingerprintResponse(res))) {
    return {
      outcome: 'not-proven',
      reason: "same body/length/shape as the app's answer for a non-existent path: catch-all",
    };
  }

  // C3: not a login page
  if (PASSWORD_INPUT.test(text)) {
    return { outcome: 'not-proven', reason: 'login page' };
  }

  // C4: row signature
  if (sig.expected !== 'html' && sig.expected !== 'binary' && looksLikeHtml(text, res.contentType)) {
    return { outcome: 'not-proven', reason: 'HTML, not the expected content' };
  }
  const match = sig.match({ body: res.body, text, contentType: res.contentType });
  if (!match) {
    return { outcome: 'not-proven', reason: `${sig.proof} not present in the response` };
  }

  // C5: found, severity never above the row's ceiling
  return {
    outcome: 'found',
    reason: `matched ${sig.proof}`,
    severity: capSeverity(match.severity, sig.ceiling),
    evidence: redact(match.evidence),
  };
}

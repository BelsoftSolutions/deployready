/**
 * Builds the reproducible `Proof` attached to live (dynamic and active)
 * findings: a curl command for the request that triggered the finding, the
 * status it got, a truncated response, and the control that shows the endpoint
 * otherwise behaves.
 *
 * Safety: every string passes through `redact()` before it is stored, and
 * credentials are never written out at all: the curl command names them with
 * shell variables ($TOKEN for --token, $TOKEN_B for --token-b) so the user can
 * re-run it with their own token, and nothing secret lands in a report.
 */
import { redact } from '../utils/redact';
import type { Proof } from '../types';

/** Response bodies in a proof are cut to this many characters. */
export const PROOF_BODY_MAX = 500;

export interface ProofRequest {
  method: string;
  /** Absolute URL, or a path when the base URL is unknown. */
  url: string;
  /**
   * How the request authenticated, as shown in the curl command. A literal token
   * is never accepted here: pass a shell-variable placeholder such as "$TOKEN"
   * or a description such as "<alg:none copy of $TOKEN>".
   */
  auth?: string;
}

/** Single-quote a value for a POSIX shell. */
function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** A redacted, copy-pasteable curl command for a request. */
export function curlCommand(req: ProofRequest): string {
  const parts = ['curl', '-i'];
  if (req.method.toUpperCase() !== 'GET') parts.push('-X', req.method.toUpperCase());
  if (req.auth) parts.push('-H', `"Authorization: Bearer ${req.auth.replace(/"/g, '')}"`);
  parts.push(shellQuote(req.url));
  return redact(parts.join(' '));
}

/** Truncate then redact a response body. */
export function proofBody(text: string, max = PROOF_BODY_MAX): string {
  const trimmed = (text ?? '').trim();
  const cut = trimmed.length > max ? `${trimmed.slice(0, max)}… [truncated, ${trimmed.length} chars]` : trimmed;
  return redact(cut);
}

/** Stringify an HTTP client's response body (string, JSON, or other). */
export function bodyToText(data: unknown): string {
  if (typeof data === 'string') return data;
  try {
    return JSON.stringify(data) ?? '';
  } catch {
    return '';
  }
}

/** Join a base URL and a path; falls back to the path when the base is missing or invalid. */
export function absoluteUrl(baseUrl: string | undefined, path: string): string {
  if (!baseUrl) return path;
  try {
    return new URL(path, baseUrl).toString();
  } catch {
    return path;
  }
}

export interface ProofInput {
  request: ProofRequest;
  status?: number;
  /** Raw response body; truncated and redacted here. */
  response?: string;
  /** Plain-language control result; redacted here. */
  control?: string;
}

/** Build a `Proof` whose every string is redacted. */
export function buildProof(input: ProofInput): Proof {
  const proof: Proof = { request: curlCommand(input.request) };
  if (input.status !== undefined) proof.status = input.status;
  if (input.response !== undefined) proof.response = proofBody(input.response);
  if (input.control) proof.control = redact(input.control);
  return proof;
}

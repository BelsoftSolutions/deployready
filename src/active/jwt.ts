/**
 * JWT manipulation for active authorization testing (Phase 5b).
 *
 * Pure, no network. Produces the classic token-tamper variants we send to a
 * target (only ever behind explicit consent in the runner) to prove whether it
 * actually verifies tokens:
 *   - forgeNoneAlg        → header alg:"none", empty signature (CVE-class bypass)
 *   - tamperClaimsKeepSig → original header+signature, mutated claims (catches
 *                           apps that decode but never verify the signature)
 *
 * We never need a signing key: the whole point is to check the SERVER's behavior
 * on an unverifiable token.
 */
export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** The raw (untouched) signature segment. */
  signature: string;
}

function decodeSegment(seg: string): unknown {
  return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
}

function encodeSegment(obj: object): string {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Decode a JWT's header + payload. Returns null if it isn't a valid JWT shape. */
export function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = decodeSegment(parts[0]!);
    const payload = decodeSegment(parts[1]!);
    if (!isPlainObject(header) || !isPlainObject(payload)) return null;
    return { header, payload, signature: parts[2]! };
  } catch {
    return null;
  }
}

/** Forge an `alg:"none"` token (empty signature), optionally patching claims. */
export function forgeNoneAlg(token: string, claimPatch: Record<string, unknown> = {}): string | null {
  const d = decodeJwt(token);
  if (!d) return null;
  const header = { ...d.header, alg: 'none' };
  const payload = { ...d.payload, ...claimPatch };
  return `${encodeSegment(header)}.${encodeSegment(payload)}.`;
}

/** Mutate claims but keep the original header + signature unchanged. */
export function tamperClaimsKeepSig(token: string, patch: Record<string, unknown>): string | null {
  const d = decodeJwt(token);
  if (!d) return null;
  const payload = { ...d.payload, ...patch };
  return `${encodeSegment(d.header)}.${encodeSegment(payload)}.${d.signature}`;
}

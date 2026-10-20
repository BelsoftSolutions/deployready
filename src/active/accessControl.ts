/**
 * Verdict engine for an active authorization probe (Phase 5b).
 *
 * Pure: given a tampered request's response and the baselines it can be compared
 * with, decide whether access control held. The primary proof is the OWNER's
 * baseline — the same resource fetched as the identity that legitimately owns it:
 * if the test user, with the owner's id swapped in, receives exactly what the
 * owner receives, access control failed. The old "foreign id appears in the body"
 * check is kept only as a fallback when no owner baseline is available.
 */
export type AuthzVerdict = 'broken' | 'denied' | 'inconclusive';

export interface AuthzResult {
  verdict: AuthzVerdict;
  reason: string;
  /** How a 'broken' verdict was proven. */
  proof?: 'owner-baseline' | 'echo';
}

export interface AuthzInput {
  /** Tampered request, sent as the test user. */
  status: number;
  bodyText: string;
  /** The test user's own baseline body for the untampered request. */
  ownBaselineBody: string;
  /** The same resource fetched as its owner; null when unavailable. */
  ownerBaseline: { status: number; bodyText: string } | null;
  /** The owner's id/tenant value that was swapped in. */
  foreignValue: string | number;
}

function canonicalize(text: string): string {
  const trimmed = text.trim();
  try {
    return JSON.stringify(sortKeys(JSON.parse(trimmed)));
  } catch {
    return trimmed;
  }
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (typeof v === 'object' && v !== null) {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, val]) => [k, sortKeys(val)]),
    );
  }
  return v;
}

/** Equality of two response bodies: JSON deep-equal ignoring key order, else trimmed text. */
export function bodiesEqual(a: string, b: string): boolean {
  return canonicalize(a) === canonicalize(b);
}

/** Empty / `{}` / `[]` / `null` carry no data, so matching them proves nothing. */
function isTrivialBody(text: string): boolean {
  return ['', '{}', '[]', 'null', '""'].includes(canonicalize(text));
}

function is2xx(status: number): boolean {
  return status >= 200 && status < 300;
}

export function classifyAuthzResult(input: AuthzInput): AuthzResult {
  const { status, bodyText, ownBaselineBody, ownerBaseline, foreignValue } = input;

  if (status === 401 || status === 403) {
    return { verdict: 'denied', reason: `Access correctly denied (HTTP ${status}).` };
  }
  if (status === 404) {
    return { verdict: 'denied', reason: 'Resource not exposed to this identity (HTTP 404).' };
  }
  if (!is2xx(status)) {
    return { verdict: 'inconclusive', reason: `HTTP ${status} — inconclusive; the endpoint may have errored.` };
  }

  if (bodiesEqual(bodyText, ownBaselineBody)) {
    return {
      verdict: 'inconclusive',
      reason: `HTTP ${status} returned the test user's own data — the swapped value was ignored.`,
    };
  }

  if (ownerBaseline && is2xx(ownerBaseline.status)) {
    if (!isTrivialBody(bodyText) && bodiesEqual(bodyText, ownerBaseline.bodyText)) {
      return {
        verdict: 'broken',
        proof: 'owner-baseline',
        reason: `Tampered request returned HTTP ${status} with exactly what the owning identity receives — access control failed.`,
      };
    }
    return {
      verdict: 'inconclusive',
      reason: `HTTP ${status} returned, but it differs from what the owning identity receives — verify manually.`,
    };
  }

  if (bodyText.includes(String(foreignValue))) {
    return {
      verdict: 'broken',
      proof: 'echo',
      reason: `Tampered request returned HTTP ${status} containing the other identity's value — access control failed (no owner baseline to confirm).`,
    };
  }
  return {
    verdict: 'inconclusive',
    reason: `HTTP ${status} returned, but no clear foreign data in the response — verify manually.`,
  };
}

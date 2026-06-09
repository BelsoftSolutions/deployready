/**
 * Verdict engine for an active authorization probe (Phase 5b).
 *
 * Pure: given the outcome of a tampered request (the HTTP status, and whether
 * the response clearly contained another identity's data), decide whether
 * access control held. The runner computes `gotForeignData` (e.g. the swapped
 * id / a known victim marker appears in the body) and feeds it here.
 */
export type AuthzVerdict = 'broken' | 'denied' | 'inconclusive';

export interface AuthzResult {
  verdict: AuthzVerdict;
  reason: string;
}

export function classifyAuthzResult(input: { status: number; gotForeignData: boolean }): AuthzResult {
  const { status, gotForeignData } = input;

  if (status === 401 || status === 403) {
    return { verdict: 'denied', reason: `Access correctly denied (HTTP ${status}).` };
  }
  if (status === 404) {
    return { verdict: 'denied', reason: 'Resource not exposed to this identity (HTTP 404).' };
  }
  if (status >= 200 && status < 300) {
    return gotForeignData
      ? {
          verdict: 'broken',
          reason: `Tampered request returned HTTP ${status} with another identity's data — access control failed.`,
        }
      : {
          verdict: 'inconclusive',
          reason: `HTTP ${status} returned, but no clear foreign data in the response — verify manually.`,
        };
  }
  return { verdict: 'inconclusive', reason: `HTTP ${status} — inconclusive; the endpoint may have errored.` };
}

/**
 * Consented active-scan runner (Phase 5a/5b).
 *
 * Replays real, authenticated requests with a tampered identity to prove broken
 * access control. The HTTP transport is INJECTED (`HttpFn`) so the engine is
 * pure-logic and fully unit-testable, and so the one place that actually touches
 * the network (the real adapter) carries all the safety rails: explicit consent,
 * single-host scope, request budget, and traffic redaction.
 *
 * Checks implemented here:
 *   - jwt-not-verified        — server accepts a forged alg:none token (CWE-347)
 *   - bola-idor               — A can read another user's object (CWE-639)
 *   - tenant-isolation-broken — A can read another tenant's data (CWE-639)
 *
 * It never sends a tampered request to an endpoint the test user can't already
 * reach (non-2xx baseline), and it honours `maxRequests`.
 */
import { makeFinding } from '../utils/finding';
import { decodeJwt, forgeNoneAlg, tamperClaimsKeepSig } from './jwt';
import { findInjectionPoints, applyInjection } from './tamper';
import { classifyAuthzResult } from './accessControl';
import type { HttpRequestSpec } from './types';
import type { Finding } from '../types';

export interface ActiveResponse {
  status: number;
  bodyText: string;
}

/** Injected transport. The real adapter applies scope/budget/redaction. */
export type HttpFn = (req: {
  method: string;
  path: string;
  query?: Record<string, string | number>;
  body?: unknown;
  headers: Record<string, string>;
}) => Promise<ActiveResponse>;

export interface ActiveScanConfig {
  /** Bearer token for the primary test identity. */
  token: string;
  /** Optional second identity — required for the cleanest tenant/IDOR proof. */
  tokenB?: string;
  /** Authenticated requests to probe (built from the route graph by the caller). */
  requests: HttpRequestSpec[];
  /** Hard cap on total HTTP calls (safety). */
  maxRequests?: number;
}

const BUDGET_DEFAULT = 200;

/** Claims we try to set to impersonate an admin during escalation tests. */
const ADMIN_CLAIMS = { role: 'admin', is_admin: true, isAdmin: true, admin: true };

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

function is2xx(status: number): boolean {
  return status >= 200 && status < 300;
}

/** Pull the value of `point`'s category from another identity's JWT claims. */
function foreignValueFor(category: 'object-id' | 'tenant-id', claims: Record<string, unknown>): string | number | null {
  const candidates =
    category === 'tenant-id'
      ? [claims.org_id, claims.organization_id, claims.tenant_id, claims.tenant, claims.workspace_id]
      : [claims.sub, claims.user_id, claims.uid, claims.id];
  for (const v of candidates) {
    if (typeof v === 'string' || typeof v === 'number') return v;
  }
  return null;
}

/**
 * A 403 endpoint: see whether forging an admin role (with the signature kept, or
 * via alg:none) flips it to a 2xx — which proves the server trusts the client's
 * role claim instead of verifying it.
 */
async function tryEscalate(
  req: HttpRequestSpec,
  token: string,
  send: (req: HttpRequestSpec, token: string) => Promise<ActiveResponse>,
  hasBudget: () => boolean,
): Promise<Finding | null> {
  const variants = [tamperClaimsKeepSig(token, ADMIN_CLAIMS), forgeNoneAlg(token, ADMIN_CLAIMS)];
  for (const variant of variants) {
    if (!variant || !hasBudget()) continue;
    const r = await send(req, variant);
    if (is2xx(r.status)) {
      return makeFinding({
        rule: 'privilege-escalation',
        title: 'Privilege escalation via forged role claim',
        severity: 'critical',
        category: 'security',
        source: 'dynamic',
        endpoint: req.path,
        owasp: 'A01:2025',
        cwe: 'CWE-269',
        description: `${req.path} returned 403 for the test user but 200 once the token's role was changed to "admin" — the server trusts the client-supplied role instead of verifying it.`,
        recommendation: 'Derive authorization from a server-verified token (validate the signature) and never trust role/claims that the client can modify.',
      });
    }
  }
  return null;
}

export async function runActiveScan(config: ActiveScanConfig, http: HttpFn): Promise<Finding[]> {
  const findings: Finding[] = [];
  const budget = config.maxRequests ?? BUDGET_DEFAULT;
  let used = 0;

  const send = (req: HttpRequestSpec, token: string): Promise<ActiveResponse> => {
    used++;
    return http({ method: req.method, path: req.path, query: req.query, body: req.body, headers: bearer(token) });
  };

  const bClaims = config.tokenB ? decodeJwt(config.tokenB)?.payload ?? null : null;
  let jwtReported = false;

  for (const req of config.requests) {
    if (used >= budget) break;

    // Baseline as the real test user.
    const baseline = await send(req, config.token);

    // Forbidden for this user? Try to escalate via a forged admin role claim.
    if (baseline.status === 403 && used < budget) {
      const escalated = await tryEscalate(req, config.token, send, () => used < budget);
      if (escalated) findings.push(escalated);
      continue;
    }

    // Only the remaining checks need an endpoint A can actually reach.
    if (!is2xx(baseline.status)) continue;

    // --- JWT verification: does the server accept a forged alg:none token? ---
    if (!jwtReported && used < budget) {
      const forged = forgeNoneAlg(config.token);
      if (forged) {
        const r = await send(req, forged);
        if (is2xx(r.status)) {
          findings.push(
            makeFinding({
              rule: 'jwt-not-verified',
              title: 'JWT signature not verified (alg:none accepted)',
              severity: 'critical',
              category: 'security',
              source: 'dynamic',
              endpoint: req.path,
              owasp: 'A02:2025',
              cwe: 'CWE-347',
              description: `${req.path} accepted a forged "alg:none" token — the server does not verify JWT signatures, so anyone can mint a valid-looking token.`,
              recommendation: 'Verify the JWT signature server-side and reject the "none" algorithm; pin the allowed algorithms (e.g. RS256/HS256).',
            }),
          );
          jwtReported = true;
        }
      }
    }

    // --- Cross-access (IDOR / tenant): request B's resource while authed as A ---
    if (bClaims) {
      for (const point of findInjectionPoints(req)) {
        if (used >= budget) break;
        const foreign = foreignValueFor(point.category, bClaims);
        if (foreign === null || String(foreign) === String(point.value)) continue;

        const tampered = applyInjection(req, point, foreign);
        const r = await send(tampered, config.token);
        const gotForeignData = r.bodyText.includes(String(foreign));
        const { verdict } = classifyAuthzResult({ status: r.status, gotForeignData });
        if (verdict !== 'broken') continue;

        const isTenant = point.category === 'tenant-id';
        findings.push(
          makeFinding({
            rule: isTenant ? 'tenant-isolation-broken' : 'bola-idor',
            title: isTenant
              ? 'Cross-tenant data access (broken tenant isolation)'
              : 'Broken object-level authorization (IDOR / BOLA)',
            severity: 'critical',
            category: 'security',
            source: 'dynamic',
            endpoint: req.path,
            owasp: 'A01:2025',
            cwe: 'CWE-639',
            description: `Setting ${point.label}=${foreign} (another identity's value) and calling ${req.path} as the test user returned HTTP ${r.status} containing that identity's data.`,
            recommendation: isTenant
              ? 'Scope every query by the authenticated tenant derived from the session — never trust a tenant id supplied in the request.'
              : 'Enforce per-object ownership checks server-side; never authorize access based on an id supplied by the client.',
          }),
        );
      }
    }
  }

  return findings;
}

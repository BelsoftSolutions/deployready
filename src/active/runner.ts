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
 * reach (non-2xx baseline), and it honours `maxRequests` (and stops cleanly when
 * the transport's own budget runs out).
 *
 * IDOR / tenant verdicts come from the semantic, field-level engine in
 * `accessControl.ts`: two own baselines ($TOKEN) and two owner baselines
 * ($TOKEN_B) per swapped id teach it the volatile fields; owner markers found in
 * the tampered body (any status) prove disclosure; an anonymous control is sent
 * only when owner data came back, to tell a public resource from a leak. Only
 * `confirmed-vulnerable` (critical) and `suspected` (warning) become findings;
 * every verdict is reported through `onObserve`.
 *
 * Every finding carries a redacted `proof` (curl command, status, truncated
 * response, control). Tokens are never written: the curl names them $TOKEN /
 * $TOKEN_B. `onObserve` reports what each check saw, so the Verifier can tell
 * "the trigger now fails and the control still works" from "nothing answered".
 */
import { makeFinding } from '../utils/finding';
import { decodeJwt, forgeNoneAlg, tamperClaimsKeepSig } from './jwt';
import { findInjectionPoints, applyInjection } from './tamper';
import { assessAuthz, maskBody, type AuthzResult, type AuthzVerdict } from './accessControl';
import { ActiveBudgetError, matchRoutePattern } from './safety';
import type { HttpRequestSpec } from './types';
import type { Finding } from '../types';
import { absoluteUrl, buildProof } from '../dynamic/proof';
import { redact } from '../utils/redact';

export interface ActiveResponse {
  status: number;
  bodyText: string;
  /** Absolute URL actually requested, when the transport knows it (used in proofs). */
  url?: string;
}

/** Rules produced by the active scan (all carry `source: 'dynamic'`). */
export const ACTIVE_RULES: ReadonlySet<string> = new Set([
  'jwt-not-verified',
  'privilege-escalation',
  'bola-idor',
  'tenant-isolation-broken',
]);

/**
 * What one check observed, keyed by the finding endpoint it would report on.
 * `trigger` is the attacking request's status (undefined = not sent); `control`
 * is the legitimate request that must keep working for a "fixed" verdict.
 */
export type ActiveObservation =
  | { kind: 'baseline'; endpoint: string; status: number }
  | { kind: 'jwt'; endpoint: string; anonymousStatus: number; trigger?: number; control: number }
  | { kind: 'escalation'; endpoint: string; trigger: number[]; control: number }
  | {
      kind: 'cross';
      rule: 'bola-idor' | 'tenant-isolation-broken';
      endpoint: string;
      tamperedPath: string;
      trigger: number;
      /** 'own-data': 2xx with the test user's own data, i.e. the swapped id was ignored. */
      outcome: 'denied' | 'own-data' | 'broken' | 'other';
      /** The full semantic verdict and its explanation. */
      verdict: AuthzVerdict;
      reason: string;
      /** The owner ($TOKEN_B) fetching the tampered resource; undefined when not fetched. */
      control?: number;
    }
  | { kind: 'untested'; endpoint: string; reason: string };

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
  /** Base URL shown in proofs when the transport does not report the URL it requested. */
  baseUrl?: string;
  /** Called with what each check saw (used by the Verifier). */
  onObserve?: (o: ActiveObservation) => void;
  /**
   * Kept for compatibility: the owner's baselines are now always fetched for a
   * cross-access attempt (they are what the field-level verdict compares with).
   */
  alwaysFetchOwnerControl?: boolean;
  /** Fields the verdict engine ignores, on top of the volatile ones it learns. */
  ignoredFields?: readonly string[];
  /** Route patterns that are public by design (verdict: intentionally-public). */
  publicRoutes?: readonly string[];
  /** Owner baselines fetched per tampered resource, to learn volatile fields (default 2, min 1). */
  ownerBaselineCount?: number;
}

const BUDGET_DEFAULT = 200;
const OWNER_BASELINES_DEFAULT = 2;

/** Claims we try to set to impersonate an admin during escalation tests. */
const ADMIN_CLAIMS = { role: 'admin', is_admin: true, isAdmin: true, admin: true };

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

function is2xx(status: number): boolean {
  return status >= 200 && status < 300;
}

function queryString(query?: Record<string, string | number>): string {
  if (!query || Object.keys(query).length === 0) return '';
  const qs = new URLSearchParams(Object.entries(query).map(([k, v]): [string, string] => [k, String(v)]));
  return `?${qs.toString()}`;
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
  baseline: ActiveResponse,
  send: (req: HttpRequestSpec, token: string) => Promise<ActiveResponse>,
  hasBudget: () => boolean,
  urlOf: (req: HttpRequestSpec, r: ActiveResponse) => string,
  observe: (o: ActiveObservation) => void,
): Promise<Finding | null> {
  const variants: [string | null, string][] = [
    [tamperClaimsKeepSig(token, ADMIN_CLAIMS), '<copy of $TOKEN with role=admin claims, original signature kept>'],
    [forgeNoneAlg(token, ADMIN_CLAIMS), '<alg:none copy of $TOKEN with role=admin claims>'],
  ];
  const statuses: number[] = [];
  for (const [variant, label] of variants) {
    if (!variant || !hasBudget()) continue;
    const r = await send(req, variant);
    statuses.push(r.status);
    if (is2xx(r.status)) {
      observe({ kind: 'escalation', endpoint: req.path, trigger: statuses, control: baseline.status });
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
        proof: buildProof({
          request: { method: req.method, url: urlOf(req, r), auth: label },
          status: r.status,
          response: r.bodyText,
          control: `Same request with your real $TOKEN got HTTP ${baseline.status}.`,
        }),
      });
    }
  }
  observe({ kind: 'escalation', endpoint: req.path, trigger: statuses, control: baseline.status });
  return null;
}

export async function runActiveScan(config: ActiveScanConfig, http: HttpFn): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    await scan(config, http, findings);
  } catch (err) {
    // The transport's own budget ran out: keep what was proven so far.
    if (!(err instanceof ActiveBudgetError)) throw err;
  }
  return findings;
}

const VERDICT_OUTCOME: Record<AuthzVerdict, 'denied' | 'broken' | 'other'> = {
  'confirmed-vulnerable': 'broken',
  suspected: 'other',
  'verified-denied': 'denied',
  inconclusive: 'other',
  untested: 'other',
  'intentionally-public': 'other',
};

async function scan(config: ActiveScanConfig, http: HttpFn, findings: Finding[]): Promise<void> {
  const budget = config.maxRequests ?? BUDGET_DEFAULT;
  const ownerCount = Math.max(1, config.ownerBaselineCount ?? OWNER_BASELINES_DEFAULT);
  let used = 0;

  const send = (req: HttpRequestSpec, token: string): Promise<ActiveResponse> => {
    used++;
    return http({ method: req.method, path: req.path, query: req.query, body: req.body, headers: bearer(token) });
  };

  const sendAnonymous = (req: HttpRequestSpec): Promise<ActiveResponse> => {
    used++;
    return http({ method: req.method, path: req.path, query: req.query, body: req.body, headers: {} });
  };

  const observe = (o: ActiveObservation): void => config.onObserve?.(o);
  const urlOf = (req: HttpRequestSpec, r: ActiveResponse): string =>
    r.url ?? absoluteUrl(config.baseUrl, req.path + queryString(req.query));

  const bClaims = config.tokenB ? decodeJwt(config.tokenB)?.payload ?? null : null;
  let jwtReported = false;
  const ownerCache = new Map<string, ActiveResponse[]>();

  for (const req of config.requests) {
    if (used >= budget) {
      observe({ kind: 'untested', endpoint: req.path, reason: `request budget of ${budget} used up` });
      continue;
    }

    // Baseline as the real test user.
    const baseline = await send(req, config.token);
    observe({ kind: 'baseline', endpoint: req.path, status: baseline.status });

    // Forbidden for this user? Try to escalate via a forged admin role claim.
    if (baseline.status === 403 && used < budget) {
      const escalated = await tryEscalate(req, config.token, baseline, send, () => used < budget, urlOf, observe);
      if (escalated) findings.push(escalated);
      continue;
    }

    // Only the remaining checks need an endpoint A can actually reach.
    if (!is2xx(baseline.status)) continue;

    // --- JWT verification: does the server accept a forged alg:none token? ---
    // Only meaningful on an endpoint that actually requires auth, so first send
    // the same request with no credentials: a public route (2xx) proves nothing.
    if (!jwtReported && used < budget) {
      const forged = forgeNoneAlg(config.token);
      if (forged) {
        const control = await sendAnonymous(req);
        if (!(control.status === 401 || control.status === 403) || used >= budget) {
          observe({ kind: 'jwt', endpoint: req.path, anonymousStatus: control.status, control: baseline.status });
        } else {
          const r = await send(req, forged);
          observe({ kind: 'jwt', endpoint: req.path, anonymousStatus: control.status, trigger: r.status, control: baseline.status });
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
                description: `${req.path} rejected the request without a token but accepted a forged "alg:none" token — the server does not verify JWT signatures, so anyone can mint a valid-looking token.`,
                recommendation: 'Verify the JWT signature server-side and reject the "none" algorithm; pin the allowed algorithms (e.g. RS256/HS256).',
                proof: buildProof({
                  request: { method: req.method, url: urlOf(req, r), auth: '<alg:none copy of $TOKEN, signature removed>' },
                  status: r.status,
                  response: r.bodyText,
                  control: `Same request without any credentials got HTTP ${control.status}; with your real $TOKEN it got HTTP ${baseline.status}.`,
                }),
              }),
            );
            jwtReported = true;
          }
        }
      }
    }

    // --- Cross-access (IDOR / tenant): request B's resource while authed as A ---
    if (!bClaims) continue;
    const points = findInjectionPoints(req);
    if (points.length === 0) continue;

    // A second own baseline lets the verdict engine learn the test user's volatile fields.
    const ownBaselines: ActiveResponse[] = [baseline];
    if (used < budget) {
      const again = await send(req, config.token);
      if (is2xx(again.status)) ownBaselines.push(again);
    }

    for (const point of points) {
      const isTenant = point.category === 'tenant-id';
      const rule = isTenant ? 'tenant-isolation-broken' : 'bola-idor';
      const foreign = foreignValueFor(point.category, bClaims);
      if (foreign === null) {
        observe({ kind: 'untested', endpoint: req.path, reason: `the second token has no ${isTenant ? 'tenant' : 'user'} claim to swap into ${point.label}` });
        continue;
      }
      if (String(foreign) === String(point.value)) continue;
      if (used >= budget) {
        observe({ kind: 'untested', endpoint: req.path, reason: `request budget of ${budget} used up before ${point.label} was tested` });
        continue;
      }

      const tampered = applyInjection(req, point, foreign);
      const r = await send(tampered, config.token);

      // The owner's own view of the same resource, fetched >= 2 times (volatile fields).
      const key = JSON.stringify([tampered.method, tampered.path, tampered.query, tampered.body]);
      let owner = ownerCache.get(key);
      if (!owner && config.tokenB) {
        owner = [];
        for (let i = 0; i < ownerCount && used < budget; i++) owner.push(await send(tampered, config.tokenB));
        ownerCache.set(key, owner);
      }
      owner ??= [];

      const declaredPublic = matchRoutePattern(config.publicRoutes ?? [], tampered.method, req.path, tampered.path) !== null;
      const input = {
        tampered: r,
        ownBaselines,
        ownerBaselines: owner,
        foreignValue: foreign,
        ownValue: point.value,
        policy: { ignoredFields: config.ignoredFields ?? [], declaredPublic },
      };
      let verdict: AuthzResult = assessAuthz(input);
      let anonymous: ActiveResponse | null = null;
      if (verdict.wantsAnonymousControl && used < budget) {
        anonymous = await sendAnonymous(tampered);
        verdict = assessAuthz({ ...input, anonymous });
      }

      const ownerOk = owner.find((o) => is2xx(o.status));
      observe({
        kind: 'cross',
        rule,
        endpoint: req.path,
        tamperedPath: tampered.path,
        trigger: r.status,
        outcome: verdict.ownData && verdict.verdict === 'verified-denied' ? 'own-data' : VERDICT_OUTCOME[verdict.verdict],
        verdict: verdict.verdict,
        reason: verdict.reason,
        control: (ownerOk ?? owner[0])?.status,
      });
      if (verdict.verdict !== 'confirmed-vulnerable' && verdict.verdict !== 'suspected') continue;

      const confirmed = verdict.verdict === 'confirmed-vulnerable';
      const subject = isTenant ? 'tenant' : 'object';
      const fields = verdict.disclosed.length
        ? `Disclosed: ${verdict.disclosed.map((d) => `${d.path}${d.sensitive ? ' (sensitive)' : ''} = ${d.masked}`).join(', ')}.`
        : 'No individual private field could be singled out.';
      findings.push(
        makeFinding({
          rule,
          title: `${confirmed ? '' : 'Suspected: '}${
            isTenant ? 'Cross-tenant data access (broken tenant isolation)' : 'Broken object-level authorization (IDOR / BOLA)'
          }`,
          severity: confirmed ? 'critical' : 'warning',
          category: 'security',
          source: 'dynamic',
          endpoint: req.path,
          owasp: 'A01:2025',
          cwe: 'CWE-639',
          evidence: redact(fields),
          description: [
            `Setting ${point.label} to another identity's value (${foreign}) and calling ${req.path} as the test user: ${verdict.reason}`,
            fields,
            `Why this violates the policy: each identity may only read ${isTenant ? "its own tenant's data" : 'objects it owns'}; these values belong to the ${subject} of $TOKEN_B and are absent from everything $TOKEN can legitimately read.`,
            `How it was established: ${verdict.method}${confirmed ? '' : ' Not enough evidence to confirm — verify manually.'}`,
          ].join(' '),
          recommendation: isTenant
            ? 'Scope every query by the authenticated tenant derived from the session — never trust a tenant id supplied in the request.'
            : 'Enforce per-object ownership checks server-side; never authorize access based on an id supplied by the client.',
          proof: buildProof({
            request: { method: tampered.method, url: urlOf(tampered, r), auth: '$TOKEN' },
            status: r.status,
            // The owner's values are masked before the body is truncated and redacted.
            response: maskBody(r.bodyText, verdict.matchedValues),
            control: ownerOk
              ? `The owning identity ($TOKEN_B) requesting the same resource: HTTP ${ownerOk.status} (${owner.length} request${owner.length === 1 ? '' : 's'}, compared field by field). Your own resource (${req.path}) with $TOKEN got HTTP ${baseline.status}.${
                  anonymous ? ` Without credentials: HTTP ${anonymous.status}.` : ''
                }`
              : `Your own resource (${req.path}) with $TOKEN got HTTP ${baseline.status}. The owner's request ($TOKEN_B) did not succeed${owner[0] ? ` (HTTP ${owner[0].status})` : ''}, so this could not be compared with the owner's data.`,
          }),
        }),
      );
    }
  }
}

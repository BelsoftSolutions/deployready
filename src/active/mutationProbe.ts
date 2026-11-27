/**
 * Unauthenticated-mutation probe: does a discovered DELETE / PATCH route accept
 * a request with NO credentials?
 *
 * Safety design (it never touches real data):
 *   - Only runs inside the consented active scan, and only against a loopback
 *     target (never an owned remote host, even with --i-own-this-target).
 *   - Only routes with at least one path parameter are probed, and EVERY
 *     parameter is filled with a value that cannot exist
 *     (`__deployready_probe_<random>__`), so the request addresses no real
 *     record. Routes without a parameter (e.g. `DELETE /api/session`) would act
 *     on real state and are skipped.
 *   - No request body is sent.
 *   - PUT is skipped: many APIs treat PUT as an upsert, so even a non-existent id
 *     could create a record.
 *
 * Verdict, per route:
 *   - 401 / 403 → authentication is enforced: nothing reported.
 *   - 2xx       → the server handled a write for an anonymous caller. Reported,
 *                 unless a control request (same method, random non-existent
 *                 path) also answers 2xx — then it's a catch-all and proves nothing.
 *   - anything else (404, 405, 5xx, no response) → inconclusive, not reported:
 *     a 404 may simply mean the lookup ran before the auth check.
 */
import { randomBytes } from 'crypto';
import { makeFinding } from '../utils/finding';
import { absoluteUrl, buildProof } from '../dynamic/proof';
import type { HttpFn, ActiveResponse } from './runner';
import type { Finding, Route, SkippedRoute } from '../types';

export const MUTATION_RULE = 'unauthenticated-mutation';
const PROBED_METHODS = new Set(['DELETE', 'PATCH']);
const PARAM_RE = /^(?::([A-Za-z0-9_]+)\??|\{([^{}/]+)\})$/;
const PATTERN_SEGMENT = /[:{}<>*()?+[\]\\]/;

export interface MutationTarget {
  method: string;
  /** The route as discovered, e.g. /api/users/:id. */
  route: string;
  /** Concrete path with every parameter replaced by a non-existent value. */
  path: string;
}

export interface MutationPlan {
  targets: MutationTarget[];
  skipped: SkippedRoute[];
}

/** Build the probe value. Exported for tests. */
export function probeValue(): string {
  return `__deployready_probe_${randomBytes(4).toString('hex')}__`;
}

export function planMutationProbes(routes: Route[], value = probeValue()): MutationPlan {
  const targets: MutationTarget[] = [];
  const skipped: SkippedRoute[] = [];
  const seen = new Set<string>();
  for (const r of routes) {
    const method = r.method.toUpperCase();
    if (method === 'PUT') {
      skipped.push({ method, path: r.path, reason: 'PUT may upsert, so even a non-existent id could create data' });
      continue;
    }
    if (!PROBED_METHODS.has(method)) continue;
    const key = `${method} ${r.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    let params = 0;
    let bad = false;
    const out = r.path.split('/').map((seg) => {
      if (PARAM_RE.test(seg)) {
        params++;
        return value;
      }
      if (PATTERN_SEGMENT.test(seg)) bad = true;
      return seg;
    });
    if (bad || !r.path.startsWith('/')) {
      skipped.push({ method, path: r.path, reason: 'path is a pattern, not a concrete route' });
    } else if (params === 0) {
      skipped.push({ method, path: r.path, reason: 'no path parameter to point at a non-existent record, so a request could change real data' });
    } else {
      targets.push({ method, route: r.path, path: out.join('/') });
    }
  }
  return { targets, skipped };
}

function is2xx(s: number | undefined): boolean {
  return s !== undefined && s >= 200 && s < 300;
}

export interface MutationObservation {
  method: string;
  route: string;
  /** Status of the anonymous request; undefined = no response. */
  trigger?: number;
  /** Status of the random-path control; undefined = not sent / no response. */
  control?: number;
}

export interface MutationProbeOptions {
  baseUrl?: string;
  onObserve?: (o: MutationObservation) => void;
}

async function safeSend(http: HttpFn, method: string, path: string): Promise<ActiveResponse | null> {
  try {
    return await http({ method, path, headers: {} });
  } catch {
    return null;
  }
}

export async function runMutationProbes(
  targets: MutationTarget[],
  http: HttpFn,
  opts: MutationProbeOptions = {},
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const controls = new Map<string, ActiveResponse | null>();
  for (const t of targets) {
    const r = await safeSend(http, t.method, t.path);
    const obs: MutationObservation = { method: t.method, route: t.route, trigger: r?.status };
    if (!r || !is2xx(r.status)) {
      opts.onObserve?.(obs);
      continue;
    }
    // Control: same method on a random path that cannot exist (sent once per method).
    if (!controls.has(t.method)) {
      controls.set(t.method, await safeSend(http, t.method, `/${probeValue()}`));
    }
    const control = controls.get(t.method) ?? null;
    obs.control = control?.status;
    opts.onObserve?.(obs);
    if (!control || is2xx(control.status)) continue; // catch-all or no control: proves nothing

    findings.push(
      makeFinding({
        rule: MUTATION_RULE,
        title: `${t.method} route accepts requests without authentication`,
        severity: 'critical',
        category: 'security',
        source: 'dynamic',
        endpoint: `${t.method} ${t.route}`,
        owasp: 'A01:2025',
        cwe: 'CWE-306',
        description: `${t.method} ${t.route} answered HTTP ${r.status} to a request with no credentials (aimed at a record id that does not exist, so no real data was touched). The route handles writes for anonymous callers.`,
        recommendation: 'Put authentication (and an ownership/role check) in front of every route that changes data, and return 401/403 before looking up the record.',
        proof: buildProof({
          request: { method: t.method, url: r.url ?? absoluteUrl(opts.baseUrl, t.path) },
          status: r.status,
          response: r.bodyText,
          control: `Same method on a random non-existent path: HTTP ${control.status}, so this is the route's own answer, not a catch-all.`,
        }),
      }),
    );
  }
  return findings;
}

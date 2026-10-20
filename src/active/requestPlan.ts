/**
 * Turn statically-discovered routes into concrete authenticated requests for the
 * active scan (Phase 5a). Pure, no network.
 *
 * Safety: only GET routes are tested (active scanning never mutates data in v1).
 * Path params (`:id`, `{id}`) are filled only from the acting identity's JWT
 * claims — user-ish params from `sub`, tenant-ish params from the org/tenant
 * claim — so the baseline request hits the user's OWN resource; the runner then
 * swaps in the second identity's value to test isolation. Routes whose params we
 * can't fill, and pattern/wildcard routes, are skipped: no value or path is ever
 * invented.
 */
import type { Route, SkippedRoute } from '../types';
import type { HttpRequestSpec, PathParam } from './types';

const PARAM_RE = /^(?::(.+)|\{(.+)\})$/; // :name or {name}
const TENANT_PARAM_RE = /^(?:org|organization|tenant|team|company|workspace)/i;
const ID_PARAM_RE = /(?:^id$|_?id$|^uid$|^user$)/i;
const PATTERN_SEGMENT = /[:{}<>*()?+[\]\\]/;

interface Claim {
  name: string;
  value: string | number;
}

function firstClaim(claims: Record<string, unknown>, names: string[]): Claim | null {
  for (const name of names) {
    const value = claims[name];
    if (typeof value === 'string' || typeof value === 'number') return { name, value };
  }
  return null;
}

const userClaim = (claims: Record<string, unknown>) => firstClaim(claims, ['sub', 'user_id', 'uid', 'id']);
const tenantClaim = (claims: Record<string, unknown>) =>
  firstClaim(claims, ['org_id', 'organization_id', 'tenant_id', 'tenant', 'workspace_id']);

type Resolution =
  | { ok: true; path: string; pathParams: PathParam[]; filled: string[] }
  | { ok: false; reason: string };

/** Resolve a single path, or say why a param/pattern can't be filled. */
function resolvePath(path: string, claims: Record<string, unknown>): Resolution {
  const out: string[] = [];
  const pathParams: PathParam[] = [];
  const filled: string[] = [];
  for (const [index, seg] of path.split('/').entries()) {
    const m = PARAM_RE.exec(seg);
    if (!m) {
      if (PATTERN_SEGMENT.test(seg)) {
        return { ok: false, reason: `segment "${seg}" is a pattern or partial parameter, not a concrete value (values are never invented)` };
      }
      out.push(seg);
      continue;
    }
    const name = m[1] ?? m[2] ?? '';
    const claim = TENANT_PARAM_RE.test(name) ? tenantClaim(claims) : ID_PARAM_RE.test(name) ? userClaim(claims) : null;
    if (claim === null) {
      return { ok: false, reason: `no claim in your token can fill path parameter "${name}" (values are never invented)` };
    }
    out.push(String(claim.value));
    pathParams.push({ index, name });
    filled.push(`"${name}" from claim "${claim.name}"`);
  }
  return { ok: true, path: out.join('/'), pathParams, filled };
}

export interface ActivePlan {
  requests: HttpRequestSpec[];
  skipped: SkippedRoute[];
  /** One human-readable line per decision, for --verbose. */
  log: string[];
}

export function planActiveRequests(routes: Route[], claims: Record<string, unknown>): ActivePlan {
  const seen = new Set<string>();
  const requests: HttpRequestSpec[] = [];
  const skipped: SkippedRoute[] = [];
  const log: string[] = [];
  for (const route of routes) {
    const method = route.method.toUpperCase();
    const skip = (reason: string) => {
      skipped.push({ method, path: route.path, reason });
      log.push(`[active] skip ${method} ${route.path}: ${reason}`);
    };
    if (method !== 'GET') {
      skip('non-GET route: the scanner never mutates data');
      continue;
    }
    const resolved = resolvePath(route.path, claims);
    if (!resolved.ok) {
      skip(resolved.reason);
      continue;
    }
    if (seen.has(resolved.path)) continue;
    seen.add(resolved.path);
    const filled = resolved.filled.length ? `; filled ${resolved.filled.join(', ')}` : '';
    log.push(`[active] request GET ${resolved.path}: discovered at ${route.file}${route.line ? `:${route.line}` : ''}${filled}`);
    requests.push(
      resolved.pathParams.length
        ? { method: 'GET', path: resolved.path, pathParams: resolved.pathParams }
        : { method: 'GET', path: resolved.path },
    );
  }
  return { requests, skipped, log };
}

export function buildActiveRequests(routes: Route[], claims: Record<string, unknown>): HttpRequestSpec[] {
  return planActiveRequests(routes, claims).requests;
}

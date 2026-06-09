/**
 * Turn statically-discovered routes into concrete authenticated requests for the
 * active scan (Phase 5a). Pure, no network.
 *
 * Safety: only GET routes are tested (active scanning never mutates data in v1).
 * Path params (`:id`, `{id}`) are filled best-effort from the acting identity's
 * JWT claims — user-ish params from `sub`, tenant-ish params from the org/tenant
 * claim — so the baseline request hits the user's OWN resource; the runner then
 * swaps in the second identity's value to test isolation. Routes whose params we
 * can't fill are skipped (an unreachable baseline would just be noise).
 */
import type { Route } from '../types';
import type { HttpRequestSpec } from './types';

const PARAM_RE = /^(?::(.+)|\{(.+)\})$/; // :name or {name}
const TENANT_PARAM_RE = /^(?:org|organization|tenant|team|company|workspace)/i;
const ID_PARAM_RE = /(?:^id$|_?id$|^uid$|^user$)/i;

function userClaim(claims: Record<string, unknown>): string | number | null {
  for (const v of [claims.sub, claims.user_id, claims.uid, claims.id]) {
    if (typeof v === 'string' || typeof v === 'number') return v;
  }
  return null;
}

function tenantClaim(claims: Record<string, unknown>): string | number | null {
  for (const v of [claims.org_id, claims.organization_id, claims.tenant_id, claims.tenant, claims.workspace_id]) {
    if (typeof v === 'string' || typeof v === 'number') return v;
  }
  return null;
}

/** Resolve a single path, or null if a param can't be filled. */
function resolvePath(path: string, claims: Record<string, unknown>): string | null {
  const out: string[] = [];
  for (const seg of path.split('/')) {
    const m = PARAM_RE.exec(seg);
    if (!m) {
      out.push(seg);
      continue;
    }
    const name = m[1] ?? m[2] ?? '';
    const value = TENANT_PARAM_RE.test(name) ? tenantClaim(claims) : ID_PARAM_RE.test(name) ? userClaim(claims) : null;
    if (value === null) return null; // unfillable param → skip the route
    out.push(String(value));
  }
  return out.join('/');
}

export function buildActiveRequests(routes: Route[], claims: Record<string, unknown>): HttpRequestSpec[] {
  const seen = new Set<string>();
  const requests: HttpRequestSpec[] = [];
  for (const route of routes) {
    if (route.method.toUpperCase() !== 'GET') continue; // safe reads only
    const path = resolvePath(route.path, claims);
    if (path === null || seen.has(path)) continue;
    seen.add(path);
    requests.push({ method: 'GET', path });
  }
  return requests;
}

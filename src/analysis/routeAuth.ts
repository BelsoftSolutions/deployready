/**
 * Routes that change data (or serve /admin) with no auth check.
 *
 * Pure, no I/O. Starts from the parser's route graph (`guarded` = router-level or
 * per-route auth middleware was seen) and then looks at the handler's own source
 * for in-handler checks the graph cannot see: FastAPI `Depends(...)`, Flask
 * `@login_required`, `getServerSession()`, `auth()`, `requireAuth(...)` and the like.
 *
 * Low false positives first:
 *  - DELETE and /admin routes always count (critical).
 *  - POST/PUT/PATCH only count (warning) when the project uses auth somewhere —
 *    a public demo with no auth at all is not "missing" a check on one route.
 *  - Public-by-design POST paths (login, signup, webhooks, contact, …) are skipped.
 */
import type { Route } from '../types';

export interface UnauthRoute {
  route: Route;
  severity: 'critical' | 'warning';
  reason: 'admin' | 'delete' | 'mutating';
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const ADMIN_PATH_RE = /(?:^|\/)admin(?:$|[/_-])/i;
const PUBLIC_POST_RE =
  /(?:^|\/)(?:log-?in|log-?out|sign-?in|sign-?up|sign-?out|register|auth|oauth|token|refresh|session|webhooks?|callback|contact|subscribe|newsletter|forgot[-_]?password|reset[-_]?password|verify|health|graphql|\[\.\.\.nextauth\])(?:$|[/_.-])/i;

/** In-handler guard calls and decorators the route graph does not model. */
const GUARD_RE = new RegExp(
  [
    '\\bDepends\\s*\\(',
    '\\bSecurity\\s*\\(',
    '@\\w*(?:login|auth|jwt|token|permission|admin)_required\\b',
    '@(?:requires_auth|authenticated|permission_classes)\\b',
    '\\bgetServerSession\\s*\\(',
    '\\bgetServerAuthSession\\s*\\(',
    '\\bauth\\s*\\(\\s*\\)',
    '\\bcurrentUser\\s*\\(',
    '\\bgetUser\\s*\\(',
    '\\bgetSession\\s*\\(',
    '\\bverifyToken\\s*\\(',
    '\\bjwt\\.verify\\s*\\(',
    '\\b(?:require|ensure|check|with)(?:Auth|Admin|User|Login|Session)\\w*\\b',
    '\\bisAuthenticated\\b',
    '\\bauthenticate\\w*\\b',
    '\\bcurrent_user\\b',
    '\\breq\\.(?:user|auth|session\\.user)\\b',
    '\\brequest\\.user\\b',
  ].join('|'),
);

/** Max lines of handler source (from the route line) to inspect for in-handler guards. */
const HANDLER_WINDOW = 40;
/** The start of the next route declaration: the current handler ends before it. */
const ROUTE_START_RE =
  /^\s*(?:@[\w.]+\.(?:get|post|put|patch|delete|route|api_route)\s*\(|(?:app|router|api|server|\w+Router)\.(?:get|post|put|patch|delete|all|route)\s*\()/i;

/** Source lines of the route's handler: its decorators, then until the next route declaration. */
function handlerSource(route: Route, source: string): string {
  const lines = source.split('\n');
  const start = route.line! - 1;
  let from = start;
  while (from > 0 && /^\s*@/.test(lines[from - 1]!)) from--;
  let to = start + 1;
  // Skip decorator lines that belong to this same handler, then stop at the next route.
  while (to < lines.length && /^\s*@/.test(lines[to]!)) to++;
  while (to < lines.length && to - start < HANDLER_WINDOW && !ROUTE_START_RE.test(lines[to]!)) to++;
  return lines.slice(from, to).join('\n');
}

function handlerHasGuard(route: Route, source: string | undefined): boolean {
  if (!source) return false;
  // Next.js route handlers / API pages, or no line info: the whole file is the handler module.
  if (!route.line || /(?:^|\/)route\.[jt]sx?$/.test(route.file) || /(?:^|\/)pages\/api\//.test(route.file)) {
    return GUARD_RE.test(source);
  }
  return GUARD_RE.test(handlerSource(route, source));
}

export function unauthenticatedRoutes(routes: Route[], sources: Map<string, string>): UnauthRoute[] {
  const code = routes.filter((r) => r.source !== 'openapi');
  const projectUsesAuth = code.some((r) => r.guarded) || [...sources.values()].some((s) => GUARD_RE.test(s));
  const out: UnauthRoute[] = [];
  const seen = new Set<string>();

  for (const r of code) {
    if (r.guarded) continue;
    const method = r.method.toUpperCase();
    const admin = ADMIN_PATH_RE.test(r.path);
    // Flask's bare @app.route is GET-only, but the parser reports it as ALL; Express app.all is real.
    const mutating = MUTATING.has(method) || (method === 'ALL' && !/\.py$/i.test(r.file));
    if (!admin && !mutating) continue;
    if (!admin && method !== 'DELETE' && (!projectUsesAuth || PUBLIC_POST_RE.test(r.path))) continue;
    if (handlerHasGuard(r, sources.get(r.file))) continue;

    const key = `${method} ${r.path} ${r.file}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const reason = admin ? 'admin' : method === 'DELETE' ? 'delete' : 'mutating';
    out.push({ route: r, severity: reason === 'mutating' ? 'warning' : 'critical', reason });
  }
  return out;
}

/**
 * The authorization policy (0.6): which role may do what to which resource.
 *
 * `.deployready.json` → `active.policy`:
 *
 *   { "draft": false,
 *     "roles": ["anonymous", "user", "admin"],
 *     "resources": [
 *       { "name": "invoices",
 *         "routes": ["GET /api/invoices", "GET /api/invoices/:id", "PATCH /api/invoices/:id",
 *                    { "route": "POST /api/invoices/batch-get", "batchField": "ids", "sideEffectFree": true }],
 *         "access": { "anonymous": "none", "user": "own", "admin": "manage" },
 *         "tenantScoped": true,
 *         "body": { "title": "DeployReady test" } } ],
 *     "graphql": { "endpoint": "/graphql", "introspection": "deny",
 *                  "queries": [{ "resource": "invoices", "query": "query($id: ID!) { invoice(id: $id) { id total } }", "variable": "id" }] } }
 *
 * Access levels, per role:
 *   none    may neither read nor change any record (and may not call the route)
 *   read    may read every record (inside its own tenant when tenantScoped), never change one
 *   own     may read and change only its own records
 *   manage  may read and change every record (inside its own tenant when tenantScoped
 *           and the identity has a tenant; an identity without a tenant is platform-wide)
 *
 * Pure: parsing, matching and the expected decision. No network.
 */
import type { Route } from '../types';

export type AccessLevel = 'none' | 'read' | 'own' | 'manage';
export const ACCESS_LEVELS: readonly AccessLevel[] = ['none', 'read', 'own', 'manage'];

export interface PolicyRoute {
  method: string;
  /** Path pattern with `:param` segments, e.g. /api/orgs/:org/projects/:id. */
  path: string;
  /** Query parameters bound to params, e.g. { userId: ':userId' } or a literal value. */
  query?: Record<string, string>;
  /** The original text, for reports. */
  label: string;
  /** Body field that carries a list of ids (a batch endpoint). */
  batchField?: string;
  /** The user declares this route safe to request repeatedly (no side effect), e.g. a POST batch read or an export GET. */
  sideEffectFree?: boolean;
}

export interface PolicyResource {
  name: string;
  routes: PolicyRoute[];
  access: Record<string, AccessLevel>;
  tenantScoped: boolean;
  /** Sample JSON body for create/update requests (stateful level only). */
  body?: Record<string, unknown>;
}

export interface GraphqlQuery {
  resource: string;
  query: string;
  /** Variable that carries the object id (default "id"). */
  variable: string;
  /** Param of the identity's own object that fills the variable (default = variable). */
  param: string;
}

export interface GraphqlPolicy {
  endpoint?: string;
  introspection: 'allow' | 'deny';
  queries: GraphqlQuery[];
}

export interface AuthzPolicyConfig {
  draft: boolean;
  roles: string[];
  resources: PolicyResource[];
  graphql?: GraphqlPolicy;
}

const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
export const READ_METHODS = new Set(['GET', 'HEAD']);

/** Normalize `{id}` and `[id]` path params to `:id`; strip a trailing slash. */
export function normalizePattern(path: string): string {
  const p = path
    .split('/')
    .map((seg) => {
      const m = /^(?:\{([^}]+)\}|\[(?:\.\.\.)?([^\]]+)\]|:(.+))$/.exec(seg);
      return m ? `:${m[1] ?? m[2] ?? m[3]}` : seg;
    })
    .join('/');
  return p.length > 1 ? p.replace(/\/+$/, '') : p;
}

/** Parse "METHOD /path?key=:param" (method optional = GET). */
export function parseRouteSpec(text: string): PolicyRoute | null {
  const m = /^\s*(?:([A-Za-z]+)\s+)?(\/\S*)\s*$/.exec(text);
  if (!m) return null;
  const method = (m[1] ?? 'GET').toUpperCase();
  if (!METHODS.has(method)) return null;
  const [rawPath, rawQuery] = m[2]!.split('?', 2);
  const route: PolicyRoute = { method, path: normalizePattern(rawPath!), label: `${method} ${m[2]}` };
  if (rawQuery) {
    const q: Record<string, string> = {};
    for (const [k, v] of new URLSearchParams(rawQuery)) q[k] = v;
    if (Object.keys(q).length) route.query = q;
  }
  return route;
}

export function routeParams(r: Pick<PolicyRoute, 'path' | 'query'>): string[] {
  const out: string[] = [];
  for (const seg of r.path.split('/')) if (seg.startsWith(':')) out.push(seg.slice(1));
  for (const v of Object.values(r.query ?? {})) if (v.startsWith(':')) out.push(v.slice(1));
  return out;
}

/** Does a discovered route match a policy route (same method, same shape; param names may differ)? */
export function routeMatches(pr: Pick<PolicyRoute, 'method' | 'path'>, method: string, path: string): boolean {
  if (pr.method !== method.toUpperCase()) return false;
  const a = pr.path.split('/');
  const b = normalizePattern(path).split('/');
  if (a.length !== b.length) return false;
  return a.every((seg, i) => (seg.startsWith(':') && b[i]!.startsWith(':')) || seg === b[i]);
}

function isLevel(v: unknown): v is AccessLevel {
  return typeof v === 'string' && (ACCESS_LEVELS as readonly string[]).includes(v);
}

/** Validate `active.policy`. Bad entries are dropped with a problem message. Returns null when absent. */
export function parsePolicy(raw: unknown): { policy: AuthzPolicyConfig | null; problems: string[] } {
  const problems: string[] = [];
  if (raw === undefined || raw === null) return { policy: null, problems };
  if (typeof raw !== 'object' || Array.isArray(raw)) return { policy: null, problems: ['active.policy must be an object.'] };
  const r = raw as Record<string, unknown>;
  const resources: PolicyResource[] = [];
  const names = new Set<string>();
  const list = Array.isArray(r.resources) ? r.resources : [];
  if (!Array.isArray(r.resources)) problems.push('active.policy.resources must be an array.');
  list.forEach((entry, i) => {
    const at = `active.policy.resources[${i}]`;
    if (typeof entry !== 'object' || entry === null) return void problems.push(`${at} must be an object.`);
    const e = entry as Record<string, unknown>;
    const name = typeof e.name === 'string' ? e.name.trim() : '';
    if (!name) return void problems.push(`${at} needs a name.`);
    if (names.has(name)) return void problems.push(`${at}: duplicate resource name "${name}".`);
    const routes: PolicyRoute[] = [];
    for (const [j, item] of (Array.isArray(e.routes) ? e.routes : []).entries()) {
      const text = typeof item === 'string' ? item : typeof item === 'object' && item !== null ? (item as Record<string, unknown>).route : undefined;
      const parsed = typeof text === 'string' ? parseRouteSpec(text) : null;
      if (!parsed) {
        problems.push(`${at}.routes[${j}] is not "METHOD /path" (got ${JSON.stringify(item)}).`);
        continue;
      }
      if (typeof item === 'object' && item !== null) {
        const o = item as Record<string, unknown>;
        if (typeof o.batchField === 'string' && o.batchField.trim()) parsed.batchField = o.batchField.trim();
        if (o.sideEffectFree === true) parsed.sideEffectFree = true;
      }
      routes.push(parsed);
    }
    if (!routes.length) return void problems.push(`${at} ("${name}") has no valid route.`);
    const access: Record<string, AccessLevel> = {};
    if (typeof e.access === 'object' && e.access !== null && !Array.isArray(e.access)) {
      for (const [role, lvl] of Object.entries(e.access as Record<string, unknown>)) {
        if (role.startsWith('_')) continue;
        if (isLevel(lvl)) access[role] = lvl;
        else problems.push(`${at}.access.${role} must be one of ${ACCESS_LEVELS.join(', ')}.`);
      }
    } else problems.push(`${at}.access must be an object of role → level.`);
    names.add(name);
    const body = typeof e.body === 'object' && e.body !== null && !Array.isArray(e.body) ? (e.body as Record<string, unknown>) : undefined;
    resources.push({ name, routes, access, tenantScoped: e.tenantScoped !== false, ...(body ? { body } : {}) });
  });

  let graphql: GraphqlPolicy | undefined;
  if (r.graphql !== undefined) {
    const g = (typeof r.graphql === 'object' && r.graphql !== null ? r.graphql : {}) as Record<string, unknown>;
    const queries: GraphqlQuery[] = [];
    for (const [i, q] of (Array.isArray(g.queries) ? g.queries : []).entries()) {
      const o = (q ?? {}) as Record<string, unknown>;
      if (typeof o.query !== 'string' || typeof o.resource !== 'string') {
        problems.push(`active.policy.graphql.queries[${i}] needs "resource" and "query".`);
        continue;
      }
      if (/^\s*(?:mutation|subscription)\b/i.test(o.query)) {
        problems.push(`active.policy.graphql.queries[${i}] is a ${/^\s*mutation/i.test(o.query) ? 'mutation' : 'subscription'}; only queries are sent.`);
        continue;
      }
      const variable = typeof o.variable === 'string' && o.variable ? o.variable : 'id';
      queries.push({ resource: o.resource, query: o.query, variable, param: typeof o.param === 'string' && o.param ? o.param : variable });
    }
    graphql = {
      ...(typeof g.endpoint === 'string' && g.endpoint.startsWith('/') ? { endpoint: g.endpoint } : {}),
      introspection: g.introspection === 'allow' ? 'allow' : 'deny',
      queries,
    };
  }
  const roles = Array.isArray(r.roles) ? r.roles.filter((x): x is string => typeof x === 'string') : [];
  return { policy: { draft: r.draft === true, roles, resources, ...(graphql ? { graphql } : {}) }, problems };
}

// ---------------------------------------------------------------------------
// The expected decision
// ---------------------------------------------------------------------------

export type Relation = 'own' | 'other' | 'other-tenant' | 'collection';
export type Action = 'read' | 'write';

export function actionOf(method: string): Action {
  return READ_METHODS.has(method.toUpperCase()) ? 'read' : 'write';
}

/** The level a role has on a resource ("*" is the fallback; missing = none). */
export function levelFor(resource: PolicyResource, role: string): AccessLevel {
  return resource.access[role] ?? resource.access['*'] ?? 'none';
}

/** May `role` perform `action` on a record in `relation` to it? */
export function expectedAllowed(resource: PolicyResource, role: string, action: Action, relation: Relation): boolean {
  const level = levelFor(resource, role);
  if (level === 'none') return false;
  if (relation === 'other-tenant' && resource.tenantScoped) return false;
  if (action === 'write' && level === 'read') return false;
  if (level === 'own') return relation === 'own' || relation === 'collection';
  return true;
}

export interface Party {
  name: string;
  role: string;
  tenant?: string;
}

/** Relation of `actor` to a record owned by `owner`. */
export function relationTo(actor: Party, owner: Party | null): Relation {
  if (!owner) return 'collection';
  if (actor.name === owner.name) return 'own';
  if (actor.tenant && owner.tenant && actor.tenant !== owner.tenant) return 'other-tenant';
  return 'other';
}

/** Roles that may perform `action` on a collection route, for messages. */
export function allowedRoles(resource: PolicyResource, action: Action): string[] {
  return Object.keys(resource.access).filter((role) => role !== '*' && expectedAllowed(resource, role, action, 'collection'));
}

// ---------------------------------------------------------------------------
// Drafting a policy from discovered routes (`deployready policy init`)
// ---------------------------------------------------------------------------

const AUTH_FLOW = /^(?:login|logout|signin|signout|signup|register|auth|oauth|callback|session|sessions|token|refresh|forgot|reset|verify|webhook|webhooks|health|healthz|ready|status|metrics|favicon\.ico|robots\.txt)$/i;
const PUBLIC_CATALOG = /^(?:products?|catalog|catalogue|categories|category|posts?|articles?|blog|pages?|public|docs|faq|pricing|plans|search|tags?|listings?|menu|events)$/i;
const ADMIN_SEG = /^(?:admin|admins|internal|staff|superuser|backoffice|manage|management)$/i;
const USERISH = /^(?:users?|accounts?|profiles?|members?|me|account|profile|settings)$/i;
const EXPORT_SEG = /(?:export|download|csv|xlsx|pdf|report|reports|attachment|attachments|files?)$/i;
const BATCH_SEG = /^(?:batch|bulk|batch-get|batchget|bulk-get|many)$/i;
const NOISE = /^(?:api|v\d+|rest|graphql)$/i;

export interface DraftEntry {
  name: string;
  routes: (string | { route: string; batchField?: string; sideEffectFree?: boolean })[];
  access: Record<string, AccessLevel>;
  tenantScoped: boolean;
  why: string;
}

export interface PolicyDraft {
  resources: DraftEntry[];
  excluded: { route: string; why: string }[];
  graphqlEndpoint?: string;
}

function resourceName(path: string): string {
  const segs = path.split('/').filter((s) => s && !s.startsWith(':') && !NOISE.test(s) && !BATCH_SEG.test(s));
  if (segs.some((s) => ADMIN_SEG.test(s))) return `admin${segs.length > 1 ? `-${segs.filter((s) => !ADMIN_SEG.test(s)).pop() ?? ''}` : ''}`.replace(/-$/, '');
  const last = segs.filter((s) => !EXPORT_SEG.test(s) || segs.length === 1).pop();
  return (last ?? segs.pop() ?? 'root').toLowerCase();
}

/** Draft a policy from discovered routes. Heuristic, for the user to review; never used while `draft` is true. */
export function draftPolicy(routes: Route[]): PolicyDraft {
  const groups = new Map<string, { routes: Route[]; why: Set<string>; kind: 'admin' | 'user' | 'catalog' | 'owned' }>();
  const excluded: { route: string; why: string }[] = [];
  let graphqlEndpoint: string | undefined;
  const seen = new Set<string>();
  for (const r of routes) {
    const method = r.method.toUpperCase();
    const path = normalizePattern(r.path);
    const key = `${method} ${path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const segs = path.split('/').filter(Boolean);
    if (/(?:^|\/)graphql$/i.test(path)) {
      graphqlEndpoint ??= path;
      continue;
    }
    if (!METHODS.has(method)) {
      excluded.push({ route: key, why: `method ${method} is not tested` });
      continue;
    }
    if (/[*()?+\\]/.test(path)) {
      excluded.push({ route: key, why: 'pattern or wildcard route: no concrete path to request' });
      continue;
    }
    const statics = segs.filter((s) => !s.startsWith(':'));
    if (statics.some((s) => AUTH_FLOW.test(s)) || segs.length === 0) {
      excluded.push({ route: key, why: 'authentication, health or webhook route: not an authorization resource' });
      continue;
    }
    const name = resourceName(path);
    const kind = statics.some((s) => ADMIN_SEG.test(s))
      ? 'admin'
      : statics.some((s) => USERISH.test(s))
        ? 'user'
        : statics.some((s) => PUBLIC_CATALOG.test(s))
          ? 'catalog'
          : 'owned';
    const g = groups.get(name) ?? { routes: [], why: new Set<string>(), kind };
    // The strictest kind wins inside one group.
    const rank = { admin: 3, user: 2, owned: 1, catalog: 0 } as const;
    if (rank[kind] > rank[g.kind]) g.kind = kind;
    g.routes.push({ ...r, method, path });
    groups.set(name, g);
  }

  const resources: DraftEntry[] = [];
  for (const [name, g] of groups) {
    const access: Record<string, AccessLevel> =
      g.kind === 'admin'
        ? { anonymous: 'none', user: 'none', admin: 'manage' }
        : g.kind === 'catalog'
          ? { anonymous: 'read', user: 'read', admin: 'manage' }
          : { anonymous: 'none', user: 'own', admin: 'manage' };
    const why =
      g.kind === 'admin'
        ? 'path contains an admin/internal segment → admin only'
        : g.kind === 'catalog'
          ? 'looks like a public catalog (products, posts, ...) → anyone may read, only admin may change'
          : g.kind === 'user'
            ? 'user/account/profile record → each user only their own'
            : 'record addressed by id or owned data → each user only their own (adjust if it is shared or public)';
    const entries: DraftEntry['routes'] = g.routes.map((r) => {
      const text = `${r.method} ${r.path}`;
      const last = r.path.split('/').filter(Boolean).pop() ?? '';
      if (BATCH_SEG.test(last)) return { route: text, batchField: 'ids', sideEffectFree: false };
      if (r.method === 'GET' && /(?:^|[-_])(?:export|csv|xlsx)(?:$|[-_])/i.test(last)) return { route: text, sideEffectFree: false };
      return text;
    });
    const noisy = entries.some((e) => typeof e !== 'string');
    resources.push({
      name,
      routes: entries,
      access,
      tenantScoped: g.kind !== 'catalog',
      why: `${why}${noisy ? '. Batch/export routes are marked sideEffectFree:false — set it to true only if requesting them changes nothing' : ''}`,
    });
  }
  resources.sort((a, b) => a.name.localeCompare(b.name));
  return { resources, excluded, ...(graphqlEndpoint ? { graphqlEndpoint } : {}) };
}

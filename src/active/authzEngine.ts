/**
 * Policy-driven authorization engine (0.6, directive §4).
 *
 * Given a policy (resources × roles → none | read | own | manage), a set of
 * named identities, and the safety level, it plans one test per
 * (resource route, identity, record owner) and runs it against the live app:
 *
 *   missing-auth     anonymous on a route the policy does not open to anonymous
 *   vertical (BFLA)  a role on a route reserved for other roles
 *   horizontal       another user's record (BOLA / IDOR), also via query params
 *   cross-tenant     a record that belongs to another tenant
 *   nested-id        own parent id + another user's child id (/orgs/:mine/projects/:theirs)
 *   list-filter      a list route whose answer includes other users' records
 *   batch            an ids array mixing own and foreign ids
 *   export           export / download routes (read requests only)
 *   graphql          introspection exposure; a query by id across identities
 *   stateful only:   cross-write, cross-delete (on a record created for the test),
 *                    mass assignment / privilege escalation via extra fields, each
 *                    proven by reading the record back
 *
 * Every read verdict comes from the field-level engine in `accessControl.ts`
 * (owner markers, volatile fields learned from repeated baselines, anonymous
 * control): a VIOLATION needs the owner's private values in the answer, never a
 * status code alone. Writes are proven by a read-back. Anything that cannot be
 * proven is inconclusive; anything that could not run is untested, with why.
 *
 * Safety: GET (and declared side-effect-free) requests up to read-only; a
 * GraphQL request is sent only when it is a query; anything that writes needs
 * the "stateful" level, which the caller only grants on a disposable, loopback
 * or declared-owned target. The request budget is enforced here and by the
 * transport. Credentials are never written: proofs name them $<NAME>_AUTH.
 */
import { randomBytes } from 'crypto';
import { assessAuthz, maskBody, type AuthzResult } from './accessControl';
import { ActiveBudgetError, matchRoutePattern, routeSkipReason, sideEffectReason, type SafetyLevel } from './safety';
import {
  actionOf,
  allowedRoles,
  expectedAllowed,
  levelFor,
  normalizePattern,
  relationTo,
  routeMatches,
  routeParams,
  type Action,
  type AuthzPolicyConfig,
  type Party,
  type PolicyResource,
  type PolicyRoute,
  type Relation,
} from './policy';
import { authPlaceholder, type IdentityProvider, type ResolvedIdentity } from './identities';
import type { HttpFn, ActiveResponse } from './runner';
import type { AuthzCell, AuthzCellVerdict, AuthzMatrix, AuthzTestClass } from './authzTypes';
import type { Finding, Route } from '../types';
import { makeFinding } from '../utils/finding';
import { redact } from '../utils/redact';
import { absoluteUrl, proofBody } from '../dynamic/proof';

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export const AUTHZ_RULES: ReadonlySet<string> = new Set([
  'authz-missing-auth',
  'authz-bfla',
  'authz-bola',
  'authz-cross-tenant',
  'authz-unauthorized-write',
  'authz-mass-assignment',
  'authz-privilege-escalation',
  'graphql-introspection',
]);

const RULE_META: Record<string, { title: string; cwe: string; severity: 'critical' | 'warning'; fix: string }> = {
  'authz-missing-auth': {
    title: 'Missing server-side authorization (anonymous access)',
    cwe: 'CWE-306',
    severity: 'critical',
    fix: 'Require an authenticated session on this route server-side (middleware or a guard on the handler), and return 401 before touching data.',
  },
  'authz-bfla': {
    title: 'Broken function-level authorization (role can use a route reserved for other roles)',
    cwe: 'CWE-285',
    severity: 'critical',
    fix: 'Check the caller\'s role server-side on every privileged route (deny by default), not only by hiding the UI.',
  },
  'authz-bola': {
    title: 'Broken object-level authorization (IDOR / BOLA)',
    cwe: 'CWE-639',
    severity: 'critical',
    fix: 'Scope every lookup by the authenticated user (WHERE owner_id = session.user), including list, batch, export and nested routes; never trust an id from the request alone.',
  },
  'authz-cross-tenant': {
    title: 'Cross-tenant data access (broken tenant isolation)',
    cwe: 'CWE-639',
    severity: 'critical',
    fix: 'Derive the tenant from the session and add it to every query; reject ids that belong to another tenant even when the parent id in the path is the caller\'s own.',
  },
  'authz-unauthorized-write': {
    title: 'Unauthorized write: an identity changed or deleted another identity\'s record',
    cwe: 'CWE-639',
    severity: 'critical',
    fix: 'Load the record scoped by the authenticated owner/tenant before updating or deleting it; return 403/404 otherwise.',
  },
  'authz-mass-assignment': {
    title: 'Mass assignment: server stored fields the client must not control',
    cwe: 'CWE-915',
    severity: 'critical',
    fix: 'Copy only an allowlist of client-editable fields into the model (DTO / schema with strip-unknown); set owner, tenant and price server-side.',
  },
  'authz-privilege-escalation': {
    title: 'Privilege escalation via a role field on the user\'s own record',
    cwe: 'CWE-269',
    severity: 'critical',
    fix: 'Never accept role/isAdmin/permissions from the client on create or update; change roles only through an admin-only route.',
  },
  'graphql-introspection': {
    title: 'GraphQL introspection exposed',
    cwe: 'CWE-200',
    severity: 'warning',
    fix: 'Disable introspection in production (e.g. Apollo `introspection: false`), or restrict it to admins.',
  },
};

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

export interface AuthzEngineInput {
  policy: AuthzPolicyConfig;
  identities: ResolvedIdentity[];
  /** Discovered routes: used to list routes the policy does not cover and to find a /graphql endpoint. */
  routes: Route[];
  safetyLevel: SafetyLevel;
  unsafeRoutes?: readonly string[];
  ignoredFields?: readonly string[];
  maxRequests?: number;
  baseUrl?: string;
  policySource?: string;
  /** Only plan cells for this policy route ("METHOD /pattern"), e.g. for a re-check. */
  onlyRoute?: string;
  /** Problems found while parsing the config, carried into the matrix. */
  problems?: string[];
  /** Called once per request sent (method + path + identity name), e.g. for --verbose. */
  onSend?: (identity: string, method: string, path: string) => void;
}

interface Spec {
  method: string;
  path: string;
  query?: Record<string, string | number>;
  body?: unknown;
}

interface Who extends Party {
  provider?: IdentityProvider;
  unavailable?: string;
}

type CaseKind = 'read' | 'list' | 'write-cross' | 'delete-cross' | 'mass-update' | 'mass-create' | 'create-denied' | 'gql-introspection';

interface Case {
  kind: CaseKind;
  cls: AuthzTestClass;
  resource: PolicyResource;
  route: PolicyRoute;
  actor: Who;
  owner?: Who;
  expected: boolean;
  action: Action;
  relation: Relation;
  /** The request under test (as the actor). */
  spec: Spec;
  /** The owner's (or the allowed reference identity's) view of the same record, for markers. */
  ownerView?: { who: Who; spec: Spec };
  /** The actor's own record on the same route, for "own data" / own values. */
  ownView?: Spec;
  /** Id that was swapped in (echo detection). */
  foreign?: string;
  ownValue?: string;
  /** Item GET route of the resource (read-back for writes), filled for the owner. */
  readBack?: (who: Who, id?: string) => Spec | null;
  /** Create route (POST collection) of the resource, for cross-delete and mass-create. */
  create?: PolicyRoute;
  note?: string;
}

interface Planned {
  cases: Case[];
  cells: AuthzCell[];
  uncovered: string[];
}

// ---------------------------------------------------------------------------
// Filling routes with an identity's own values (never invented)
// ---------------------------------------------------------------------------

const TENANT_PARAM = /^(?:org|organization|tenant|team|company|workspace)(?:[-_]?id)?$/i;
const USER_PARAM = /^(?:user[-_]?id|uid|user|owner[-_]?id|account[-_]?id|member[-_]?id)$/i;
const USERISH_SEG = /^(?:users?|accounts?|profiles?|members?)$/i;
const ID_LIST_PARAM = /^ids$/i;

function claimValue(claims: Record<string, unknown> | undefined, keys: string[]): string | undefined {
  if (!claims) return undefined;
  for (const k of keys) {
    const v = claims[k];
    if (typeof v === 'string' || typeof v === 'number') return String(v);
  }
  return undefined;
}

function lookupParam(who: Who, resource: string, param: string, prevSeg: string | undefined): string | undefined {
  const p = who.provider;
  if (!p) return undefined;
  const own = p.objects?.[resource]?.[param] ?? p.params?.[param];
  // A "<placeholder>" left from the drafted config is not a value.
  if (own !== undefined) return /^<.*>$/.test(String(own)) ? undefined : String(own);
  if (TENANT_PARAM.test(param)) {
    return who.tenant ?? claimValue(p.claims, ['org_id', 'organization_id', 'tenant_id', 'tenant', 'workspace_id']);
  }
  if (USER_PARAM.test(param) || (param === 'id' && prevSeg !== undefined && USERISH_SEG.test(prevSeg))) {
    const v = p.params?.userId ?? p.params?.user_id ?? p.params?.uid;
    return v !== undefined ? String(v) : claimValue(p.claims, ['sub', 'user_id', 'uid', 'id']);
  }
  return undefined;
}

/** The identity's own user id, for owner fields (ownerId := someone else's id). */
function userIdOf(who: Who): string | undefined {
  const p = who.provider;
  if (!p) return undefined;
  const v = p.params?.userId ?? p.params?.user_id ?? p.params?.uid;
  return v !== undefined ? String(v) : claimValue(p.claims, ['sub', 'user_id', 'uid']);
}

interface Filled {
  spec: Spec;
  values: Record<string, string>;
}

function fillRoute(route: PolicyRoute, who: Who, resource: string, override: Record<string, string> = {}): Filled | null {
  const values: Record<string, string> = {};
  const segs = route.path.split('/');
  const out: string[] = [];
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i]!;
    if (!seg.startsWith(':')) {
      out.push(seg);
      continue;
    }
    const name = seg.slice(1);
    const v = override[name] ?? lookupParam(who, resource, name, segs[i - 1]);
    if (v === undefined || v === '') return null;
    values[name] = v;
    out.push(encodeURIComponent(v));
  }
  let query: Record<string, string> | undefined;
  for (const [k, raw] of Object.entries(route.query ?? {})) {
    query ??= {};
    if (!raw.startsWith(':')) {
      query[k] = raw;
      continue;
    }
    const name = raw.slice(1);
    const v = override[name] ?? lookupParam(who, resource, name, undefined);
    if (v === undefined || v === '') return null;
    values[name] = v;
    query[k] = v;
  }
  return { spec: { method: route.method, path: out.join('/') || '/', ...(query ? { query } : {}) }, values };
}

function lastParam(route: PolicyRoute): string | undefined {
  const ps = routeParams(route);
  return ps[ps.length - 1];
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

const EXPORT_PATH = /(?:^|[-_/])(?:export|exports|download|downloads|csv|xlsx|pdf)(?:$|[-_/.])/i;

function who(i: ResolvedIdentity): Who {
  return { name: i.name, role: i.role, ...(i.tenant ? { tenant: i.tenant } : {}), ...(i.provider ? { provider: i.provider } : {}), ...(i.unavailable ? { unavailable: i.unavailable } : {}) };
}

function specLabel(s: Spec): string {
  const q = s.query && Object.keys(s.query).length ? `?${new URLSearchParams(Object.entries(s.query).map(([k, v]): [string, string] => [k, String(v)])).toString()}` : '';
  return `${s.method} ${s.path}${q}`;
}

const LEVEL_RANK = { manage: 3, read: 2, own: 1, none: 0 } as const;

function classify(actor: Who, resource: PolicyResource, relation: Relation, expected: boolean, isExport: boolean): AuthzTestClass {
  if (expected) return relation === 'own' || relation === 'collection' ? 'own-access' : 'horizontal';
  if (isExport) return 'export';
  if (actor.role === 'anonymous') return 'missing-auth';
  if (levelFor(resource, actor.role) === 'none' || relation === 'collection') return 'vertical';
  return relation === 'other-tenant' ? 'cross-tenant' : 'horizontal';
}

export function planAuthz(input: AuthzEngineInput): Planned {
  const { policy, safetyLevel } = input;
  const unsafe = input.unsafeRoutes ?? [];
  const ids = input.identities.map(who);
  const available = ids.filter((i) => i.provider);
  const cases: Case[] = [];
  const cells: AuthzCell[] = [];

  const untested = (resource: PolicyResource, route: PolicyRoute, actor: Who, reason: string, extra: Partial<AuthzCell> = {}): void => {
    const action = actionOf(route.method);
    cells.push({
      resource: resource.name,
      route: route.label,
      identity: actor.name,
      role: actor.role,
      action,
      testClass: extra.testClass ?? 'own-access',
      expected: expectedAllowed(resource, actor.role, action, extra.target ? 'other' : 'collection') ? 'allow' : 'deny',
      verdict: 'untested',
      reason,
      ...extra,
    });
  };

  for (const resource of policy.resources) {
    // The item GET route doubles as the read-back / comparison request, so it must pass the same gates.
    const itemGet = resource.routes.find(
      (r) =>
        r.method === 'GET' &&
        routeParams(r).length > 0 &&
        !r.batchField &&
        !routeParams(r).some((p) => ID_LIST_PARAM.test(p)) &&
        !matchRoutePattern(unsafe, r.method, r.path) &&
        (r.sideEffectFree || safetyLevel === 'stateful' || !sideEffectReason(r.path)),
    );
    const createRoute = resource.routes.find((r) => r.method === 'POST' && !r.batchField && itemGet && itemGet.path.startsWith(`${r.path}/`));
    const readBack = itemGet
      ? (w: Who, id?: string): Spec | null => fillRoute(itemGet, w, resource.name, id === undefined ? {} : { [lastParam(itemGet)!]: id })?.spec ?? null
      : undefined;

    for (const route of resource.routes) {
      if (input.onlyRoute && `${route.method} ${route.path}` !== normalizeLabel(input.onlyRoute)) continue;
      const isBatch = Boolean(route.batchField) || routeParams(route).some((p) => ID_LIST_PARAM.test(p));
      // A batch read sent as POST is a read only when the user declared it side-effect free.
      const action: Action = isBatch && route.sideEffectFree ? 'read' : actionOf(route.method);
      const isExport = EXPORT_PATH.test(route.path);

      // ---- Safety gates (the same rules as the rest of the active scan) ----
      const denied = matchRoutePattern(unsafe, route.method, route.path);
      let gate: string | null = denied ? `listed in unsafeRoutes ("${denied}")` : null;
      if (!gate && safetyLevel === 'passive') gate = 'safety level "passive" sends no active requests';
      if (!gate && action === 'write' && safetyLevel !== 'stateful') {
        gate = `${route.method} changes data: only the "stateful" safety level (disposableEnvironment: true, loopback or owned host) sends it`;
      }
      if (!gate && action === 'read' && route.method !== 'GET' && route.method !== 'HEAD' && !route.sideEffectFree && safetyLevel !== 'stateful') {
        gate = `${route.method} is not assumed to be side-effect free (declare "sideEffectFree": true if it is)`;
      }
      if (!gate && route.method === 'GET' && !route.sideEffectFree && safetyLevel !== 'stateful') {
        const se = sideEffectReason(route.path);
        if (se) gate = `${se}; set "sideEffectFree": true on the route if requesting it changes nothing`;
        else if (routeSkipReason(safetyLevel, route.method, route.path, unsafe)) gate = routeSkipReason(safetyLevel, route.method, route.path, unsafe);
      }
      for (const a of ids) {
        if (gate) {
          untested(resource, route, a, gate, { testClass: isExport ? 'export' : 'own-access' });
          continue;
        }
        if (!a.provider) untested(resource, route, a, `identity unavailable: ${a.unavailable ?? 'no credential'}`);
      }
      if (gate) continue;

      const params = routeParams(route);
      // ---------------- Collection routes (no record id) ----------------
      if (params.length === 0 || (isBatch && params.every((p) => ID_LIST_PARAM.test(p)))) {
        if (isBatch) {
          planBatch(resource, route, available, itemGet, cases, cells);
          continue;
        }
        for (const a of available) {
          const expected = expectedAllowed(resource, a.role, action, 'collection');
          const spec: Spec = { method: route.method, path: route.path, ...(route.query ? { query: route.query } : {}) };
          if (action === 'write') {
            // POST to a collection = create.
            if (route.method !== 'POST') {
              untested(resource, route, a, `${route.method} on a collection is not exercised`);
              continue;
            }
            if (!resource.body) {
              untested(resource, route, a, 'no sample "body" in the policy resource, so no create request can be built (values are never invented)', { testClass: expected ? 'mass-assignment' : 'vertical' });
              continue;
            }
            cases.push({
              kind: expected ? 'mass-create' : 'create-denied',
              cls: expected ? 'mass-assignment' : a.role === 'anonymous' ? 'missing-auth' : 'vertical',
              resource, route, actor: a, expected, action, relation: 'collection',
              spec: { ...spec, body: resource.body }, readBack, create: route,
            });
            continue;
          }
          if (!expected) {
            // Reference: the strongest identity the policy allows here.
            const ref = available
              .filter((r) => r !== a && r.role !== 'anonymous' && expectedAllowed(resource, r.role, 'read', 'collection'))
              .sort((x, y) => LEVEL_RANK[levelFor(resource, y.role)] - LEVEL_RANK[levelFor(resource, x.role)])[0];
            cases.push({
              kind: 'read', cls: classify(a, resource, 'collection', false, isExport), resource, route, actor: a, expected, action, relation: 'collection', spec,
              ...(ref ? { ownerView: { who: ref, spec } } : {}),
            });
            continue;
          }
          cases.push({ kind: 'read', cls: isExport ? 'export' : 'own-access', resource, route, actor: a, expected, action, relation: 'collection', spec });
          // List filtering: the list must not contain records the actor may not read.
          if (itemGet && route.method === 'GET') {
            const actorItem = fillRoute(itemGet, a, resource.name);
            for (const o of available) {
              if (o === a || o.role === 'anonymous') continue;
              const rel = relationTo(a, o);
              if (expectedAllowed(resource, a.role, 'read', rel)) continue;
              const ownerItem = fillRoute(itemGet, o, resource.name);
              if (!ownerItem) continue;
              const fid = ownerItem.values[lastParam(itemGet)!];
              cases.push({
                kind: 'list', cls: 'list-filter', resource, route, actor: a, owner: o, expected: false, action, relation: rel, spec,
                ownerView: { who: o, spec: ownerItem.spec },
                ...(actorItem ? { ownView: actorItem.spec, ownValue: actorItem.values[lastParam(itemGet)!] } : {}),
                ...(fid !== undefined ? { foreign: fid } : {}),
              });
            }
          }
        }
        continue;
      }

      // ---------------- Item routes (addressed by id) ----------------
      const owners = available.filter((o) => o.role !== 'anonymous' && fillRoute(route, o, resource.name) !== null);
      if (owners.length === 0) {
        for (const a of available) untested(resource, route, a, `no identity declares its own value for ${params.map((p) => `"${p}"`).join(', ')} (add it under params/objects; values are never invented)`);
        continue;
      }
      const lp = lastParam(route)!;
      for (const a of available) {
        const actorOwn = a.role === 'anonymous' ? null : fillRoute(route, a, resource.name);
        for (const o of owners) {
          const ownerFill = fillRoute(route, o, resource.name)!;
          const rel = relationTo(a, o);
          const expected = expectedAllowed(resource, a.role, action, rel);
          const foreign = ownerFill.values[lp];
          const base: Omit<Case, 'kind' | 'cls' | 'spec'> = {
            resource, route, actor: a, owner: o, expected, action, relation: rel,
            ...(foreign !== undefined ? { foreign } : {}),
            ...(actorOwn ? { ownView: actorOwn.spec, ownValue: actorOwn.values[lp] } : {}),
            ...(readBack ? { readBack } : {}),
            ...(createRoute ? { create: createRoute } : {}),
          };
          if (action === 'read') {
            const cls = rel === 'own' ? 'own-access' : classify(a, resource, rel, expected, isExport);
            cases.push({ ...base, kind: 'read', cls, spec: ownerFill.spec, ownerView: { who: o, spec: ownerFill.spec } });
            // Nested ids: the actor's own parent ids with the owner's child id.
            if (rel !== 'own' && !expected && actorOwn && params.length >= 2) {
              const mixed = fillRoute(route, a, resource.name, { [lp]: ownerFill.values[lp]! });
              if (mixed && mixed.spec.path !== ownerFill.spec.path && mixed.spec.path !== actorOwn.spec.path) {
                cases.push({ ...base, kind: 'read', cls: 'nested-id', spec: mixed.spec, ownerView: { who: o, spec: ownerFill.spec } });
              }
            }
            continue;
          }
          // Writes (stateful only; the gate above already ensured it).
          if (rel === 'own') {
            if (route.method === 'PATCH' || route.method === 'PUT') {
              if (!readBack) {
                untested(resource, route, a, 'no GET route for the same record in this resource to read the result back', { testClass: 'mass-assignment' });
                continue;
              }
              if (expected) cases.push({ ...base, kind: 'mass-update', cls: 'mass-assignment', spec: ownerFill.spec });
            }
            continue;
          }
          if (expected) {
            cells.push({
              resource: resource.name, route: route.label, identity: a.name, role: a.role, action, testClass: 'cross-write', target: o.name,
              expected: 'allow', verdict: 'untested', reason: 'allowed writes on another identity\'s record are not exercised (only the denials are tested)',
            });
            continue;
          }
          const cls: AuthzTestClass = route.method === 'DELETE' ? 'cross-delete' : 'cross-write';
          if (!readBack) {
            untested(resource, route, a, 'no GET route for the same record in this resource to read the result back', { testClass: cls, target: o.name, expected: 'deny' });
            continue;
          }
          if (route.method === 'DELETE') {
            if (!createRoute || !resource.body) {
              untested(resource, route, a, 'a delete is only tried on a record created for the test: the resource needs a POST collection route and a sample "body"', { testClass: cls, target: o.name, expected: 'deny' });
              continue;
            }
            cases.push({ ...base, kind: 'delete-cross', cls, spec: ownerFill.spec });
            continue;
          }
          if (route.method === 'PATCH' || route.method === 'PUT') cases.push({ ...base, kind: 'write-cross', cls, spec: ownerFill.spec });
          else untested(resource, route, a, `${route.method} on a record is not exercised`, { testClass: cls, target: o.name });
        }
      }
    }
  }

  planGraphql(input, available, cases, cells);

  const uncovered: string[] = [];
  const seen = new Set<string>();
  for (const r of input.routes) {
    const key = `${r.method.toUpperCase()} ${normalizePattern(r.path)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const covered = policy.resources.some((res) => res.routes.some((pr) => routeMatches(pr, r.method, r.path)));
    const gql = /(?:^|\/)graphql$/i.test(r.path);
    if (!covered && !gql) uncovered.push(key);
  }
  return { cases, cells, uncovered };
}

function normalizeLabel(label: string): string {
  const m = /^\s*([A-Za-z]+)\s+(\S+)/.exec(label);
  if (!m) return label;
  return `${m[1]!.toUpperCase()} ${normalizePattern(m[2]!.split('?')[0]!)}`;
}

function planBatch(resource: PolicyResource, route: PolicyRoute, available: Who[], itemGet: PolicyRoute | undefined, cases: Case[], cells: AuthzCell[]): void {
  const field = route.batchField ?? routeParams(route).find((p) => ID_LIST_PARAM.test(p)) ?? 'ids';
  const push = (a: Who, reason: string) =>
    cells.push({ resource: resource.name, route: route.label, identity: a.name, role: a.role, action: 'read', testClass: 'batch', expected: 'deny', verdict: 'untested', reason });
  if (!itemGet) {
    for (const a of available) push(a, 'no GET item route in this resource, so the owner\'s record cannot be read for comparison');
    return;
  }
  const lp = lastParam(itemGet)!;
  for (const a of available) {
    const own = a.role === 'anonymous' ? null : fillRoute(itemGet, a, resource.name);
    for (const o of available) {
      if (o === a || o.role === 'anonymous') continue;
      const rel = relationTo(a, o);
      if (expectedAllowed(resource, a.role, 'read', rel)) continue;
      const ownerItem = fillRoute(itemGet, o, resource.name);
      if (!ownerItem) continue;
      const theirs = ownerItem.values[lp]!;
      const list = own ? [own.values[lp]!, theirs] : [theirs];
      const spec: Spec = route.batchField
        ? { method: route.method, path: route.path, body: { [field]: list } }
        : (() => {
            const f = fillRoute(route, a, resource.name, { [field]: list.join(',') });
            return f ? f.spec : { method: route.method, path: route.path, query: { [field]: list.join(',') } };
          })();
      cases.push({
        kind: 'list', cls: 'batch', resource, route, actor: a, owner: o, expected: false, action: 'read', relation: rel, spec,
        ownerView: { who: o, spec: ownerItem.spec }, foreign: theirs,
        ...(own ? { ownView: own.spec, ownValue: own.values[lp] } : {}),
      });
    }
  }
}

const INTROSPECTION_QUERY = 'query DeployReadyIntrospectionProbe { __schema { queryType { name } } }';

function planGraphql(input: AuthzEngineInput, available: Who[], cases: Case[], cells: AuthzCell[]): void {
  const g = input.policy.graphql;
  const discovered = input.routes.find((r) => /(?:^|\/)graphql$/i.test(r.path))?.path;
  const endpoint = g?.endpoint ?? discovered;
  if (!endpoint || input.onlyRoute && normalizeLabel(input.onlyRoute) !== `POST ${endpoint}`) return;
  const route: PolicyRoute = { method: 'POST', path: endpoint, label: `POST ${endpoint}` };
  const pseudo: PolicyResource = { name: 'graphql', routes: [route], access: {}, tenantScoped: false };
  const gate = matchRoutePattern(input.unsafeRoutes ?? [], 'POST', endpoint) ? 'listed in unsafeRoutes' : input.safetyLevel === 'passive' ? 'safety level "passive" sends no active requests' : null;
  const anon = available.find((a) => a.role === 'anonymous');
  const expected = (g?.introspection ?? 'deny') === 'allow';
  if (anon) {
    const spec: Spec = { method: 'POST', path: endpoint, body: { query: INTROSPECTION_QUERY } };
    if (gate) cells.push({ resource: 'graphql', route: route.label, identity: anon.name, role: anon.role, action: 'read', testClass: 'graphql-introspection', expected: expected ? 'allow' : 'deny', verdict: 'untested', reason: gate });
    else cases.push({ kind: 'gql-introspection', cls: 'graphql-introspection', resource: pseudo, route, actor: anon, expected, action: 'read', relation: 'collection', spec });
  }
  for (const q of g?.queries ?? []) {
    const resource = input.policy.resources.find((r) => r.name === q.resource);
    const qRoute: PolicyRoute = { method: 'POST', path: endpoint, label: `POST ${endpoint} (${q.resource} by ${q.variable})` };
    if (!resource) {
      cells.push({ resource: q.resource, route: qRoute.label, identity: '*', role: '*', action: 'read', testClass: 'graphql-id', expected: 'deny', verdict: 'untested', reason: `no policy resource named "${q.resource}"` });
      continue;
    }
    const idOf = (w: Who): string | undefined => {
      const v = w.provider?.objects?.[resource.name]?.[q.param] ?? w.provider?.params?.[q.param];
      return v === undefined ? undefined : String(v);
    };
    const mk = (id: string): Spec => ({ method: 'POST', path: endpoint, body: { query: q.query, variables: { [q.variable]: id } } });
    const owners = available.filter((o) => o.role !== 'anonymous' && idOf(o) !== undefined);
    for (const a of available) {
      for (const o of owners) {
        if (o === a) continue;
        const rel = relationTo(a, o);
        const exp = expectedAllowed(resource, a.role, 'read', rel);
        if (gate) {
          cells.push({ resource: resource.name, route: qRoute.label, identity: a.name, role: a.role, action: 'read', testClass: 'graphql-id', target: o.name, expected: exp ? 'allow' : 'deny', verdict: 'untested', reason: gate });
          continue;
        }
        const own = idOf(a);
        cases.push({
          kind: 'read', cls: 'graphql-id', resource, route: qRoute, actor: a, owner: o, expected: exp, action: 'read', relation: rel,
          spec: mk(idOf(o)!), ownerView: { who: o, spec: mk(idOf(o)!) }, foreign: idOf(o)!,
          ...(own !== undefined && a.role !== 'anonymous' ? { ownView: mk(own), ownValue: own } : {}),
        });
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Dry run
// ---------------------------------------------------------------------------

const COST: Record<CaseKind, number> = {
  read: 6, list: 5, 'write-cross': 4, 'delete-cross': 5, 'mass-update': 4, 'mass-create': 4, 'create-denied': 2, 'gql-introspection': 1,
};

/** List the matrix plan without sending anything. */
export function previewAuthz(input: AuthzEngineInput): { lines: string[]; upperBound: number; matrix: AuthzMatrix } {
  const plan = planAuthz(input);
  const lines: string[] = [`Authorization matrix dry run — safety level "${input.safetyLevel}", policy ${input.policySource ?? '(config)'}. Nothing below is sent.`];
  let n = 0;
  for (const c of plan.cases) {
    const cost = c.expected ? 1 : COST[c.kind];
    n += cost;
    const target = c.owner ? ` → ${c.owner.name}'s record` : '';
    lines.push(`  [${c.cls}] ${c.actor.name} (${c.actor.role})${target}: ${specLabel(c.spec)}  expect ${c.expected ? 'allow' : 'deny'}  (≤${cost} request${cost === 1 ? '' : 's'})`);
  }
  const skipped = plan.cells.filter((c) => c.verdict === 'untested');
  if (skipped.length) {
    lines.push('Not tested:');
    for (const c of skipped) lines.push(`  ${c.route} as ${c.identity}: ${c.reason}`);
  }
  if (plan.uncovered.length) lines.push(`Discovered routes not covered by the policy: ${plan.uncovered.join(', ')}`);
  const max = input.maxRequests ?? 200;
  lines.push(`At most ${Math.min(n, max)} request(s) (upper bound ${n}; request budget ${max}).`);
  const cells = [...plan.cases.map((c) => toCell(c, 'untested', 'dry run: planned, not sent')), ...plan.cells];
  return { lines, upperBound: n, matrix: buildMatrix(input, cells, plan.uncovered, 0) };
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

function toCell(c: Case, verdict: AuthzCellVerdict, reason: string, statement?: string): AuthzCell {
  return {
    resource: c.resource.name,
    route: c.route.label,
    identity: c.actor.name,
    role: c.actor.role,
    action: c.action,
    testClass: c.cls,
    ...(c.owner && c.owner.name !== c.actor.name ? { target: c.owner.name } : {}),
    expected: c.expected ? 'allow' : 'deny',
    verdict,
    reason,
    ...(statement ? { statement } : {}),
    request: specLabel(c.spec),
  };
}

function buildMatrix(input: AuthzEngineInput, cells: AuthzCell[], uncovered: string[], sent: number): AuthzMatrix {
  const summary: Record<AuthzCellVerdict, number> = { 'allowed-as-expected': 0, 'denied-as-expected': 0, violation: 0, inconclusive: 0, untested: 0 };
  for (const c of cells) summary[c.verdict]++;
  return {
    policySource: input.policySource ?? 'config',
    safetyLevel: input.safetyLevel,
    identities: input.identities.map((i) => ({
      name: i.name, role: i.role, ...(i.tenant ? { tenant: i.tenant } : {}), available: Boolean(i.provider), ...(i.unavailable ? { reason: i.unavailable } : {}),
    })),
    cells,
    summary,
    uncoveredRoutes: uncovered,
    requestsSent: sent,
    ...(input.problems?.length ? { problems: input.problems } : {}),
  };
}

function is2xx(s: number): boolean {
  return s >= 200 && s < 300;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function asRecord(v: unknown): Record<string, unknown> | null {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const r = v as Record<string, unknown>;
  // Unwrap a single { data: {...} } envelope.
  const keys = Object.keys(r);
  if (keys.length === 1 && typeof r[keys[0]!] === 'object' && r[keys[0]!] !== null && !Array.isArray(r[keys[0]!]) && /^(?:data|result|item|record)$/i.test(keys[0]!)) {
    return r[keys[0]!] as Record<string, unknown>;
  }
  return r;
}

function createdId(text: string): string | undefined {
  const rec = asRecord(parseJson(text));
  if (!rec) return undefined;
  for (const [k, v] of Object.entries(rec)) {
    if ((k === 'id' || k === '_id' || k === 'uuid' || /Id$/.test(k)) && (typeof v === 'string' || typeof v === 'number') && !/^(?:owner|user|tenant|org|organization|account)/i.test(k)) return String(v);
  }
  return undefined;
}

function describe(w: Who): string {
  if (w.role === 'anonymous') return 'An anonymous visitor (no credentials)';
  return `User "${w.name}" (role ${w.role}${w.tenant ? `, tenant ${w.tenant}` : ''})`;
}

function ownerDesc(w: Who, rel: Relation): string {
  return `"${w.name}" (role ${w.role}${rel === 'other-tenant' && w.tenant ? `, tenant ${w.tenant}` : ''})`;
}

function ruleFor(c: Case): string {
  if (c.cls === 'graphql-introspection') return 'graphql-introspection';
  if (c.cls === 'cross-write' || c.cls === 'cross-delete') return 'authz-unauthorized-write';
  if (c.cls === 'mass-assignment') return 'authz-mass-assignment';
  if (c.cls === 'privilege-escalation') return 'authz-privilege-escalation';
  if (c.actor.role === 'anonymous') return 'authz-missing-auth';
  if (c.cls === 'vertical') return 'authz-bfla';
  if (c.relation === 'other-tenant') return 'authz-cross-tenant';
  if (!c.owner) return 'authz-bfla';
  if (levelFor(c.resource, c.actor.role) === 'none') return 'authz-bfla';
  return 'authz-bola';
}

function statementFor(c: Case, extra: string): string {
  const actor = describe(c.actor);
  const req = specLabel(c.spec);
  const res = c.resource.name;
  const owner = c.owner ? ownerDesc(c.owner, c.relation) : '';
  const tenant = c.relation === 'other-tenant' && c.owner?.tenant ? ` in another tenant (${c.owner.tenant})` : '';
  switch (c.cls) {
    case 'missing-auth':
      return `${actor} could read ${res}${c.owner ? ` belonging to ${owner}` : ''} via ${req}, which the policy does not open to anonymous visitors.${extra}`;
    case 'vertical':
      return `${actor} could use ${req} (${res}), which the policy reserves for ${allowedRoles(c.resource, c.action).join(', ') || 'no role'}.${extra}`;
    case 'cross-tenant':
      return `${actor} could read ${res} of ${owner}${tenant} via ${req}.${extra}`;
    case 'nested-id':
      return `${actor} could read ${res} of ${owner}${tenant} by putting its id under the caller's own parent id (${req}).${extra}`;
    case 'list-filter':
      return `${actor}'s ${res} list (${req}) includes records of ${owner}${tenant}.${extra}`;
    case 'batch':
      return `${actor} could read ${res} of ${owner}${tenant} by adding its id to the batch request ${req}.${extra}`;
    case 'export':
      return `${actor} could export ${res}${c.owner ? ` of ${owner}${tenant}` : ''} via ${req}, which the policy does not allow.${extra}`;
    case 'graphql-id':
      return `${actor} could read ${res} of ${owner}${tenant} through the GraphQL query by id (${req}).${extra}`;
    case 'graphql-introspection':
      return `Anyone, without logging in, could download the GraphQL schema (introspection) at ${req}.${extra}`;
    case 'cross-write':
      return `${actor} could change ${res} of ${owner}${tenant} (${req}).${extra}`;
    case 'cross-delete':
      return `${actor} could delete ${res} of ${owner}${tenant} (${req}).${extra}`;
    default:
      return `${actor} could read ${res} of ${owner}${tenant} via ${req}.${extra}`;
  }
}

interface Violation {
  case: Case;
  cell: AuthzCell;
  rule: string;
  proof: { request: Spec; who: Who; status: number; body: string; matched: string[]; control: string };
}

function curl(spec: Spec, w: Who, baseUrl: string | undefined): string {
  const q = spec.query && Object.keys(spec.query).length ? `?${new URLSearchParams(Object.entries(spec.query).map(([k, v]): [string, string] => [k, String(v)])).toString()}` : '';
  const url = absoluteUrl(baseUrl, spec.path + q);
  const parts = ['curl', '-i'];
  if (spec.method !== 'GET') parts.push('-X', spec.method);
  if (w.role !== 'anonymous') parts.push('-H', `"${authPlaceholder(w.name)}"`);
  if (spec.body !== undefined) parts.push('-H', "'Content-Type: application/json'", '--data', `'${JSON.stringify(spec.body).replace(/'/g, `'\\''`)}'`);
  parts.push(`'${url.replace(/'/g, `'\\''`)}'`);
  return redact(parts.join(' '));
}

const PRIV_ROLE_KEY = /^(?:role|roles|user_?role|is_?admin|admin|is_?staff|is_?superuser|superuser|permissions|scopes|access_?level)$/i;
const OWNER_KEY = /^(?:owner_?id|owner|user_?id|created_?by|author_?id|account_?id)$/i;
const TENANT_KEY = /^(?:tenant_?id|tenant|org_?id|organization_?id|workspace_?id|team_?id|company_?id)$/i;
const MONEY_KEY = /^(?:price|unit_?price|amount|total|balance|credits?|discount|cost|plan|tier)$/i;
const FLAG_KEY = /^(?:is_?verified|verified|email_?verified|approved|is_?approved|is_?paid|paid)$/i;
const PROBE_FIELDS = ['title', 'name', 'description', 'note', 'notes', 'label', 'comment', 'subject', 'memo', 'text'];

interface Injection {
  field: string;
  value: string | number | boolean | string[];
  cls: 'privilege-escalation' | 'mass-assignment';
}

function injectionsFor(before: Record<string, unknown>, others: Who[], self: Who): Injection[] {
  const out: Injection[] = [];
  const otherUser = others.map(userIdOf).find((v) => v !== undefined && v !== userIdOf(self));
  const otherTenant = others.map((o) => o.tenant).find((t) => t !== undefined && t !== self.tenant);
  for (const [k, v] of Object.entries(before)) {
    if (PRIV_ROLE_KEY.test(k)) {
      if (typeof v === 'boolean') out.push({ field: k, value: true, cls: 'privilege-escalation' });
      else if (Array.isArray(v)) out.push({ field: k, value: [...(v as unknown[]).map(String), 'admin'], cls: 'privilege-escalation' });
      else if (typeof v === 'string' && v.toLowerCase() !== 'admin') out.push({ field: k, value: 'admin', cls: 'privilege-escalation' });
    } else if (OWNER_KEY.test(k) && otherUser !== undefined && typeof v !== 'object') {
      out.push({ field: k, value: typeof v === 'number' && /^\d+$/.test(otherUser) ? Number(otherUser) : otherUser, cls: 'mass-assignment' });
    } else if (TENANT_KEY.test(k) && otherTenant !== undefined && typeof v !== 'object') {
      out.push({ field: k, value: typeof v === 'number' && /^\d+$/.test(otherTenant) ? Number(otherTenant) : otherTenant, cls: 'mass-assignment' });
    } else if (MONEY_KEY.test(k) && typeof v === 'number') {
      out.push({ field: k, value: v === 0.01 ? 0.02 : 0.01, cls: 'mass-assignment' });
    } else if (FLAG_KEY.test(k) && v === false) {
      out.push({ field: k, value: true, cls: 'mass-assignment' });
    }
  }
  return out;
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export interface AuthzRunResult {
  matrix: AuthzMatrix;
  findings: Finding[];
}

export async function runAuthz(input: AuthzEngineInput, http: HttpFn): Promise<AuthzRunResult> {
  const plan = planAuthz(input);
  const budget = input.maxRequests ?? 200;
  const ignoredFields = input.ignoredFields ?? [];
  let sent = 0;
  const cells: AuthzCell[] = [...plan.cells];
  const violations: Violation[] = [];
  const cache = new Map<string, ActiveResponse[]>();
  const anon = input.identities.map(who).find((w) => w.role === 'anonymous' && w.provider);

  const send = async (w: Who, spec: Spec): Promise<ActiveResponse> => {
    if (sent >= budget) throw new ActiveBudgetError(budget);
    sent++;
    const headers = { ...(await w.provider!.headers()) };
    if (spec.body !== undefined) headers['Content-Type'] = 'application/json';
    input.onSend?.(w.name, spec.method, specLabel(spec));
    return http({ method: spec.method, path: spec.path, query: spec.query, body: spec.body, headers });
  };
  const baselines = async (w: Who, spec: Spec, n: number): Promise<ActiveResponse[]> => {
    const key = JSON.stringify([w.name, spec]);
    const list = cache.get(key) ?? [];
    while (list.length < n) list.push(await send(w, spec));
    cache.set(key, list);
    return list;
  };
  const record = (c: Case, verdict: AuthzCellVerdict, reason: string, proof?: Violation['proof'], extra = '', cls?: AuthzTestClass): void => {
    const cc = cls ? { ...c, cls } : c;
    const statement = verdict === 'violation' ? statementFor(cc, extra) : undefined;
    const cell = toCell(cc, verdict, reason, statement);
    cells.push(cell);
    if (verdict === 'violation' && proof) violations.push({ case: cc, cell, rule: ruleFor(cc), proof });
  };

  // Reads first, then writes, then the ones that change the caller's own record.
  const order: CaseKind[] = ['gql-introspection', 'read', 'list', 'create-denied', 'write-cross', 'delete-cross', 'mass-create', 'mass-update'];
  const sorted = [...plan.cases].sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind));
  for (let i = 0; i < sorted.length; i++) {
    const c = sorted[i]!;
    try {
      await runCase(c);
    } catch (err) {
      if (!(err instanceof ActiveBudgetError)) {
        record(c, 'inconclusive', `request failed: ${(err as Error).message}`);
        continue;
      }
      for (const rest of sorted.slice(i)) record(rest, 'untested', `request budget of ${budget} used up`);
      break;
    }
  }

  async function runCase(c: Case): Promise<void> {
    switch (c.kind) {
      case 'gql-introspection': {
        const r = await send(c.actor, c.spec);
        const schema = (asRecord(parseJson(r.bodyText)) as { __schema?: { queryType?: unknown } } | null)?.__schema;
        const exposed = is2xx(r.status) && schema !== undefined && schema !== null && typeof schema === 'object';
        if (!exposed) return record(c, c.expected ? 'inconclusive' : 'denied-as-expected', `introspection not answered (HTTP ${r.status}${is2xx(r.status) ? ', no __schema in the answer' : ''})`);
        if (c.expected) return record(c, 'allowed-as-expected', `HTTP ${r.status} with a schema; the policy allows introspection`);
        return record(c, 'violation', `HTTP ${r.status} returned data.__schema to a request without credentials`, {
          request: c.spec, who: c.actor, status: r.status, body: r.bodyText, matched: [], control: 'Introspection is a read-only query; the answer contained the schema root.',
        });
      }
      case 'read':
        return runRead(c);
      case 'list':
        return runList(c);
      case 'create-denied':
        return runCreateDenied(c);
      case 'write-cross':
        return runWriteCross(c);
      case 'delete-cross':
        return runDeleteCross(c);
      case 'mass-update':
        return runMassUpdate(c);
      case 'mass-create':
        return runMassCreate(c);
    }
  }

  function verdictOf(c: Case, res: AuthzResult, r: ActiveResponse, ownerOk: boolean): { verdict: AuthzCellVerdict; reason: string } {
    switch (res.verdict) {
      case 'confirmed-vulnerable':
        return { verdict: 'violation', reason: res.reason };
      case 'verified-denied':
        return { verdict: 'denied-as-expected', reason: res.reason };
      case 'suspected':
        return { verdict: 'inconclusive', reason: `Suspected, not proven: ${res.reason}` };
      case 'intentionally-public':
        return { verdict: 'inconclusive', reason: `${res.reason} The policy says this identity may not read it: protect it, or open it in the policy.` };
      default:
        if (!ownerOk && (r.status === 401 || r.status === 403)) {
          return { verdict: 'denied-as-expected', reason: `Refused with HTTP ${r.status}${c.ownerView ? ' (the allowed identity\'s own request failed, so the body could not be compared field by field)' : ''}.` };
        }
        return { verdict: 'inconclusive', reason: res.reason };
    }
  }

  async function runRead(c: Case): Promise<void> {
    if (c.expected) {
      const r = (await baselines(c.actor, c.spec, 1))[0]!;
      if (is2xx(r.status)) return record(c, 'allowed-as-expected', `HTTP ${r.status}`);
      if (r.status === 401 || r.status === 403) return record(c, 'inconclusive', `the policy allows this but the server refused (HTTP ${r.status}): check the identity's credential or the policy`);
      return record(c, 'inconclusive', `HTTP ${r.status}: neither data nor a refusal`);
    }
    const r = await send(c.actor, c.spec);
    const owner = c.ownerView ? await baselines(c.ownerView.who, c.ownerView.spec, 2) : [];
    const own = c.ownView ? (await baselines(c.actor, c.ownView, 2)).filter((x) => is2xx(x.status)) : [];
    const base = {
      tampered: r,
      ownBaselines: own,
      ownerBaselines: owner,
      foreignValue: c.foreign ?? '\u0000no-id',
      ...(c.ownValue !== undefined ? { ownValue: c.ownValue } : {}),
      policy: { ignoredFields },
    };
    let res = assessAuthz(base);
    let anonR: ActiveResponse | undefined;
    if (res.wantsAnonymousControl && anon && c.actor.role !== 'anonymous' && sent < budget) {
      anonR = await send(anon, c.spec);
      res = assessAuthz({ ...base, anonymous: anonR });
    }
    const ownerOk = owner.some((o) => is2xx(o.status));
    const v = verdictOf(c, res, r, ownerOk);
    const fields = res.disclosed.length ? ` Disclosed: ${res.disclosed.map((d) => `${d.path}${d.sensitive ? ' (sensitive)' : ''} = ${d.masked}`).join(', ')}.` : '';
    record(c, v.verdict, v.reason, v.verdict === 'violation' ? {
      request: c.spec, who: c.actor, status: r.status, body: r.bodyText, matched: res.matchedValues,
      control: `${c.ownerView ? `${c.ownerView.who.name} (allowed) requesting the same record: HTTP ${owner.map((o) => o.status).join('/')}, compared field by field. ` : ''}${anonR ? `Without credentials: HTTP ${anonR.status}. ` : ''}${res.method}`,
    } : undefined, fields);
  }

  async function runList(c: Case): Promise<void> {
    const r = await send(c.actor, c.spec);
    const owner = await baselines(c.ownerView!.who, c.ownerView!.spec, 2);
    const own = c.ownView ? (await baselines(c.actor, c.ownView, 2)).filter((x) => is2xx(x.status)) : [];
    if (!owner.some((o) => is2xx(o.status))) return record(c, 'inconclusive', `${c.owner!.name}'s own record could not be read (HTTP ${owner.map((o) => o.status).join('/')}), so there is nothing to look for`);
    const res = assessAuthz({ tampered: r, ownBaselines: own, ownerBaselines: owner, foreignValue: c.foreign ?? '\u0000no-id', ...(c.ownValue !== undefined ? { ownValue: c.ownValue } : {}), policy: { ignoredFields } });
    if (res.verdict === 'confirmed-vulnerable') {
      const fields = ` Disclosed: ${res.disclosed.map((d) => `${d.path}${d.sensitive ? ' (sensitive)' : ''} = ${d.masked}`).join(', ')}.`;
      return record(c, 'violation', res.reason, {
        request: c.spec, who: c.actor, status: r.status, body: r.bodyText, matched: res.matchedValues,
        control: `${c.owner!.name}'s own record (${specLabel(c.ownerView!.spec)}) read as ${c.owner!.name}: HTTP ${owner.map((o) => o.status).join('/')}. ${res.method}`,
      }, fields);
    }
    if (res.verdict === 'suspected') return record(c, 'inconclusive', `Suspected, not proven: ${res.reason}`);
    if (!is2xx(r.status)) {
      return r.status === 401 || r.status === 403
        ? record(c, 'denied-as-expected', `Refused with HTTP ${r.status}.`)
        : record(c, 'inconclusive', `HTTP ${r.status}: the request did not return a list`);
    }
    if (res.markerCount === 0) return record(c, 'inconclusive', `${c.owner!.name}'s record has no value that is unique to it, so its absence cannot be shown`);
    return record(c, 'denied-as-expected', `HTTP ${r.status}; none of ${c.owner!.name}'s ${res.markerCount} private value(s) appear in the answer.`);
  }

  async function runCreateDenied(c: Case): Promise<void> {
    const r = await send(c.actor, c.spec);
    if (r.status === 401 || r.status === 403) return record(c, 'denied-as-expected', `Refused with HTTP ${r.status}.`);
    if (!is2xx(r.status)) return record(c, 'inconclusive', `HTTP ${r.status}: neither created nor refused`);
    const id = createdId(r.bodyText);
    const ref = input.identities.map(who).find((w) => w.provider && w.role !== 'anonymous' && expectedAllowed(c.resource, w.role, 'read', 'other'));
    const back = id && ref && c.readBack ? c.readBack(ref, id) : null;
    if (!back || !ref) return record(c, 'inconclusive', `HTTP ${r.status}, but the created record could not be read back to prove it exists`);
    const rb = await send(ref, back);
    if (is2xx(rb.status)) {
      return record(c, 'violation', `HTTP ${r.status} and the record ${id} exists afterwards (read back by ${ref.name}: HTTP ${rb.status}).`, {
        request: c.spec, who: c.actor, status: r.status, body: r.bodyText, matched: [], control: `${ref.name} read the created record back: HTTP ${rb.status} (${specLabel(back)}).`,
      }, ` A record was created (id ${id}).`);
    }
    return record(c, 'inconclusive', `HTTP ${r.status}, but the record could not be read back (HTTP ${rb.status})`);
  }

  async function runWriteCross(c: Case): Promise<void> {
    const o = c.owner!;
    const readSpec = c.readBack!(o);
    if (!readSpec) return record(c, 'untested', 'the owner\'s record has no readable GET route');
    const before = await send(o, readSpec);
    const rec = is2xx(before.status) ? asRecord(parseJson(before.bodyText)) : null;
    if (!rec) return record(c, 'inconclusive', `the owner could not read its own record first (HTTP ${before.status})`);
    const field = PROBE_FIELDS.find((f) => typeof rec[f] === 'string') ?? Object.keys(rec).find((k) => typeof rec[k] === 'string' && !/id$/i.test(k) && !PRIV_ROLE_KEY.test(k));
    if (!field) return record(c, 'untested', 'the record has no text field that can be changed harmlessly');
    const marker = `deployready-probe-${randomBytes(4).toString('hex')}`;
    const body = c.route.method === 'PUT' ? { ...rec, [field]: marker } : { [field]: marker };
    const spec = { ...c.spec, body };
    const w = await send(c.actor, spec);
    const after = await send(o, readSpec);
    const now = is2xx(after.status) ? asRecord(parseJson(after.bodyText)) : null;
    const changed = now !== null && now[field] === marker;
    if (changed) {
      // Best effort: put the owner's value back (the owner may change its own record).
      try {
        await send(o, { method: c.route.method === 'PUT' ? 'PUT' : 'PATCH', path: c.spec.path, ...(c.spec.query ? { query: c.spec.query } : {}), body: c.route.method === 'PUT' ? rec : { [field]: rec[field] } });
      } catch {
        /* budget or error: the environment is disposable */
      }
      return record(c, 'violation', `HTTP ${w.status}; afterwards ${o.name} read "${field}" = the probe value written by ${c.actor.name}.`, {
        request: spec, who: c.actor, status: w.status, body: w.bodyText, matched: [], control: `${o.name} read its record back (${specLabel(readSpec)}): HTTP ${after.status}, "${field}" changed to the probe value.`,
      }, ` Field "${field}" was overwritten.`);
    }
    if (!is2xx(after.status)) return record(c, 'inconclusive', `the owner could not read its record afterwards (HTTP ${after.status})`);
    return record(c, 'denied-as-expected', `HTTP ${w.status}; ${o.name}'s "${field}" is unchanged when read back.`);
  }

  async function runDeleteCross(c: Case): Promise<void> {
    const o = c.owner!;
    const created = await send(o, { method: 'POST', path: fillRoute(c.create!, o, c.resource.name)?.spec.path ?? c.create!.path, body: c.resource.body });
    const id = is2xx(created.status) ? createdId(created.bodyText) : undefined;
    if (!id) return record(c, 'inconclusive', `the owner could not create a disposable record to try the delete on (HTTP ${created.status}${is2xx(created.status) ? ', no id in the answer' : ''})`);
    const lp = lastParam(c.route)!;
    const target = fillRoute(c.route, o, c.resource.name, { [lp]: id });
    const readSpec = c.readBack!(o, id);
    if (!target || !readSpec) return record(c, 'inconclusive', 'the created record could not be addressed');
    const control = await send(o, readSpec);
    if (!is2xx(control.status)) return record(c, 'inconclusive', `the owner could not read the record it just created (HTTP ${control.status})`);
    const d = await send(c.actor, target.spec);
    const after = await send(o, readSpec);
    const cc = { ...c, spec: target.spec };
    if (after.status === 404 || after.status === 410) {
      return record(cc, 'violation', `HTTP ${d.status}; afterwards the owner gets HTTP ${after.status} for its record.`, {
        request: target.spec, who: c.actor, status: d.status, body: d.bodyText, matched: [], control: `${o.name} created the record (id ${id}) and could read it (HTTP ${control.status}) before; after ${c.actor.name}'s DELETE: HTTP ${after.status}.`,
      }, ' The record was deleted.');
    }
    if (is2xx(after.status)) return record(cc, 'denied-as-expected', `HTTP ${d.status}; the record still exists for its owner (HTTP ${after.status}).`);
    return record(cc, 'inconclusive', `HTTP ${d.status}; the owner then got HTTP ${after.status}`);
  }

  function others(self: Who): Who[] {
    return input.identities.map(who).filter((w) => w.provider && w.name !== self.name && w.role !== 'anonymous');
  }

  async function runMassUpdate(c: Case): Promise<void> {
    const readSpec = c.readBack!(c.actor);
    if (!readSpec) return record(c, 'untested', 'the record has no readable GET route');
    const before = await send(c.actor, readSpec);
    const rec = is2xx(before.status) ? asRecord(parseJson(before.bodyText)) : null;
    if (!rec) return record(c, 'inconclusive', `the identity could not read its own record first (HTTP ${before.status})`);
    const inj = injectionsFor(rec, others(c.actor), c.actor);
    if (!inj.length) return record(c, 'untested', 'the record has no role, owner, tenant, price or verification field to try');
    const body: Record<string, unknown> = c.route.method === 'PUT' ? { ...rec } : {};
    for (const i of inj) body[i.field] = i.value;
    const spec = { ...c.spec, body };
    const w = await send(c.actor, spec);
    let after = await send(c.actor, readSpec);
    if (!is2xx(after.status)) {
      // The owner field may now point elsewhere: read it as an identity that may read every record.
      const ref = others(c.actor).find((r) => expectedAllowed(c.resource, r.role, 'read', 'other'));
      if (ref) after = await send(ref, readSpec);
    }
    const now = is2xx(after.status) ? asRecord(parseJson(after.bodyText)) : null;
    if (!now) return record(c, 'inconclusive', `HTTP ${w.status}; the record could not be read back (HTTP ${after.status})`);
    const stuck = inj.filter((i) => same(now[i.field], i.value) && !same(rec[i.field], i.value));
    // Best effort restore of the original values.
    if (stuck.length) {
      try {
        const restore: Record<string, unknown> = c.route.method === 'PUT' ? { ...rec } : Object.fromEntries(stuck.map((s) => [s.field, rec[s.field]]));
        await send(c.actor, { ...c.spec, body: restore });
      } catch {
        /* disposable environment */
      }
    }
    emitMass(c, spec, w, stuck, inj, `${c.actor.name} read its record back (${specLabel(readSpec)}) before and after: `, 'updates');
  }

  async function runMassCreate(c: Case): Promise<void> {
    if (!c.readBack) return record(c, 'untested', 'no GET item route to read the created record back');
    const path = fillRoute(c.route, c.actor, c.resource.name)?.spec.path ?? c.spec.path;
    const control = await send(c.actor, { method: 'POST', path, body: c.resource.body });
    const cid = is2xx(control.status) ? createdId(control.bodyText) : undefined;
    if (!cid) return record(c, 'inconclusive', `the control create did not return an id (HTTP ${control.status})`);
    const cSpec = c.readBack(c.actor, cid);
    const cRead = cSpec ? await send(c.actor, cSpec) : null;
    const crec = cRead && is2xx(cRead.status) ? asRecord(parseJson(cRead.bodyText)) : null;
    if (!crec) return record(c, 'inconclusive', `the control record could not be read back (HTTP ${cRead?.status ?? 'n/a'})`);
    const inj = injectionsFor(crec, others(c.actor), c.actor);
    if (!inj.length) return record(c, 'untested', 'created records have no role, owner, tenant, price or verification field to try');
    const body = { ...(c.resource.body ?? {}) } as Record<string, unknown>;
    for (const i of inj) body[i.field] = i.value;
    const spec = { method: 'POST', path, body };
    const w = await send(c.actor, spec);
    const id = is2xx(w.status) ? createdId(w.bodyText) : undefined;
    if (!id) {
      return is2xx(w.status)
        ? record(c, 'inconclusive', `HTTP ${w.status} without an id, so the record cannot be read back`)
        : record(c, 'denied-as-expected', `HTTP ${w.status}: the create with extra fields was rejected.`);
    }
    const rSpec = c.readBack(c.actor, id);
    if (!rSpec) return record(c, 'inconclusive', 'the created record could not be addressed');
    let after = await send(c.actor, rSpec);
    if (!is2xx(after.status)) {
      const ref = others(c.actor).find((r) => expectedAllowed(c.resource, r.role, 'read', 'other'));
      if (ref) after = await send(ref, rSpec);
    }
    const now = is2xx(after.status) ? asRecord(parseJson(after.bodyText)) : null;
    if (!now) return record(c, 'inconclusive', `HTTP ${w.status}; the created record could not be read back (HTTP ${after.status})`);
    const stuck = inj.filter((i) => same(now[i.field], i.value) && !same(crec[i.field], i.value));
    emitMass(c, spec, w, stuck, inj, `A control record created with the plain body (id ${cid}) and the probe record (id ${id}) were read back: `, 'creates');
  }

  function emitMass(c: Case, spec: Spec, w: ActiveResponse, stuck: Injection[], tried: Injection[], controlPrefix: string, verb: string): void {
    const cc = { ...c, spec };
    if (!stuck.length) {
      return record(cc, 'denied-as-expected', `HTTP ${w.status}; none of ${tried.map((t) => `"${t.field}"`).join(', ')} took the client's value when read back.`);
    }
    for (const cls of ['privilege-escalation', 'mass-assignment'] as const) {
      const group = stuck.filter((s) => s.cls === cls);
      if (!group.length) continue;
      const list = group.map((s) => `"${s.field}" = ${JSON.stringify(s.value)}`).join(', ');
      const statement =
        cls === 'privilege-escalation'
          ? ` ${describe(c.actor)} could grant itself ${list} on the ${c.resource.name} record it ${verb} (${specLabel(spec)}); the server stored it.`
          : ` ${describe(c.actor)} could set ${list} on the ${c.resource.name} record it ${verb} (${specLabel(spec)}); the server stored the values.`;
      const cell = toCell({ ...cc, cls }, 'violation', `HTTP ${w.status}; read back: ${list}.`, statement.trim());
      cells.push(cell);
      violations.push({
        case: { ...cc, cls }, cell, rule: cls === 'privilege-escalation' ? 'authz-privilege-escalation' : 'authz-mass-assignment',
        proof: { request: spec, who: c.actor, status: w.status, body: w.bodyText, matched: [], control: `${controlPrefix}${list} (the value before was different).` },
      });
    }
  }

  const findings = toFindings(violations, input.baseUrl);
  const matrix = buildMatrix(input, cells, plan.uncovered, sent);
  return { matrix, findings };
}

/** One finding per (rule, route), listing every violating identity pair. */
function toFindings(violations: Violation[], baseUrl: string | undefined): Finding[] {
  const groups = new Map<string, Violation[]>();
  for (const v of violations) {
    const key = `${v.rule}|${v.case.route.method} ${v.case.route.path}`;
    groups.set(key, [...(groups.get(key) ?? []), v]);
  }
  const out: Finding[] = [];
  for (const [, list] of groups) {
    const first = list[0]!;
    const meta = RULE_META[first.rule]!;
    const endpoint = `${first.case.route.method} ${first.case.route.path}`;
    const statements = [...new Set(list.map((v) => v.cell.statement!))];
    const f = makeFinding({
      rule: first.rule,
      title: meta.title,
      severity: meta.severity,
      category: 'security',
      source: 'dynamic',
      endpoint,
      owasp: 'A01:2025',
      cwe: meta.cwe,
      evidence: redact(statements[0]!),
      description: redact(
        [
          ...statements.slice(0, 5),
          statements.length > 5 ? `…and ${statements.length - 5} more cell(s) in the authorization matrix.` : '',
          `Policy: resource "${first.case.resource.name}", route ${first.case.route.label}. Why: ${first.cell.reason}`,
        ].filter(Boolean).join(' '),
      ),
      recommendation: meta.fix,
      proof: {
        request: curl(first.proof.request, first.proof.who, baseUrl),
        status: first.proof.status,
        response: proofBody(maskBody(first.proof.body, first.proof.matched)),
        control: redact(`${first.proof.control} Credentials are named ${authPlaceholder(first.proof.who.name)} (the full Authorization/Cookie header of identity "${first.proof.who.name}").`),
      },
    });
    for (const v of list) v.cell.findingId = f.id;
    out.push(f);
  }
  return out;
}

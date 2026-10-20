import { runActiveScan, type ActiveResponse, type HttpFn } from '../src/active/runner';
import { decodeJwt } from '../src/active/jwt';
import { buildActiveRequests } from '../src/active/requestPlan';
import type { HttpRequestSpec } from '../src/active/types';
import { checkFindings, type BenchCase, type FindingExpectation } from './core';

interface ActiveCaseDef {
  id: string;
  description: string;
  knownGap?: string;
  token: string;
  tokenB?: string;
  requests: HttpRequestSpec[];
  app: HttpFn;
  expected: FindingExpectation[];
}

const VALID_SIGNATURE = 'fakeSignature';

function segment(o: object): string {
  return Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
}

function jwt(claims: object): string {
  return `${segment({ alg: 'HS256', typ: 'JWT' })}.${segment(claims)}.${VALID_SIGNATURE}`;
}

/** The caller's claims, or null when the app would answer 401. */
function authenticate(headers: Record<string, string>, verifySignature: boolean): Record<string, unknown> | null {
  const decoded = decodeJwt((headers.Authorization ?? '').replace('Bearer ', ''));
  if (!decoded) return null;
  if (verifySignature && (decoded.header.alg === 'none' || decoded.signature !== VALID_SIGNATURE)) return null;
  return decoded.payload;
}

const json = (status: number, body: object): ActiveResponse => ({ status, bodyText: JSON.stringify(body) });
const UNAUTHORIZED = json(401, { error: 'unauthorized' });
const FORBIDDEN = json(403, { error: 'forbidden' });
const NOT_FOUND = json(404, { error: 'not found' });

/** Build requests the way a real scan does: route paths go through requestPlan with the acting identity's claims. */
function plan(token: string, ...routePaths: string[]): HttpRequestSpec[] {
  const claims = decodeJwt(token)?.payload ?? {};
  const routes = routePaths.map((path) => ({ method: 'GET', path, file: 'benchmark', guarded: false }));
  return buildActiveRequests(routes, claims);
}

const publicApp: HttpFn = async () => json(200, { ok: true });

const lenientAuthApp: HttpFn = async (req) => (authenticate(req.headers, false) ? json(200, { me: 'ok' }) : UNAUTHORIZED);

const strictAuthApp: HttpFn = async (req) => (authenticate(req.headers, true) ? json(200, { me: 'ok' }) : UNAUTHORIZED);

const publicPlus =
  (protectedApp: HttpFn): HttpFn =>
  async (req) =>
    req.path === '/api/public' ? json(200, { ok: true }) : protectedApp(req);

const publicThenSecure = (token: string): HttpRequestSpec[] => plan(token, '/api/public', '/api/secure');

const userIdOf = (path: string): string | null => /^\/(?:api\/)?users\/([^/]+)$/.exec(path)?.[1] ?? null;
const orgIdOf = (path: string): string | null => /^\/orgs\/([^/]+)\/projects$/.exec(path)?.[1] ?? null;

const usersEchoApp: HttpFn = async (req) => {
  if (!authenticate(req.headers, true)) return UNAUTHORIZED;
  const id = userIdOf(req.path);
  return id === null ? NOT_FOUND : json(200, { id, name: `user ${id}` });
};

const usersNoEchoApp: HttpFn = async (req) => {
  if (!authenticate(req.headers, true)) return UNAUTHORIZED;
  const id = userIdOf(req.path);
  if (id === '1') return json(200, { name: 'Alice', email: 'alice@example.test' });
  if (id === '2') return json(200, { name: 'Bob', email: 'bob@example.test' });
  return NOT_FOUND;
};

const usersIsolatedApp =
  (denied: ActiveResponse): HttpFn =>
  async (req) => {
    const claims = authenticate(req.headers, true);
    if (!claims) return UNAUTHORIZED;
    const id = userIdOf(req.path);
    if (id === null) return NOT_FOUND;
    return id === String(claims.sub) ? json(200, { id, name: `user ${id}` }) : denied;
  };

const productsPublicApp: HttpFn = async (req) => {
  const id = /^\/api\/products\/([^/]+)$/.exec(req.path)?.[1];
  return id ? json(200, { id, name: 'widget' }) : NOT_FOUND;
};

const orgsLeakyApp: HttpFn = async (req) => {
  if (!authenticate(req.headers, true)) return UNAUTHORIZED;
  const org = orgIdOf(req.path);
  return org === null ? NOT_FOUND : json(200, { orgId: org, projects: ['alpha'] });
};

const orgsIsolatedApp: HttpFn = async (req) => {
  const claims = authenticate(req.headers, true);
  if (!claims) return UNAUTHORIZED;
  const org = orgIdOf(req.path);
  if (org === null) return NOT_FOUND;
  return org === String(claims.org_id) ? json(200, { orgId: org, projects: ['alpha'] }) : FORBIDDEN;
};

const profileLeakyApp: HttpFn = async (req) => {
  const claims = authenticate(req.headers, true);
  if (!claims) return UNAUTHORIZED;
  return json(200, { org_id: req.query?.org_id ?? claims.org_id, data: 'tenant data' });
};

const tokenUser1 = jwt({ sub: '1' });
const tokenUser2 = jwt({ sub: '2' });
const tokenUserU1 = jwt({ sub: 'u1' });
const tokenUserU2 = jwt({ sub: 'u2' });
const tokenOrg10 = jwt({ sub: '101', org_id: '10' });
const tokenOrg20 = jwt({ sub: '202', org_id: '20' });
const tokenOrgA = jwt({ sub: 'uA', org_id: 'orgA' });
const tokenOrgB = jwt({ sub: 'uB', org_id: 'orgB' });
const tokenTenantA = jwt({ sub: 'userA', org_id: 'tenantA' });
const tokenTenantB = jwt({ sub: 'userB', org_id: 'tenantB' });

const ACTIVE_DEFS: ActiveCaseDef[] = [
  {
    id: 'jwt-public-route',
    description: 'A public route that answers 200 to every request (any token, or none) says nothing about JWT verification',
    token: tokenUser1,
    requests: plan(tokenUser1, '/api/public'),
    app: publicApp,
    expected: [{ rule: 'jwt-not-verified', present: false }],
  },
  {
    id: 'jwt-protected-accepts-alg-none',
    description: 'A protected route (401 without a valid token) that still answers 200 to an alg:none token does not verify JWTs',
    token: tokenUser1,
    requests: plan(tokenUser1, '/api/secure'),
    app: lenientAuthApp,
    expected: [{ rule: 'jwt-not-verified', present: true, endpoint: '/api/secure' }],
  },
  {
    id: 'jwt-protected-rejects-alg-none',
    description: 'A protected route that answers 401 to an alg:none token verifies JWTs',
    token: tokenUser1,
    requests: plan(tokenUser1, '/api/secure'),
    app: strictAuthApp,
    expected: [{ rule: 'jwt-not-verified', present: false }],
  },
  {
    id: 'jwt-first-public-second-vulnerable',
    description: 'The first probed route is public, the second is protected but accepts alg:none: the app is vulnerable',
    token: tokenUser1,
    requests: publicThenSecure(tokenUser1),
    app: publicPlus(lenientAuthApp),
    expected: [{ rule: 'jwt-not-verified', present: true }],
  },
  {
    id: 'jwt-first-public-second-vulnerable-endpoint',
    description: 'Same app as jwt-first-public-second-vulnerable: the finding belongs on the protected route, not the public one',
    token: tokenUser1,
    requests: publicThenSecure(tokenUser1),
    app: publicPlus(lenientAuthApp),
    expected: [{ rule: 'jwt-not-verified', present: true, endpoint: '/api/secure' }],
  },
  {
    id: 'jwt-first-public-second-secure',
    description: 'The first probed route is public, the second is protected and rejects alg:none: the app is fine',
    token: tokenUser1,
    requests: publicThenSecure(tokenUser1),
    app: publicPlus(strictAuthApp),
    expected: [{ rule: 'jwt-not-verified', present: false }],
  },
  {
    id: 'bola-numeric-id-echoed',
    description: 'GET /api/users/:id returns another user record (echoing the numeric id) to a different user',
    token: tokenUser1,
    tokenB: tokenUser2,
    requests: plan(tokenUser1, '/api/users/:id'),
    app: usersEchoApp,
    expected: [{ rule: 'bola-idor', present: true, endpoint: '/api/users/1' }],
  },
  {
    id: 'bola-string-ids',
    description: 'Same IDOR with non-numeric ids (/users/u1): user u1 can read user u2',
    token: tokenUserU1,
    tokenB: tokenUserU2,
    requests: plan(tokenUserU1, '/users/:id'),
    app: usersEchoApp,
    expected: [{ rule: 'bola-idor', present: true, endpoint: '/users/u1' }],
  },
  {
    id: 'bola-foreign-id-not-echoed',
    description: 'IDOR where the response never contains the foreign id: user 1 gets user 2 data (200, different body) from /api/users/2',
    token: tokenUser1,
    tokenB: tokenUser2,
    requests: plan(tokenUser1, '/api/users/:id'),
    app: usersNoEchoApp,
    expected: [{ rule: 'bola-idor', present: true, endpoint: '/api/users/1' }],
  },
  {
    id: 'bola-isolated-403',
    description: 'A properly isolated app answers 403 for another user id',
    token: tokenUser1,
    tokenB: tokenUser2,
    requests: plan(tokenUser1, '/api/users/:id'),
    app: usersIsolatedApp(FORBIDDEN),
    expected: [
      { rule: 'bola-idor', present: false },
      { rule: 'tenant-isolation-broken', present: false },
    ],
  },
  {
    id: 'bola-isolated-404',
    description: 'A properly isolated app answers 404 for another user id',
    token: tokenUser1,
    tokenB: tokenUser2,
    requests: plan(tokenUser1, '/api/users/:id'),
    app: usersIsolatedApp(NOT_FOUND),
    expected: [
      { rule: 'bola-idor', present: false },
      { rule: 'tenant-isolation-broken', present: false },
    ],
  },
  {
    id: 'bola-public-resource',
    description:
      'A public catalogue (/api/products/:id readable by anyone, echoing the id) is not an IDOR; accepted open false positive: the scan still reports it',
    knownGap: 'audit item P2-8',
    token: tokenUser1,
    tokenB: tokenUser2,
    requests: plan(tokenUser1, '/api/products/:id'),
    app: productsPublicApp,
    expected: [{ rule: 'bola-idor', present: false }],
  },
  {
    id: 'tenant-query-param',
    description: 'GET /api/profile?org_id=tenantA lets tenant A read tenant B by changing the query parameter',
    token: tokenTenantA,
    tokenB: tokenTenantB,
    requests: [{ method: 'GET', path: '/api/profile', query: { org_id: 'tenantA' } }],
    app: profileLeakyApp,
    expected: [{ rule: 'tenant-isolation-broken', present: true, endpoint: '/api/profile' }],
  },
  {
    id: 'tenant-numeric-path-param',
    description: 'GET /orgs/:orgId/projects lets org 10 read org 20: must be reported as tenant isolation, not object-level IDOR',
    token: tokenOrg10,
    tokenB: tokenOrg20,
    requests: plan(tokenOrg10, '/orgs/:orgId/projects'),
    app: orgsLeakyApp,
    expected: [{ rule: 'tenant-isolation-broken', present: true, endpoint: '/orgs/10/projects' }],
  },
  {
    id: 'tenant-string-path-param',
    description: 'Same tenant leak with string org ids (/orgs/orgA/projects)',
    token: tokenOrgA,
    tokenB: tokenOrgB,
    requests: plan(tokenOrgA, '/orgs/:orgId/projects'),
    app: orgsLeakyApp,
    expected: [{ rule: 'tenant-isolation-broken', present: true, endpoint: '/orgs/orgA/projects' }],
  },
  {
    id: 'tenant-isolated-403',
    description: 'A tenant-isolated app answers 403 when another org is requested',
    token: tokenOrg10,
    tokenB: tokenOrg20,
    requests: plan(tokenOrg10, '/orgs/:orgId/projects'),
    app: orgsIsolatedApp,
    expected: [
      { rule: 'tenant-isolation-broken', present: false },
      { rule: 'bola-idor', present: false },
    ],
  },
];

export function activeCases(): BenchCase[] {
  return ACTIVE_DEFS.map((def) => ({
    id: def.id,
    kind: 'active',
    description: def.description,
    knownGap: def.knownGap,
    async evaluate() {
      const findings = await runActiveScan({ token: def.token, tokenB: def.tokenB, requests: def.requests }, def.app);
      return checkFindings(findings, def.expected);
    },
  }));
}

/**
 * A real loopback multi-role, multi-tenant HTTP API (node http) for the
 * authorization-matrix tests. Every vulnerability class is a flag: with all
 * flags off the app enforces the policy below; each flag breaks exactly one
 * check, so a test can show the engine reports that class and nothing else.
 *
 * Identities (opaque bearer tokens, never real credentials):
 *   alice  user  tenant acme     bob  user  tenant acme
 *   eve    user  tenant globex   admin admin (platform-wide, no tenant)
 */
import * as http from 'http';
import type { AddressInfo } from 'net';

export interface Vulns {
  bola?: boolean; // GET /api/invoices/:id: any logged-in user reads any invoice
  missingAuth?: boolean; // GET /api/invoices/:id: no login needed at all
  listLeak?: boolean; // GET /api/invoices: lists everyone's invoices
  queryId?: boolean; // GET /api/user-invoices?userId=: trusts the userId parameter
  batch?: boolean; // POST /api/invoices/batch-get: returns every requested id
  exportLeak?: boolean; // GET /api/invoices/:id/download: no owner check
  bfla?: boolean; // GET /admin/stats: any logged-in user
  crossTenant?: boolean; // GET /orgs/:org/projects/:id: no tenant check at all
  nested?: boolean; // ...checks the caller's org = :org, but not that the project is in :org
  crossWrite?: boolean; // PATCH /api/invoices/:id: no owner check
  crossDelete?: boolean; // DELETE /api/invoices/:id: no owner check
  massAssign?: boolean; // PATCH/POST /api/invoices: stores ownerId/orgId/amount from the client
  privEsc?: boolean; // PATCH /api/users/:id: stores role from the client
  introspection?: boolean; // /graphql answers __schema
  graphqlBola?: boolean; // /graphql invoice(id): no owner check
}

interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  org?: string;
}

interface Invoice {
  id: string;
  ownerId: string;
  orgId: string;
  title: string;
  amount: number;
  customerEmail: string;
}

export const TOKENS: Record<string, string> = { alice: 'tok-alice-0001', bob: 'tok-bob-0002', eve: 'tok-eve-0003', admin: 'tok-admin-0004' };

export interface AuthzApp {
  baseUrl: string;
  port: number;
  requests: { method: string; path: string; auth: string }[];
  close: () => Promise<void>;
}

function seed(): { users: Record<string, User>; invoices: Record<string, Invoice> } {
  const users: Record<string, User> = {
    u_alice: { id: 'u_alice', name: 'Alice Anders', email: 'alice@example.test', role: 'user', org: 'acme' },
    u_bob: { id: 'u_bob', name: 'Bob Brown', email: 'bob@example.test', role: 'user', org: 'acme' },
    u_eve: { id: 'u_eve', name: 'Eve Evans', email: 'eve@globex.test', role: 'user', org: 'globex' },
    u_admin: { id: 'u_admin', name: 'Ada Admin', email: 'ada@example.test', role: 'admin' },
  };
  const invoices: Record<string, Invoice> = {
    inv_a: { id: 'inv_a', ownerId: 'u_alice', orgId: 'acme', title: 'Alice consulting March', amount: 1250.5, customerEmail: 'alice.customer@example.test' },
    inv_b: { id: 'inv_b', ownerId: 'u_bob', orgId: 'acme', title: 'Bob hosting April', amount: 777.25, customerEmail: 'bob.customer@example.test' },
    inv_e: { id: 'inv_e', ownerId: 'u_eve', orgId: 'globex', title: 'Eve design May', amount: 4321.75, customerEmail: 'eve.customer@globex.test' },
  };
  return { users, invoices };
}

const PROJECTS: Record<string, { id: string; org: string; name: string; budget: number; lead: string }> = {
  p_acme: { id: 'p_acme', org: 'acme', name: 'Acme Rocket Skates', budget: 50000.5, lead: 'wile@acme.test' },
  p_globex: { id: 'p_globex', org: 'globex', name: 'Globex Doomsday Device', budget: 99999.9, lead: 'hank@globex.test' },
};

export async function startAuthzApp(v: Vulns = {}): Promise<AuthzApp> {
  const { users, invoices } = seed();
  const byToken: Record<string, string> = { [TOKENS.alice!]: 'u_alice', [TOKENS.bob!]: 'u_bob', [TOKENS.eve!]: 'u_eve', [TOKENS.admin!]: 'u_admin' };
  const requests: AuthzApp['requests'] = [];
  let seq = 0;

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url ?? '/', 'http://x');
      const auth = String(req.headers.authorization ?? '');
      const me = users[byToken[auth.replace(/^Bearer /, '')] ?? ''];
      requests.push({ method: req.method ?? '?', path: url.pathname + url.search, auth: me?.id ?? 'anonymous' });
      let body: Record<string, unknown> = {};
      try {
        body = chunks.length ? (JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>) : {};
      } catch {
        body = {};
      }
      const json = (status: number, data: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(data));
      };
      const isAdmin = me?.role === 'admin';
      const canRead = (inv: Invoice) => Boolean(me) && (isAdmin || inv.ownerId === me!.id);
      const p = url.pathname;
      const m = req.method ?? 'GET';
      let mm: RegExpExecArray | null;

      if (p === '/graphql' && m === 'POST') {
        const q = String(body.query ?? '');
        if (q.includes('__schema')) {
          return v.introspection ? json(200, { data: { __schema: { queryType: { name: 'Query' } } } }) : json(400, { errors: [{ message: 'introspection disabled' }] });
        }
        const id = String((body.variables as Record<string, unknown> | undefined)?.id ?? '');
        const inv = invoices[id];
        if (!me) return json(200, { data: { invoice: null }, errors: [{ message: 'unauthenticated' }] });
        if (!inv || !(v.graphqlBola || canRead(inv))) return json(200, { data: { invoice: null }, errors: [{ message: 'not found' }] });
        return json(200, { data: { invoice: inv } });
      }

      if (!me && !(v.missingAuth && m === 'GET' && /^\/api\/invoices\/[^/]+$/.test(p))) return json(401, { error: 'login required' });

      if (p === '/admin/stats' && m === 'GET') {
        if (!isAdmin && !v.bfla) return json(403, { error: 'admins only' });
        return json(200, { revenue: 99881.5, topCustomer: 'alice.customer@example.test', invoices: Object.keys(invoices).length });
      }
      if ((mm = /^\/orgs\/([^/]+)\/projects\/([^/]+)$/.exec(p)) && m === 'GET') {
        const [, org, id] = mm;
        const proj = PROJECTS[id!];
        if (!proj) return json(404, { error: 'not found' });
        if (!v.crossTenant && !isAdmin) {
          if (me!.org !== org) return json(403, { error: 'not your organization' });
          if (!v.nested && proj.org !== org) return json(404, { error: 'not found' });
        }
        return json(200, proj);
      }
      if ((mm = /^\/api\/users\/([^/]+)$/.exec(p))) {
        const u = users[mm[1]!];
        if (!u || (u.id !== me!.id && !isAdmin)) return json(404, { error: 'not found' });
        if (m === 'GET') return json(200, u);
        if (m === 'PATCH') {
          if (typeof body.name === 'string') u.name = body.name;
          if (v.privEsc && typeof body.role === 'string') u.role = body.role;
          return json(200, u);
        }
      }
      if (p === '/api/invoices' && m === 'GET') {
        return json(200, { items: Object.values(invoices).filter((i) => v.listLeak || canRead(i)), page: 1 });
      }
      if (p === '/api/user-invoices' && m === 'GET') {
        const uid = url.searchParams.get('userId') ?? '';
        if (!v.queryId && uid !== me!.id && !isAdmin) return json(403, { error: 'forbidden' });
        return json(200, { items: Object.values(invoices).filter((i) => i.ownerId === uid) });
      }
      if (p === '/api/invoices/batch-get' && m === 'POST') {
        const ids = Array.isArray(body.ids) ? body.ids.map(String) : [];
        return json(200, { items: ids.map((id) => invoices[id]).filter((i): i is Invoice => Boolean(i) && (v.batch || canRead(i!))) });
      }
      if (p === '/api/invoices' && m === 'POST') {
        const id = `inv_n${++seq}`;
        const inv: Invoice = { id, ownerId: me!.id, orgId: me!.org ?? 'acme', title: String(body.title ?? 'untitled'), amount: 100, customerEmail: me!.email };
        if (v.massAssign) Object.assign(inv, body, { id });
        invoices[id] = inv;
        return json(201, { id });
      }
      if ((mm = /^\/api\/invoices\/([^/]+)\/download$/.exec(p)) && m === 'GET') {
        const inv = invoices[mm[1]!];
        if (!inv || !(v.exportLeak || canRead(inv))) return json(404, { error: 'not found' });
        res.writeHead(200, { 'content-type': 'text/csv' });
        return res.end(`id,title,amount,customer\n${inv.id},${inv.title},${inv.amount},${inv.customerEmail}\n`);
      }
      if ((mm = /^\/api\/invoices\/([^/]+)$/.exec(p))) {
        const inv = invoices[mm[1]!];
        if (m === 'GET') {
          if (!inv || !(v.bola || v.missingAuth || canRead(inv))) return json(404, { error: 'not found', id: mm[1] });
          return json(200, inv);
        }
        if (!inv) return json(404, { error: 'not found' });
        if (m === 'PATCH') {
          if (!v.crossWrite && !canRead(inv)) return json(404, { error: 'not found' });
          if (typeof body.title === 'string') inv.title = body.title;
          if (v.massAssign) Object.assign(inv, body, { id: inv.id });
          return json(200, inv);
        }
        if (m === 'DELETE') {
          if (!v.crossDelete && !canRead(inv)) return json(404, { error: 'not found' });
          delete invoices[inv.id];
          return json(204, {});
        }
      }
      return json(404, { error: 'no route' });
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    port,
    requests,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

/** The reviewed policy and identities for this app (the `active` section of .deployready.json). */
export function authzActiveConfig(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    identities: [
      { name: 'anonymous', role: 'anonymous' },
      { name: 'alice', role: 'user', tenant: 'acme', token: TOKENS.alice, params: { userId: 'u_alice', org: 'acme' }, objects: { invoices: { id: 'inv_a' }, projects: { id: 'p_acme' }, users: { id: 'u_alice' } } },
      { name: 'bob', role: 'user', tenant: 'acme', token: TOKENS.bob, params: { userId: 'u_bob', org: 'acme' }, objects: { invoices: { id: 'inv_b' }, projects: { id: 'p_acme' }, users: { id: 'u_bob' } } },
      { name: 'eve', role: 'user', tenant: 'globex', token: TOKENS.eve, params: { userId: 'u_eve', org: 'globex' }, objects: { invoices: { id: 'inv_e' }, projects: { id: 'p_globex' }, users: { id: 'u_eve' } } },
      { name: 'admin', role: 'admin', token: TOKENS.admin },
    ],
    policy: {
      draft: false,
      resources: [
        {
          name: 'invoices',
          routes: [
            'GET /api/invoices',
            'GET /api/invoices/:id',
            'PATCH /api/invoices/:id',
            'DELETE /api/invoices/:id',
            'POST /api/invoices',
            { route: 'POST /api/invoices/batch-get', batchField: 'ids', sideEffectFree: true },
            'GET /api/invoices/:id/download',
            'GET /api/user-invoices?userId=:userId',
          ],
          access: { anonymous: 'none', user: 'own', admin: 'manage' },
          body: { title: 'DeployReady test invoice' },
        },
        { name: 'admin-stats', routes: ['GET /admin/stats'], access: { anonymous: 'none', user: 'none', admin: 'manage' } },
        { name: 'projects', routes: ['GET /orgs/:org/projects/:id'], access: { anonymous: 'none', user: 'read', admin: 'manage' } },
        { name: 'users', routes: ['GET /api/users/:id', 'PATCH /api/users/:id'], access: { anonymous: 'none', user: 'own', admin: 'manage' } },
      ],
      graphql: { endpoint: '/graphql', introspection: 'deny', queries: [{ resource: 'invoices', query: 'query($id: ID!) { invoice(id: $id) { id title amount customerEmail } }', variable: 'id' }] },
    },
    ...extra,
  };
}

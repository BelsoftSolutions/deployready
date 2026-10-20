import * as http from 'http';
import type { AddressInfo } from 'net';
import { DynamicTester } from '../src/dynamic/DynamicTester';
import { IssueAggregator } from '../src/analysis/IssueAggregator';
import type { Route } from '../src/types';
import { checkFindings, type BenchCase, type FindingExpectation } from './core';

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

interface DynamicCaseDef {
  id: string;
  description: string;
  knownGap?: string;
  app: () => Handler;
  routes?: Route[];
  aggressive?: boolean;
  expected: FindingExpectation[];
  /** Paths the scanner may request; any other request (bar the lazy catch-all control) is a guess and fails the case. */
  requestsOnly?: string[];
  /** Informational notes must not change the score or the scored summary. */
  notesUnscored?: boolean;
}

const route = (method: string, path: string, guarded = false, guardNames?: string[]): Route => ({
  method,
  path,
  file: 'app.js',
  guarded,
  ...(guardNames ? { guardNames } : {}),
});

const NO_ROUTES_GAP = 'route not discovered by the parser; DeployReady no longer guesses routes';
const CONTROL_PATH = /^\/__deployready_probe_/;

function reply(
  res: http.ServerResponse,
  status: number,
  body: string,
  type = 'text/html',
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, { 'content-type': type, ...headers });
  res.end(body);
}

const pathOf = (req: http.IncomingMessage): string => (req.url ?? '/').split('?')[0] ?? '/';
const notFound = (res: http.ServerResponse): void => reply(res, 404, 'Not found', 'text/plain');

const SPA_SHELL = '<!doctype html><html><body><div id="root"></div><script src="/bundle.js"></script></body></html>';
const SECURE_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=63072000',
  'content-security-policy': "default-src 'self'",
  'cache-control': 'no-store',
};

/** Every path answers 200 with the same single-page-app shell; auth lives in the API. */
const spaCatchAll = (): Handler => (_req, res) => reply(res, 200, SPA_SHELL);

const DYNAMIC_DEFS: DynamicCaseDef[] = [
  {
    id: 'admin-open-200',
    description: '/admin really serves an admin dashboard to anonymous users',
    knownGap: NO_ROUTES_GAP,
    app: () => (req, res) =>
      pathOf(req) === '/admin'
        ? reply(res, 200, '<h1>Admin dashboard</h1><ul><li>Manage users</li><li>Billing</li></ul>')
        : notFound(res),
    expected: [{ rule: 'exposed-admin-route', present: true, endpoint: '/admin' }],
  },
  {
    id: 'admin-redirect-to-login',
    description: '/admin answers 302 to /login, so it is protected',
    app: () => (req, res) => {
      const p = pathOf(req);
      if (p === '/admin') return reply(res, 302, '', 'text/plain', { location: '/login' });
      if (p === '/login') return reply(res, 200, '<form method="post"><input name="user"><input name="pass"></form>');
      notFound(res);
    },
    expected: [{ rule: 'exposed-admin-route', present: false, endpoint: '/admin' }],
  },
  {
    id: 'admin-401',
    description: '/admin answers 401 to anonymous users, so it is protected',
    app: () => (req, res) =>
      pathOf(req) === '/admin' ? reply(res, 401, '{"error":"unauthorized"}', 'application/json') : notFound(res),
    expected: [{ rule: 'exposed-admin-route', present: false, endpoint: '/admin' }],
  },
  {
    id: 'spa-catchall-no-admin',
    description: 'A single-page app answering 200 with the same shell for every path does not expose an admin route',
    app: spaCatchAll,
    expected: [{ rule: 'exposed-admin-route', present: false }],
  },
  {
    id: 'spa-catchall-no-auth-bypass',
    description: 'Client-side-guarded routes in a catch-all single-page app are not an auth bypass',
    app: spaCatchAll,
    routes: [route('GET', '/dashboard', true), route('GET', '/settings', true)],
    expected: [{ rule: 'auth-bypass', present: false }],
  },
  {
    id: 'catchall-env-exposed',
    description: 'In a catch-all app, /.env returns distinct secret-bearing content, which is a real exposure',
    knownGap: NO_ROUTES_GAP,
    app: () => (req, res) =>
      pathOf(req) === '/.env'
        ? reply(res, 200, 'DB_PASSWORD=hunter2hunter2\nSECRET_KEY=fake-fake-fake\n', 'text/plain')
        : reply(res, 200, SPA_SHELL),
    expected: [{ rule: 'exposed-admin-route', present: true, endpoint: '/.env' }],
  },

  // Siblings with the route in the discovered list, odd-named admin routes, and the "never guess" behaviour.
  {
    id: 'admin-open-200-discovered',
    description: 'Sibling of admin-open-200 with GET /admin in the discovered routes: the open admin dashboard is detected',
    app: () => (req, res) =>
      pathOf(req) === '/admin'
        ? reply(res, 200, '<h1>Admin dashboard</h1><ul><li>Manage users</li><li>Billing</li></ul>')
        : notFound(res),
    routes: [route('GET', '/admin')],
    requestsOnly: ['/admin'],
    expected: [{ rule: 'exposed-admin-route', present: true, endpoint: '/admin' }],
  },
  {
    id: 'admin-open-backoffice-discovered',
    description: 'An admin area named /backoffice, discovered by the parser and served open, is treated like /admin',
    app: () => (req, res) =>
      pathOf(req) === '/backoffice'
        ? reply(res, 200, '<h1>Back office</h1><ul><li>Customers</li><li>Refunds</li></ul>')
        : notFound(res),
    routes: [route('GET', '/backoffice')],
    requestsOnly: ['/backoffice'],
    expected: [{ rule: 'exposed-admin-route', present: true, endpoint: '/backoffice' }],
  },
  {
    id: 'admin-open-staff-console-discovered',
    description: 'An admin area named /staff/console, discovered by the parser and served open, is treated like /admin',
    app: () => (req, res) =>
      pathOf(req) === '/staff/console'
        ? reply(res, 200, '<h1>Staff console</h1><ul><li>Orders</li><li>Impersonate</li></ul>')
        : notFound(res),
    routes: [route('GET', '/staff/console')],
    requestsOnly: ['/staff/console'],
    expected: [{ rule: 'exposed-admin-route', present: true, endpoint: '/staff/console' }],
  },
  {
    id: 'admin-open-neutral-path-staff-guard',
    description:
      'A neutral path guarded by requireRole("staff") in code that answers 200 anonymously is an exposed admin route and an auth bypass',
    app: () => (req, res) =>
      pathOf(req) === '/reports/summary'
        ? reply(res, 200, '<h1>Revenue summary</h1><p>internal figures</p>')
        : notFound(res),
    routes: [route('GET', '/reports/summary', true, ['requireRole', 'staff'])],
    requestsOnly: ['/reports/summary'],
    expected: [
      { rule: 'exposed-admin-route', present: true, endpoint: '/reports/summary' },
      { rule: 'auth-bypass', present: true, endpoint: '/reports/summary' },
    ],
  },
  {
    id: 'neutral-path-unguarded-open',
    description: 'A neutral, unguarded route that answers 200 is public by design: not an exposed admin route and not an auth bypass',
    app: () => (req, res) =>
      pathOf(req) === '/reports/public' ? reply(res, 200, '<h1>Public report</h1>') : notFound(res),
    routes: [route('GET', '/reports/public')],
    requestsOnly: ['/reports/public'],
    expected: [
      { rule: 'exposed-admin-route', present: false },
      { rule: 'auth-bypass', present: false },
    ],
  },
  {
    id: 'admin-401-discovered',
    description: 'Sibling of admin-401 with GET /admin in the discovered routes: a 401 means protected',
    app: () => (req, res) =>
      pathOf(req) === '/admin' ? reply(res, 401, '{"error":"unauthorized"}', 'application/json') : notFound(res),
    routes: [route('GET', '/admin')],
    requestsOnly: ['/admin'],
    expected: [{ rule: 'exposed-admin-route', present: false, endpoint: '/admin' }],
  },
  {
    id: 'admin-redirect-to-login-discovered',
    description:
      'Sibling of admin-redirect-to-login with GET /admin in the discovered routes: a 302 to /login means protected, and /login is never followed',
    app: () => (req, res) => {
      const p = pathOf(req);
      if (p === '/admin') return reply(res, 302, '', 'text/plain', { location: '/login' });
      if (p === '/login') return reply(res, 200, '<form method="post"><input name="user"><input name="pass"></form>');
      notFound(res);
    },
    routes: [route('GET', '/admin')],
    requestsOnly: ['/admin'],
    expected: [{ rule: 'exposed-admin-route', present: false, endpoint: '/admin' }],
  },
  {
    id: 'admin-401-backoffice-discovered',
    description: 'A discovered /backoffice that answers 401 to anonymous users is protected',
    app: () => (req, res) =>
      pathOf(req) === '/backoffice' ? reply(res, 401, '{"error":"unauthorized"}', 'application/json') : notFound(res),
    routes: [route('GET', '/backoffice')],
    requestsOnly: ['/backoffice'],
    expected: [{ rule: 'exposed-admin-route', present: false, endpoint: '/backoffice' }],
  },
  {
    id: 'admin-403-staff-console-discovered',
    description: 'A discovered /staff/console that answers 403 to anonymous users is protected',
    app: () => (req, res) =>
      pathOf(req) === '/staff/console' ? reply(res, 403, '{"error":"forbidden"}', 'application/json') : notFound(res),
    routes: [route('GET', '/staff/console')],
    requestsOnly: ['/staff/console'],
    expected: [{ rule: 'exposed-admin-route', present: false, endpoint: '/staff/console' }],
  },
  {
    id: 'admin-redirect-staff-console-discovered',
    description: 'A discovered /staff/console that answers 302 to /login is protected, and /login is never followed',
    app: () => (req, res) => {
      const p = pathOf(req);
      if (p === '/staff/console') return reply(res, 302, '', 'text/plain', { location: '/login' });
      if (p === '/login') return reply(res, 200, '<form method="post"></form>');
      notFound(res);
    },
    routes: [route('GET', '/staff/console')],
    requestsOnly: ['/staff/console'],
    expected: [{ rule: 'exposed-admin-route', present: false, endpoint: '/staff/console' }],
  },
  {
    id: 'spa-catchall-no-admin-discovered',
    description:
      'Sibling of spa-catchall-no-admin with /admin and /backoffice in the discovered routes: the single-page shell is not an exposed admin route',
    app: spaCatchAll,
    routes: [route('GET', '/admin'), route('GET', '/backoffice')],
    requestsOnly: ['/admin', '/backoffice'],
    expected: [{ rule: 'exposed-admin-route', present: false }],
  },
  {
    id: 'catchall-env-exposed-discovered',
    description:
      'Sibling of catchall-env-exposed with GET /.env in the discovered routes: distinct secret-bearing content in a catch-all app is detected',
    knownGap:
      'a discovered /.env route is requested but not classified sensitive (admin vocabulary has no secret-file names); only the secret-in-response warning fires',
    app: () => (req, res) =>
      pathOf(req) === '/.env'
        ? reply(res, 200, 'DB_PASSWORD=hunter2hunter2\nSECRET_KEY=fake-fake-fake\n', 'text/plain')
        : reply(res, 200, SPA_SHELL),
    routes: [route('GET', '/.env')],
    requestsOnly: ['/.env'],
    expected: [{ rule: 'exposed-admin-route', present: true, endpoint: '/.env' }],
  },
  {
    id: 'no-routes-discovered-note',
    description:
      'No routes discovered (empty list): zero requests reach an app that serves /admin and /.env openly; the scan reports only the non-scored note',
    app: () => (req, res) =>
      pathOf(req) === '/.env'
        ? reply(res, 200, 'DB_PASSWORD=hunter2hunter2\n', 'text/plain')
        : reply(res, 200, '<h1>Admin dashboard</h1>'),
    routes: [],
    aggressive: true,
    requestsOnly: [],
    notesUnscored: true,
    expected: [
      { rule: 'dynamic-skipped', present: true, severity: 'info' },
      { rule: 'exposed-admin-route', present: false },
      { rule: 'auth-bypass', present: false },
      { rule: 'secret-in-response', present: false },
      { rule: 'missing-security-headers', present: false },
    ],
  },
  {
    id: 'path-param-route-skipped-note',
    description:
      'The only discovered route is GET /users/:id: it is never requested (no invented id) although /users/1 would answer; the scan reports a skipped-routes note',
    app: () => (_req, res) => reply(res, 200, '{"id":1,"email":"a@example.test"}', 'application/json'),
    routes: [route('GET', '/users/:id')],
    aggressive: true,
    requestsOnly: [],
    notesUnscored: true,
    expected: [
      { rule: 'dynamic-skipped', present: true, severity: 'info' },
      { rule: 'secret-in-response', present: false },
      { rule: 'missing-security-headers', present: false },
    ],
  },
  {
    id: 'path-param-route-skipped-alongside-probed',
    description: 'GET /ping is requested, GET /users/:id is skipped with a note and never requested; the note does not change the score',
    app: () => (req, res) =>
      pathOf(req) === '/ping'
        ? reply(res, 200, '{"ok":true}', 'application/json', SECURE_HEADERS)
        : reply(res, 200, '{"id":1}', 'application/json'),
    routes: [route('GET', '/ping'), route('GET', '/users/:id')],
    requestsOnly: ['/ping'],
    notesUnscored: true,
    expected: [
      { rule: 'dynamic-routes-skipped', present: true, severity: 'info' },
      { rule: 'dynamic-skipped', present: false },
    ],
  },
  {
    id: 'secret-json-nested',
    description: 'A JSON response carrying an AWS key in a nested field leaks a secret',
    app: () => (req, res) =>
      pathOf(req) === '/api/config'
        ? reply(res, 200, '{"config":{"key":"AKIAIOSFODNN7EXAMPLE"}}', 'application/json')
        : notFound(res),
    routes: [route('GET', '/api/config')],
    expected: [{ rule: 'secret-in-response', present: true, endpoint: '/api/config' }],
  },
  {
    id: 'secret-plain-text',
    description: 'A plain-text response carrying an AWS key leaks a secret',
    app: () => (req, res) =>
      pathOf(req) === '/api/config' ? reply(res, 200, 'key=AKIAIOSFODNN7EXAMPLE', 'text/plain') : notFound(res),
    routes: [route('GET', '/api/config')],
    expected: [{ rule: 'secret-in-response', present: true, endpoint: '/api/config' }],
  },
  {
    id: 'secret-json-clean',
    description: 'A JSON response without any secret must not be flagged',
    app: () => (req, res) =>
      pathOf(req) === '/api/config'
        ? reply(res, 200, '{"name":"demo","version":"1.0.0","features":["search","export"]}', 'application/json')
        : notFound(res),
    routes: [route('GET', '/api/config')],
    expected: [{ rule: 'secret-in-response', present: false }],
  },
  {
    id: 'auth-bypass-open',
    description: 'A route that is guarded in code but answers 200 to anonymous requests is a real bypass',
    app: () => (req, res) =>
      pathOf(req) === '/api/private'
        ? reply(res, 200, '{"owner":"alice","note":"private"}', 'application/json')
        : notFound(res),
    routes: [route('GET', '/api/private', true)],
    expected: [{ rule: 'auth-bypass', present: true, endpoint: '/api/private' }],
  },
  {
    id: 'auth-bypass-enforced',
    description: 'A guarded route that answers 401 to anonymous requests is not a bypass',
    app: () => (req, res) =>
      pathOf(req) === '/api/private' ? reply(res, 401, '{"error":"unauthorized"}', 'application/json') : notFound(res),
    routes: [route('GET', '/api/private', true)],
    expected: [{ rule: 'auth-bypass', present: false }],
  },
  {
    id: 'ratelimit-login-page-get',
    description: 'A GET /login page that serves HTML is not a brute-forceable endpoint and must not be reported as critical',
    app: () => (req, res) =>
      pathOf(req) === '/login'
        ? reply(res, 200, '<form method="post" action="/api/login"><input name="user"><input name="pass"></form>')
        : notFound(res),
    routes: [route('GET', '/login')],
    aggressive: true,
    expected: [{ rule: 'missing-rate-limit', present: false, severity: 'critical' }],
  },
  {
    id: 'ratelimit-post-login-open',
    description:
      'POST /api/login with no limiter cannot be probed (GET-only); the scanner must say so with an info note rather than go silent or claim a missing limiter',
    app: () => (req, res) =>
      pathOf(req) === '/api/login' && req.method === 'POST'
        ? reply(res, 401, '{"error":"bad credentials"}', 'application/json')
        : notFound(res),
    routes: [route('POST', '/api/login')],
    aggressive: true,
    expected: [{ rule: 'missing-rate-limit', present: true, endpoint: '/api/login', severity: 'info' }],
  },
  {
    id: 'ratelimit-limiter-all-methods',
    description: 'A login endpoint that answers 429 after a few requests (any method) is rate limited',
    app: () => {
      let hits = 0;
      return (req, res) => {
        if (pathOf(req) !== '/api/login') return notFound(res);
        hits++;
        if (hits > 5) return reply(res, 429, '{"error":"too many requests"}', 'application/json');
        reply(res, req.method === 'POST' ? 401 : 405, '{"error":"nope"}', 'application/json');
      };
    },
    routes: [route('POST', '/api/login')],
    aggressive: true,
    expected: [
      { rule: 'missing-rate-limit', present: false, severity: 'warning' },
      { rule: 'missing-rate-limit', present: false, severity: 'critical' },
    ],
  },
  {
    id: 'ratelimit-limiter-post-only',
    description: 'A login endpoint whose POST handler answers 429 after a few attempts is rate limited (GET just returns 405)',
    app: () => {
      let posts = 0;
      return (req, res) => {
        if (pathOf(req) !== '/api/login') return notFound(res);
        if (req.method !== 'POST') return reply(res, 405, '{"error":"method not allowed"}', 'application/json');
        posts++;
        if (posts > 5) return reply(res, 429, '{"error":"too many requests"}', 'application/json');
        reply(res, 401, '{"error":"bad credentials"}', 'application/json');
      };
    },
    routes: [route('POST', '/api/login')],
    aggressive: true,
    expected: [
      { rule: 'missing-rate-limit', present: false, severity: 'warning' },
      { rule: 'missing-rate-limit', present: false, severity: 'critical' },
    ],
  },
  {
    id: 'advertised-link-backoffice-open',
    description:
      'The home page links to /backoffice, which the parser never found: the link is the app itself advertising it, so it is requested and its open 200 is reported (nothing else is requested)',
    app: () => (req, res) => {
      const p = pathOf(req);
      if (p === '/') return reply(res, 200, '<h1>Home</h1><a href="/backoffice">Back office</a>');
      if (p === '/backoffice') return reply(res, 200, '<h1>Back office</h1><ul><li>Users</li><li>Invoices</li></ul>');
      notFound(res);
    },
    routes: [route('GET', '/')],
    requestsOnly: ['/', '/backoffice'],
    expected: [{ rule: 'exposed-admin-route', present: true, endpoint: '/backoffice' }],
  },
  {
    id: 'advertised-link-spa-catchall-no-finding',
    description: 'A single-page app answers 200 with its shell for every path and links to /admin: the lazy catch-all control stops a false admin finding',
    app: () => (_req, res) => reply(res, 200, '<!doctype html><div id="root"></div><a href="/admin">Admin</a>'),
    routes: [route('GET', '/')],
    requestsOnly: ['/', '/admin'],
    expected: [{ rule: 'exposed-admin-route', present: false }],
  },
  {
    id: 'advertised-link-unsafe-and-foreign-not-requested',
    description:
      'Links to logout/delete URLs, a script, another host, a mailto: and a form action are never requested, although the app would answer them with an open admin page',
    app: () => (req, res) =>
      pathOf(req) === '/'
        ? reply(
            res,
            200,
            '<a href="/logout">out</a><a href="/account/delete">del</a><a href="/app.js">js</a><a href="http://example.test/admin">ext</a><a href="mailto:a@example.test">m</a><form method="get" action="/admin"></form>',
          )
        : reply(res, 200, '<h1>Admin dashboard</h1>'),
    routes: [route('GET', '/')],
    requestsOnly: ['/'],
    expected: [{ rule: 'exposed-admin-route', present: false }],
  },
  {
    id: 'advertised-link-depth-one',
    description: 'A link on an advertised page is not followed: /a is advertised by the discovered /, /secret-admin (linked only from /a) is never requested',
    app: () => (req, res) => {
      const p = pathOf(req);
      if (p === '/') return reply(res, 200, '<a href="/a">a</a>');
      if (p === '/a') return reply(res, 200, '<a href="/staff/secret-admin">next</a>');
      reply(res, 200, '<h1>Admin dashboard</h1>');
    },
    routes: [route('GET', '/')],
    requestsOnly: ['/', '/a'],
    expected: [{ rule: 'exposed-admin-route', present: false }],
  },
  {
    id: 'robots-sitemap-not-evidence-not-requested',
    description: 'The app serves /robots.txt and /sitemap.xml but nothing in the project or in a fetched response points at them: neither is requested',
    app: () => (req, res) => {
      const p = pathOf(req);
      if (p === '/robots.txt') return reply(res, 200, 'Sitemap: /sitemap.xml\nDisallow: /staff\n', 'text/plain');
      if (p === '/sitemap.xml') return reply(res, 200, '<urlset><url><loc>/staff/console</loc></url></urlset>', 'application/xml');
      if (p === '/') return reply(res, 200, '<h1>Home</h1>');
      notFound(res);
    },
    routes: [route('GET', '/')],
    requestsOnly: ['/'],
    expected: [{ rule: 'exposed-admin-route', present: false }],
  },
  {
    id: 'clean-app',
    description: 'A hardened app (auth enforced, headers set, nothing exposed, no leaks) yields none of the dynamic findings',
    app: () => (req, res) => {
      const p = pathOf(req);
      if (p === '/') return reply(res, 200, SPA_SHELL, 'text/html', SECURE_HEADERS);
      if (p === '/api/items') {
        return reply(res, 200, '{"items":[{"id":1,"name":"widget"}]}', 'application/json', SECURE_HEADERS);
      }
      if (p === '/api/private') return reply(res, 401, '{"error":"unauthorized"}', 'application/json', SECURE_HEADERS);
      reply(res, 404, '{"error":"not found"}', 'application/json', SECURE_HEADERS);
    },
    routes: [route('GET', '/api/items'), route('GET', '/api/private', true)],
    expected: [
      { rule: 'auth-bypass', present: false },
      { rule: 'exposed-admin-route', present: false },
      { rule: 'secret-in-response', present: false },
      { rule: 'stack-trace-leak', present: false },
      { rule: 'cors-wildcard-live', present: false },
      { rule: 'missing-security-headers', present: false },
      { rule: 'missing-cache-headers', present: false },
      { rule: 'version-banner', present: false },
    ],
  },
];

async function withServer<T>(handler: Handler, fn: (baseUrl: string) => Promise<T>): Promise<T> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address() as AddressInfo;
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

export function dynamicCases(): BenchCase[] {
  return DYNAMIC_DEFS.map((def) => ({
    id: def.id,
    kind: 'dynamic',
    description: def.description,
    knownGap: def.knownGap,
    evaluate: () => {
      const requested: string[] = [];
      const inner = def.app();
      const handler: Handler = (req, res) => {
        requested.push(pathOf(req));
        inner(req, res);
      };
      return withServer(handler, async (baseUrl) => {
        const results = await DynamicTester.run(baseUrl, def.routes ?? [], { aggressive: def.aggressive ?? false });
        const checks = checkFindings(results.findings, def.expected);
        if (def.requestsOnly) {
          const allowed = def.requestsOnly;
          const guessed = requested.filter((p) => !CONTROL_PATH.test(p) && !allowed.includes(p));
          checks.push({
            rule: 'unrequested-path',
            label: 'request outside the discovered routes absent',
            expected: false,
            actual: guessed.length > 0,
            detail: guessed.length > 0 ? `requested ${[...new Set(guessed)].join(', ')}` : 'nothing outside the discovered routes was requested',
          });
        }
        if (def.notesUnscored) {
          const withNotes = IssueAggregator.process([], results.findings);
          const scoredOnly = IssueAggregator.process([], results.findings.filter((f) => !f.note));
          const changed = withNotes.score !== scoredOnly.score || withNotes.summary.total !== scoredOnly.summary.total;
          checks.push({
            rule: 'note-scored',
            label: 'informational note changes the score absent',
            expected: false,
            actual: changed,
            detail: changed ? `score ${scoredOnly.score} -> ${withNotes.score}` : `score ${withNotes.score} with and without notes`,
          });
        }
        return checks;
      });
    },
  }));
}

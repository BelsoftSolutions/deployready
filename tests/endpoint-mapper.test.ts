import { EndpointMapper } from '../src/dynamic/EndpointMapper';
import { adminEvidence } from '../src/dynamic/adminEvidence';
import type { Route } from '../src/types';

const route = (method: string, path: string, extra: Partial<Route> = {}): Route => ({
  method,
  path,
  file: 'src/app.js',
  line: 7,
  guarded: false,
  ...extra,
});

describe('EndpointMapper.plan', () => {
  it('produces no targets from an empty route list (no common or sensitive paths)', () => {
    expect(EndpointMapper.plan([])).toEqual({ targets: [], skipped: [] });
  });

  it('targets exactly the discovered GET routes and nothing else', () => {
    const { targets } = EndpointMapper.plan([route('GET', '/ping'), route('GET', '/api/things')]);
    expect(targets.map((t) => t.path)).toEqual(['/ping', '/api/things']);
    for (const guess of ['/', '/health', '/api', '/status', '/metrics', '/admin', '/.env', '/debug', '/actuator', '/api/users']) {
      expect(targets.map((t) => t.path)).not.toContain(guess);
    }
  });

  it('treats ALL as GET', () => {
    const { targets } = EndpointMapper.plan([route('ALL', '/anything')]);
    expect(targets).toMatchObject([{ method: 'GET', path: '/anything' }]);
  });

  it('skips non-GET routes with the never-mutates reason', () => {
    const { targets, skipped } = EndpointMapper.plan([
      route('POST', '/login'),
      route('DELETE', '/things'),
      route('PUT', '/things'),
    ]);
    expect(targets).toEqual([]);
    expect(skipped).toHaveLength(3);
    for (const s of skipped) expect(s.reason).toBe('non-GET route: the scanner never mutates data');
  });

  it.each([
    ['/users/:id', ':id'],
    ['/users/{id}', '{id}'],
    ['/users/<id>', '<id>'],
    ['/orgs/:orgId/users/:userId', ':orgId'],
  ])('skips %s and never substitutes a value', (path, param) => {
    const { targets, skipped } = EndpointMapper.plan([route('GET', path)]);
    expect(targets).toEqual([]);
    expect(skipped).toEqual([
      {
        method: 'GET',
        path,
        reason: `needs a value for path parameter "${param}" that the scan cannot supply (values are never invented)`,
      },
    ]);
    expect(JSON.stringify(skipped)).not.toMatch(/\/1\b/);
  });

  it.each(['/files/*', '/a(b)c', '/maybe?', '/a+', String.raw`/a\b`])('skips pattern/wildcard path %s', (path) => {
    const { targets, skipped } = EndpointMapper.plan([route('GET', path)]);
    expect(targets).toEqual([]);
    expect(skipped).toHaveLength(1);
    expect(skipped[0]!.reason).toMatch(/pattern or wildcard/);
  });

  it('dedupes by METHOD path, including ALL and GET for the same path', () => {
    const { targets } = EndpointMapper.plan([route('GET', '/a'), route('ALL', '/a'), route('GET', '/a'), route('GET', '/b')]);
    expect(targets.map((t) => `${t.method} ${t.path}`)).toEqual(['GET /a', 'GET /b']);
  });

  it('carries guarded and the evidence for requesting each route', () => {
    const { targets } = EndpointMapper.plan([
      route('GET', '/backoffice/stats', { guarded: false }),
      route('GET', '/me', { guarded: true }),
    ]);
    expect(targets[0]).toMatchObject({ guarded: false, sensitive: true });
    expect(targets[0]!.why).toEqual([
      'discovered at src/app.js:7',
      'unguarded in code',
      'admin-like: path segment "backoffice"',
    ]);
    expect(targets[1]).toMatchObject({ guarded: true, sensitive: false });
    expect(targets[1]!.why).toEqual(['discovered at src/app.js:7', 'guarded in code']);
  });

  it('marks a route sensitive from an admin-like guard name', () => {
    const { targets } = EndpointMapper.plan([route('GET', '/reports', { guarded: true, guardNames: ['requireAdmin'] })]);
    expect(targets[0]!.sensitive).toBe(true);
    expect(targets[0]!.why).toContain('middleware "requireAdmin"');
  });
});

describe('adminEvidence', () => {
  it.each(['/back-office/stats', '/backoffice', '/staff/users', '/Admin', '/internal/jobs', '/api/v1/superuser', '/admin', '/api/admin/users', '/adminPanel', '/super_admin'])(
    'matches %s',
    (path) => {
      expect(adminEvidence({ path }).length).toBeGreaterThan(0);
    },
  );

  it.each(['/badminton', '/staffing', '/author', '/api/users', '/administered-by', '/', '/health', '/users/:id', '/api/consoles', '/readmin'])(
    'does not match %s',
    (path) => {
      expect(adminEvidence({ path })).toEqual([]);
    },
  );

  it('names the matching segment', () => {
    expect(adminEvidence({ path: '/back-office/stats' })).toEqual(['admin-like: path segment "back-office"']);
  });

  it('ignores parameter segments', () => {
    expect(adminEvidence({ path: '/users/:admin' })).toEqual([]);
    expect(adminEvidence({ path: '/users/{staff}' })).toEqual([]);
  });

  it('uses guard names whose words are in the vocabulary', () => {
    expect(adminEvidence({ path: '/x', guardNames: ['requireAdmin'] })).toEqual(['middleware "requireAdmin"']);
    expect(adminEvidence({ path: '/x', guardNames: ['isStaff'] })).toEqual(['middleware "isStaff"']);
    expect(adminEvidence({ path: '/x', guardNames: ['backofficeOnly'] })).toEqual(['middleware "backofficeOnly"']);
    expect(adminEvidence({ path: '/x', guardNames: ['requireAuth', 'badminton'] })).toEqual([]);
  });

  it('combines path and guard evidence', () => {
    expect(adminEvidence({ path: '/admin', guardNames: ['requireAdmin'] })).toHaveLength(2);
  });
});

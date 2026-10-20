import { buildActiveRequests, planActiveRequests } from '../src/active/requestPlan';
import type { Route } from '../src/types';

const route = (method: string, path: string): Route => ({ method, path, file: 'a', guarded: true });

describe('active/requestPlan', () => {
  const claims = { sub: '1', org_id: 'A' };

  it('fills a user id path param from the sub claim', () => {
    const reqs = buildActiveRequests([route('GET', '/users/:id')], claims);
    expect(reqs.map((r) => r.path)).toContain('/users/1');
  });

  it('fills an org/tenant path param from the tenant claim', () => {
    const reqs = buildActiveRequests([route('GET', '/orgs/:orgId/users')], claims);
    expect(reqs.map((r) => r.path)).toContain('/orgs/A/users');
  });

  it('includes parameterless routes (still useful for the JWT check)', () => {
    const reqs = buildActiveRequests([route('GET', '/health')], claims);
    expect(reqs.map((r) => r.path)).toContain('/health');
  });

  it('only tests safe read methods (GET)', () => {
    const reqs = buildActiveRequests(
      [route('POST', '/users'), route('DELETE', '/users/:id'), route('GET', '/users/:id')],
      claims,
    );
    expect(reqs.every((r) => r.method === 'GET')).toBe(true);
    expect(reqs).toHaveLength(1);
  });

  it('skips routes whose params it cannot fill', () => {
    const reqs = buildActiveRequests([route('GET', '/reports/:slug')], claims);
    expect(reqs).toHaveLength(0);
  });

  it('supports {param} style as well as :param', () => {
    const reqs = buildActiveRequests([route('GET', '/users/{id}')], claims);
    expect(reqs.map((r) => r.path)).toContain('/users/1');
  });

  it('de-duplicates identical resolved paths', () => {
    const reqs = buildActiveRequests([route('GET', '/health'), route('GET', '/health')], claims);
    expect(reqs).toHaveLength(1);
  });
});

describe('active/requestPlan — path param info', () => {
  it('records which segments came from route params', () => {
    const reqs = buildActiveRequests([route('GET', '/orgs/:orgId/users/{id}')], { sub: 'u1', org_id: 'orgA' });
    expect(reqs[0]).toMatchObject({
      path: '/orgs/orgA/users/u1',
      pathParams: [
        { index: 2, name: 'orgId' },
        { index: 4, name: 'id' },
      ],
    });
  });

  it('fills a string id from the sub claim', () => {
    const reqs = buildActiveRequests([route('GET', '/users/:id')], { sub: 'u1' });
    expect(reqs[0]).toMatchObject({ path: '/users/u1', pathParams: [{ index: 2, name: 'id' }] });
  });

  it('omits pathParams for routes without params', () => {
    const reqs = buildActiveRequests([route('GET', '/health')], {});
    expect(reqs[0]!.pathParams).toBeUndefined();
  });
});

describe('active/requestPlan — never invents a path or value', () => {
  const claims = { sub: 'u1', org_id: 'orgA' };
  const r = (method: string, path: string): Route => ({ method, path, file: 'src/a.js', line: 4, guarded: true });

  it('skips pattern/wildcard and partial-parameter routes instead of requesting them literally', () => {
    const plan = planActiveRequests([r('GET', '/files/*'), r('GET', '/v:version/ping'), r('GET', '/a(b)'), r('GET', '/ok')], claims);
    expect(plan.requests.map((q) => q.path)).toEqual(['/ok']);
    expect(plan.skipped.map((s) => s.path)).toEqual(['/files/*', '/v:version/ping', '/a(b)']);
  });

  it('gives a reason for every skipped route and never falls back to a default id', () => {
    const plan = planActiveRequests([r('GET', '/reports/:slug'), r('POST', '/users'), r('GET', '/users/:id')], {});
    expect(plan.requests).toEqual([]);
    expect(plan.skipped).toHaveLength(3);
    expect(plan.skipped[0]!.reason).toMatch(/no claim in your token can fill path parameter "slug"/);
    expect(plan.skipped[1]!.reason).toBe('non-GET route: the scanner never mutates data');
    expect(JSON.stringify(plan)).not.toMatch(/\/users\/1\b/);
  });

  it('logs one [active] line per decision, naming the claim each param came from', () => {
    const plan = planActiveRequests([r('GET', '/orgs/:orgId/users/:id'), r('GET', '/x/:slug')], claims);
    expect(plan.log).toEqual([
      '[active] request GET /orgs/orgA/users/u1: discovered at src/a.js:4; filled "orgId" from claim "org_id", "id" from claim "sub"',
      expect.stringMatching(/^\[active\] skip GET \/x\/:slug: no claim in your token can fill path parameter "slug"/),
    ]);
  });
});

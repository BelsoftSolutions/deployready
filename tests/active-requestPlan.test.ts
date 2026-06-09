import { buildActiveRequests } from '../src/active/requestPlan';
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

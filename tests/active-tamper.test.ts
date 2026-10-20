import { findInjectionPoints, applyInjection } from '../src/active/tamper';
import type { HttpRequestSpec } from '../src/active/types';

describe('active/tamper — injection point discovery', () => {
  it('finds an object id in a path segment', () => {
    const spec: HttpRequestSpec = { method: 'GET', path: '/users/123/posts' };
    const pts = findInjectionPoints(spec);
    const p = pts.find((x) => x.location === 'path' && x.value === '123');
    expect(p).toBeDefined();
    expect(p!.category).toBe('object-id');
  });

  it('classifies query ids vs tenant ids', () => {
    const spec: HttpRequestSpec = { method: 'GET', path: '/api', query: { user_id: '5', org_id: 'A' } };
    const pts = findInjectionPoints(spec);
    expect(pts.find((p) => p.field === 'user_id')!.category).toBe('object-id');
    expect(pts.find((p) => p.field === 'org_id')!.category).toBe('tenant-id');
  });

  it('finds ids nested in a JSON body via a dotted path', () => {
    const spec: HttpRequestSpec = {
      method: 'POST', path: '/x', body: { userId: 1, nested: { tenantId: 'T1' } },
    };
    const pts = findInjectionPoints(spec);
    expect(pts.find((p) => p.field === 'userId')!.category).toBe('object-id');
    expect(pts.find((p) => p.field === 'nested.tenantId')!.category).toBe('tenant-id');
  });

  it('ignores non-id fields', () => {
    const spec: HttpRequestSpec = { method: 'POST', path: '/x', body: { title: 'hi', count: 3 } };
    expect(findInjectionPoints(spec)).toHaveLength(0);
  });
});

describe('active/tamper — applying an injection', () => {
  it('replaces a query id without mutating the original spec', () => {
    const spec: HttpRequestSpec = { method: 'GET', path: '/api', query: { user_id: '5' } };
    const point = findInjectionPoints(spec)[0];
    const out = applyInjection(spec, point, '999');
    expect(out.query!.user_id).toBe('999');
    expect(spec.query!.user_id).toBe('5'); // original untouched
  });

  it('replaces a path segment id', () => {
    const spec: HttpRequestSpec = { method: 'GET', path: '/users/123/posts' };
    const point = findInjectionPoints(spec).find((p) => p.location === 'path')!;
    expect(applyInjection(spec, point, '456').path).toBe('/users/456/posts');
  });

  it('replaces a nested body id by dotted path', () => {
    const spec: HttpRequestSpec = { method: 'POST', path: '/x', body: { nested: { tenantId: 'T1' } } };
    const point = findInjectionPoints(spec).find((p) => p.field === 'nested.tenantId')!;
    const out = applyInjection(spec, point, 'T2');
    expect((out.body as any).nested.tenantId).toBe('T2');
    expect((spec.body as any).nested.tenantId).toBe('T1'); // original untouched
  });
});

describe('active/tamper — route-param-aware path points', () => {
  it('treats a param-derived string id as an injection point', () => {
    const spec: HttpRequestSpec = { method: 'GET', path: '/users/u1', pathParams: [{ index: 2, name: 'id' }] };
    const p = findInjectionPoints(spec).find((x) => x.location === 'path');
    expect(p).toMatchObject({ category: 'object-id', field: '2', value: 'u1' });
    expect(applyInjection(spec, p!, 'u2').path).toBe('/users/u2');
  });

  it('categorises a tenant-named path param as tenant-id', () => {
    for (const name of ['orgId', 'org_id', 'organization', 'tenantId', 'teamId', 'company', 'workspaceId']) {
      const spec: HttpRequestSpec = { method: 'GET', path: '/x/orgA/y', pathParams: [{ index: 2, name }] };
      const p = findInjectionPoints(spec).find((x) => x.location === 'path');
      expect(p?.category).toBe('tenant-id');
    }
  });

  it('categorises other param names as object-id', () => {
    const spec: HttpRequestSpec = { method: 'GET', path: '/posts/p9', pathParams: [{ index: 2, name: 'postId' }] };
    expect(findInjectionPoints(spec).find((x) => x.location === 'path')?.category).toBe('object-id');
  });

  it('does not treat arbitrary literal words as ids', () => {
    const spec: HttpRequestSpec = { method: 'GET', path: '/users/u1/orgA/profile' };
    expect(findInjectionPoints(spec)).toHaveLength(0);
  });

  it('still treats literal numeric/UUID segments without param info as object ids', () => {
    const uuid = '123e4567-e89b-12d3-a456-426614174000';
    const pts = findInjectionPoints({ method: 'GET', path: `/users/123/files/${uuid}` });
    expect(pts.map((p) => [p.category, p.value])).toEqual([['object-id', '123'], ['object-id', uuid]]);
  });

  it('does not duplicate a param segment that also looks numeric', () => {
    const spec: HttpRequestSpec = { method: 'GET', path: '/orgs/5', pathParams: [{ index: 2, name: 'orgId' }] };
    const pts = findInjectionPoints(spec);
    expect(pts).toHaveLength(1);
    expect(pts[0]!.category).toBe('tenant-id');
  });
});

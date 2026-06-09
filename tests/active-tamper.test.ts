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

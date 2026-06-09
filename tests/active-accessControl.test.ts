import { classifyAuthzResult } from '../src/active/accessControl';

describe('active/accessControl', () => {
  it('flags broken access when a tampered request returns 2xx WITH another identity’s data', () => {
    expect(classifyAuthzResult({ status: 200, gotForeignData: true }).verdict).toBe('broken');
    expect(classifyAuthzResult({ status: 201, gotForeignData: true }).verdict).toBe('broken');
  });

  it('treats 401/403/404 as correctly denied', () => {
    expect(classifyAuthzResult({ status: 401, gotForeignData: false }).verdict).toBe('denied');
    expect(classifyAuthzResult({ status: 403, gotForeignData: false }).verdict).toBe('denied');
    expect(classifyAuthzResult({ status: 404, gotForeignData: false }).verdict).toBe('denied');
  });

  it('is inconclusive on a 2xx with no clear foreign data', () => {
    expect(classifyAuthzResult({ status: 200, gotForeignData: false }).verdict).toBe('inconclusive');
  });

  it('is inconclusive on server errors', () => {
    expect(classifyAuthzResult({ status: 500, gotForeignData: false }).verdict).toBe('inconclusive');
  });

  it('always returns a human-readable reason', () => {
    expect(classifyAuthzResult({ status: 200, gotForeignData: true }).reason).toMatch(/access control/i);
    expect(classifyAuthzResult({ status: 403, gotForeignData: false }).reason).toMatch(/denied/i);
  });
});

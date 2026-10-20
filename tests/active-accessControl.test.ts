import { classifyAuthzResult, bodiesEqual } from '../src/active/accessControl';

const own = '{"name":"Alice"}';
const owner = { status: 200, bodyText: '{"name":"Bob"}' };
const base = { status: 200, bodyText: '{"name":"Bob"}', ownBaselineBody: own, ownerBaseline: owner, foreignValue: 'u2' };

describe('active/accessControl', () => {
  it('treats 401/403/404 as correctly denied', () => {
    for (const status of [401, 403, 404]) {
      expect(classifyAuthzResult({ ...base, status, bodyText: 'no' }).verdict).toBe('denied');
    }
  });

  it('is inconclusive on other non-2xx statuses', () => {
    for (const status of [301, 400, 500]) {
      expect(classifyAuthzResult({ ...base, status }).verdict).toBe('inconclusive');
    }
  });

  it('is inconclusive when the tampered 2xx equals the test user’s own baseline (id ignored)', () => {
    const r = classifyAuthzResult({ ...base, bodyText: ' { "name": "Alice" } ' });
    expect(r.verdict).toBe('inconclusive');
    expect(r.reason).toMatch(/own data/);
  });

  it('is broken when the tampered 2xx equals the owner baseline', () => {
    for (const status of [200, 201]) {
      const r = classifyAuthzResult({ ...base, status });
      expect(r.verdict).toBe('broken');
      expect(r.proof).toBe('owner-baseline');
      expect(r.reason).toMatch(/access control/i);
    }
  });

  it('owner-baseline proof does not need the foreign value to appear in the body', () => {
    expect(base.bodyText.includes('u2')).toBe(false);
    expect(classifyAuthzResult({ ...base }).verdict).toBe('broken');
  });

  it('is inconclusive when the owner baseline exists and disagrees, even if the foreign value is echoed', () => {
    const r = classifyAuthzResult({ ...base, bodyText: '{"error":"user u2 not found"}' });
    expect(r.verdict).toBe('inconclusive');
  });

  it('does not accept an empty/trivial matching body as proof', () => {
    for (const t of ['', '{}', '[]', 'null']) {
      const r = classifyAuthzResult({ ...base, bodyText: t, ownerBaseline: { status: 200, bodyText: t } });
      expect(r.verdict).toBe('inconclusive');
    }
  });

  it('falls back to the echo proof when the owner baseline is unavailable', () => {
    const body = '{"id":"u2","note":"x"}';
    for (const ownerBaseline of [null, { status: 403, bodyText: 'no' }, { status: 500, bodyText: 'err' }]) {
      const r = classifyAuthzResult({ ...base, bodyText: body, ownerBaseline });
      expect(r.verdict).toBe('broken');
      expect(r.proof).toBe('echo');
    }
  });

  it('is inconclusive without an owner baseline and without echo', () => {
    const r = classifyAuthzResult({ ...base, bodyText: '{"name":"Carol"}', ownerBaseline: null });
    expect(r.verdict).toBe('inconclusive');
    expect(r.reason).toMatch(/verify manually/);
  });

  it('echoes numeric foreign values too', () => {
    const r = classifyAuthzResult({ ...base, bodyText: '{"id":2}', ownerBaseline: null, foreignValue: 2 });
    expect(r.verdict).toBe('broken');
  });
});

describe('active/accessControl — bodiesEqual', () => {
  it('ignores JSON key order and whitespace, including nested objects', () => {
    expect(bodiesEqual('{"a":1,"b":{"c":[1,2],"d":2}}', '{ "b": {"d":2,"c":[1,2]}, "a": 1 }')).toBe(true);
  });
  it('respects array order and values', () => {
    expect(bodiesEqual('[1,2]', '[2,1]')).toBe(false);
    expect(bodiesEqual('{"a":1}', '{"a":2}')).toBe(false);
  });
  it('compares non-JSON bodies as trimmed text', () => {
    expect(bodiesEqual('  hello\n', 'hello')).toBe(true);
    expect(bodiesEqual('hello', 'world')).toBe(false);
  });
});

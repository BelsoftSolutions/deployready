import { SupabaseHttp, BudgetExceededError, isLoopbackUrl } from '../src/supabase/http';
import { checkOwnership } from '../src/supabase/guard';
import { ANON, SERVICE, OTHER_SERVICE, REF, URL_HOSTED, json, mockTransport } from './helpers/supabaseMock';

describe('supabase/http — the one client', () => {
  it('refuses plain http unless loopback', () => {
    expect(() => new SupabaseHttp({ origin: 'http://abc.supabase.co' })).toThrow(/https/);
    expect(() => new SupabaseHttp({ origin: 'http://127.0.0.1:54321' })).not.toThrow();
    expect(isLoopbackUrl('http://localhost:54321')).toBe(true);
    expect(isLoopbackUrl(URL_HOSTED)).toBe(false);
  });

  it('never leaves its origin', () => {
    const http = new SupabaseHttp({ origin: URL_HOSTED });
    expect(() => http.buildUrl('//evil.example.com/x')).toThrow(/outside/);
    expect(() => http.buildUrl('https://evil.example.com/x')).toThrow(/outside/);
    expect(http.buildUrl('/rest/v1/t', { limit: 1 })).toBe(`${URL_HOSTED}/rest/v1/t?limit=1`);
  });

  it('rate-limits and enforces a request budget', async () => {
    const { transport, sent } = mockTransport(() => ({ status: 200 }));
    const sleeps: number[] = [];
    let t = 1000;
    const http = new SupabaseHttp({
      origin: URL_HOSTED,
      transport,
      minIntervalMs: 250,
      maxRequests: 2,
      sleep: async (ms) => {
        sleeps.push(ms);
        t += ms;
      },
      now: () => t,
    });
    await http.request({ method: 'GET', path: '/a' });
    t += 100;
    await http.request({ method: 'GET', path: '/b' });
    expect(sleeps).toEqual([150]);
    await expect(http.request({ method: 'GET', path: '/c' })).rejects.toBeInstanceOf(BudgetExceededError);
    expect(sent).toHaveLength(2);
  });
});

describe('supabase/guard — ownership gate', () => {
  const project = (handler: Parameters<typeof mockTransport>[0]) => {
    const m = mockTransport(handler);
    return { ...m, http: new SupabaseHttp({ origin: URL_HOSTED, transport: m.transport, minIntervalMs: 0 }) };
  };

  it('allows a loopback project without any request', async () => {
    const m = mockTransport(() => ({ status: 200 }));
    const http = new SupabaseHttp({ origin: 'http://127.0.0.1:54321', transport: m.transport, minIntervalMs: 0 });
    const r = await checkOwnership({ url: 'http://127.0.0.1:54321' }, { project: http });
    expect(r).toMatchObject({ allowed: true, mode: 'local' });
    expect(m.sent).toHaveLength(0);
  });

  it('refuses a hosted project with no proof, sending nothing', async () => {
    const p = project(() => ({ status: 200 }));
    const r = await checkOwnership({ url: URL_HOSTED }, { project: p.http });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/anon key is public/);
    expect(p.sent).toHaveLength(0);
  });

  it('refuses an anon key passed as service key, and a service key for another project, without sending', async () => {
    const p = project(() => ({ status: 200 }));
    const a = await checkOwnership({ url: URL_HOSTED, serviceKey: ANON }, { project: p.http });
    const b = await checkOwnership({ url: URL_HOSTED, serviceKey: OTHER_SERVICE }, { project: p.http });
    expect(a.allowed).toBe(false);
    expect(a.reason).toMatch(/not a service_role/);
    expect(b.allowed).toBe(false);
    expect(b.reason).toMatch(/different project/);
    expect(p.sent).toHaveLength(0);
  });

  it('accepts a service key only when the project accepts it on an admin-only endpoint', async () => {
    const ok = project((r) => (r.path.startsWith('/auth/v1/admin/users') ? { status: 200 } : undefined));
    expect(await checkOwnership({ url: URL_HOSTED, serviceKey: SERVICE }, { project: ok.http })).toMatchObject({
      allowed: true,
      mode: 'service-role',
    });
    expect(ok.sent[0]!.path).toBe('/auth/v1/admin/users?page=1&per_page=1');

    const bad = project(() => ({ status: 401 }));
    const r = await checkOwnership({ url: URL_HOSTED, serviceKey: SERVICE }, { project: bad.http });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/HTTP 401/);
    expect(r.reason).not.toContain(SERVICE);
  });

  it('accepts an access token only when its project list includes the ref', async () => {
    const p = project(() => ({ status: 500 }));
    const listed = mockTransport((r) => (r.url === 'https://api.supabase.com/v1/projects' ? json(200, [{ id: 'other' }, { id: REF }]) : undefined));
    expect(
      await checkOwnership({ url: URL_HOSTED, accessToken: 'sbp_x' }, { project: p.http, managementTransport: listed.transport, minIntervalMs: 0 }),
    ).toMatchObject({ allowed: true, mode: 'access-token' });
    expect(listed.sent[0]!.headers.Authorization).toBe('Bearer sbp_x');

    const notListed = mockTransport(() => json(200, [{ id: 'other' }]));
    const r = await checkOwnership(
      { url: URL_HOSTED, accessToken: 'sbp_x' },
      { project: p.http, managementTransport: notListed.transport, minIntervalMs: 0 },
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/does not list this project/);
    expect(p.sent).toHaveLength(0);
  });

  it('refuses an access token for a custom domain (no project ref to match)', async () => {
    const m = mockTransport(() => ({ status: 500 }));
    const http = new SupabaseHttp({ origin: 'https://db.example.com', transport: m.transport, minIntervalMs: 0 });
    const r = await checkOwnership({ url: 'https://db.example.com', accessToken: 'sbp_x' }, { project: http, managementTransport: m.transport });
    expect(r.allowed).toBe(false);
    expect(m.sent).toHaveLength(0);
  });
});

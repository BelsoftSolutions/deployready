import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runSupabase, resolveCredentials } from '../src/supabase';
import { runLiveChecks, parseCount, parseOpenApi, ownerColumn } from '../src/supabase/live';
import { SupabaseHttp } from '../src/supabase/http';
import { ANON, SERVICE, URL_HOSTED, json, mockTransport, openApi, type Sent } from './helpers/supabaseMock';

const LOCAL = 'http://127.0.0.1:54321';
const USER_A = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLWEtaWQiLCJyb2xlIjoiYXV0aGVudGljYXRlZCJ9.c2lnbmF0dXJlLWFh';
const USER_B = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLWItaWQiLCJyb2xlIjoiYXV0aGVudGljYXRlZCJ9.c2lnbmF0dXJlLWJi';

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-sb-live-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const bearer = (r: Sent): string | undefined => r.headers.Authorization;

/** A small fake project: profiles readable by anon (RLS off), notes protected, one rpc, one public bucket. */
function fakeProject(opts: { crossLeak?: boolean } = {}) {
  return mockTransport((r) => {
    const u = new URL(r.url);
    const p = u.pathname;
    if (p === '/auth/v1/admin/users') return { status: bearer(r) === `Bearer ${SERVICE}` ? 200 : 401 };
    if (p === '/rest/v1/' && r.method === 'GET') {
      if (r.headers.apikey === SERVICE) return { status: 200, bodyText: openApi({ profiles: ['id', 'email', 'full_name'], notes: ['id', 'user_id', 'body'] }, ['get_stats']) };
      return { status: 200, bodyText: openApi({ profiles: ['id', 'email', 'full_name'] }, ['get_stats']) };
    }
    if (r.method === 'HEAD' && p === '/rest/v1/profiles') {
      return { status: 200, headers: { 'content-range': r.headers.apikey === SERVICE ? '0-0/7' : '0-0/7' } };
    }
    if (r.method === 'HEAD' && p === '/rest/v1/notes') {
      const owner = u.searchParams.get('user_id');
      if (owner === 'eq.user-b-id') {
        if (bearer(r) === `Bearer ${USER_B}`) return { status: 200, headers: { 'content-range': '0-0/3' } };
        if (bearer(r) === `Bearer ${USER_A}`) return { status: 200, headers: { 'content-range': opts.crossLeak ? '0-0/3' : '*/0' } };
      }
      return { status: 200, headers: { 'content-range': r.headers.apikey === SERVICE && !owner ? '0-0/12' : '*/0' } };
    }
    if (p === '/storage/v1/bucket') return json(200, [{ id: 'avatars', public: true }, { id: 'private-docs', public: false }]);
    if (p === '/storage/v1/object/list/avatars') return json(200, [{ name: 'secret-user-file.png' }]);
    if (p === '/storage/v1/object/list/private-docs') return json(200, []);
    if (p === '/auth/v1/settings') return json(200, { disable_signup: false, mailer_autoconfirm: true });
    if (p === '/auth/v1/token' && r.method === 'POST') {
      const email = (r.body as { email: string }).email;
      if (email === 'a@test.dev') return json(200, { access_token: USER_A, user: { id: 'user-a-id' } });
      if (email === 'b@test.dev') return json(200, { access_token: USER_B, user: { id: 'user-b-id' } });
      return json(400, { error: 'invalid' });
    }
    return undefined;
  });
}

const env = { SUPABASE_URL: URL_HOSTED, SUPABASE_ANON_KEY: ANON, SUPABASE_SERVICE_ROLE_KEY: SERVICE };
const users = {
  SUPABASE_TEST_USER_A_EMAIL: 'a@test.dev',
  SUPABASE_TEST_USER_A_PASSWORD: 'pw-a-123456',
  SUPABASE_TEST_USER_B_EMAIL: 'b@test.dev',
  SUPABASE_TEST_USER_B_PASSWORD: 'pw-b-123456',
};

describe('supabase/live — parsing', () => {
  it('parses Content-Range counts and the OpenAPI schema', () => {
    expect(parseCount('0-0/42')).toBe(42);
    expect(parseCount('*/0')).toBe(0);
    expect(parseCount('0-0/*')).toBeUndefined();
    expect(parseCount(undefined)).toBeUndefined();
    const s = parseOpenApi(openApi({ t: ['a', 'b'] }, ['f']))!;
    expect(s).toEqual({ tables: ['t'], rpc: ['f'], columns: { t: ['a', 'b'] } });
    expect(parseOpenApi('nope')).toBeUndefined();
    expect(ownerColumn('notes', ['id', 'user_id'])).toBe('user_id');
    expect(ownerColumn('profiles', ['id'])).toBe('id');
    expect(ownerColumn('posts', ['id'])).toBeUndefined();
  });
});

describe('supabase — ownership gate in the full run', () => {
  it('refuses a hosted project with only the (public) anon key and sends nothing', async () => {
    const m = fakeProject();
    const res = await runSupabase(dir, { live: true, delayMs: 0 }, { env: { SUPABASE_URL: URL_HOSTED, SUPABASE_ANON_KEY: ANON }, transport: m.transport });
    expect(res.refused).toBe(true);
    expect(res.liveFindings).toEqual([]);
    expect(m.sent).toHaveLength(0);
    expect(res.notes.join('\n')).toMatch(/refused/);
  });

  it('refuses when the service key does not work for that project; only the ownership request is sent', async () => {
    const m = mockTransport(() => ({ status: 401 }));
    const res = await runSupabase(dir, { live: true, delayMs: 0 }, { env, transport: m.transport });
    expect(res.refused).toBe(true);
    expect(m.sent.map((s) => s.path)).toEqual(['/auth/v1/admin/users?page=1&per_page=1']);
  });

  it('does nothing on the network without --supabase, but hints when a project is detected', async () => {
    fs.writeFileSync(path.join(dir, '.env'), `SUPABASE_URL=${URL_HOSTED}\n`);
    const m = fakeProject();
    const res = await runSupabase(dir, {}, { env, transport: m.transport });
    expect(m.sent).toHaveLength(0);
    expect(res.notes[0]).toMatch(/--supabase/);
  });

  it('allows a loopback project without ownership proof', async () => {
    const m = mockTransport((r) => (r.path.startsWith('/auth/v1/settings') ? json(200, { disable_signup: true }) : { status: 401 }));
    const res = await runSupabase(dir, { live: true, delayMs: 0 }, { env: { SUPABASE_URL: LOCAL, SUPABASE_ANON_KEY: ANON }, transport: m.transport });
    expect(res.refused).toBeUndefined();
    expect(m.sent.every((s) => s.url.startsWith(LOCAL))).toBe(true);
    expect(m.sent.some((s) => s.path === '/auth/v1/settings')).toBe(true);
  });

  it('asks for consent after ownership is proven and stops on "no"', async () => {
    const m = fakeProject();
    const confirm = jest.fn().mockResolvedValue(false);
    const res = await runSupabase(dir, { live: true, delayMs: 0 }, { env, transport: m.transport, confirm });
    expect(confirm).toHaveBeenCalledWith(URL_HOSTED, 'service-role');
    expect(m.sent).toHaveLength(1); // the ownership check only
    expect(res.liveFindings).toEqual([]);
  });
});

describe('supabase — live read-only checks', () => {
  it('proves anon-readable tables with a count and redacted proof, never fetching rows or printing keys', async () => {
    const m = fakeProject();
    const res = await runSupabase(dir, { live: true, delayMs: 0 }, { env, transport: m.transport });
    const byRule = (r: string) => res.liveFindings.filter((f) => f.rule === r);

    const anon = byRule('supabase-anon-read');
    expect(anon).toHaveLength(1);
    expect(anon[0]!.severity).toBe('critical');
    expect(anon[0]!.title).toContain('profiles');
    expect(anon[0]!.evidence).toBe('anon can read 7 of 7 rows');
    expect(anon[0]!.description).toContain('Columns: id, email, full_name');
    expect(anon[0]!.proof).toMatchObject({ status: 200, response: 'Content-Range: 0-0/7' });
    expect(anon[0]!.proof!.request).toContain('-H "apikey: ${SUPABASE_ANON_KEY}"');
    expect(anon[0]!.proof!.control).toMatch(/7 row/);

    expect(byRule('supabase-rpc-anon-executable').map((f) => f.endpoint)).toEqual([`${URL_HOSTED}/rest/v1/rpc/get_stats`]);
    expect(byRule('supabase-storage-public-bucket')).toHaveLength(1);
    expect(byRule('supabase-storage-anon-list').map((f) => f.title)).toEqual(['Anon can list files in storage bucket "avatars"']);
    expect(byRule('supabase-open-signups')[0]!.severity).toBe('info');
    expect(byRule('supabase-email-confirm-off')[0]!.severity).toBe('info');
    expect(byRule('supabase-cross-user-read')).toEqual([]);

    // Read-only: table probes are HEAD; the only POST is the bounded storage list.
    const tableReqs = m.sent.filter((s) => /^\/rest\/v1\/[^/?]+/.test(new URL(s.url).pathname));
    expect(tableReqs.length).toBeGreaterThan(0);
    expect(tableReqs.every((s) => s.method === 'HEAD' && new URL(s.url).searchParams.get('limit') === '1')).toBe(true);
    for (const s of m.sent.filter((x) => x.method === 'POST')) {
      expect(new URL(s.url).pathname).toMatch(/^\/storage\/v1\/object\/list\//);
      expect(s.body).toEqual({ prefix: '', limit: 1, offset: 0 });
    }
    expect(m.sent.every((s) => s.url.startsWith(URL_HOSTED))).toBe(true);

    // Secrets and object names never appear in findings or notes.
    const out = JSON.stringify(res);
    for (const secret of [SERVICE, ANON, 'secret-user-file']) expect(out).not.toContain(secret);
  });

  it('two-user cross-read: critical with proof when A sees B\'s rows; silent when RLS holds', async () => {
    const leak = fakeProject({ crossLeak: true });
    const res = await runSupabase(dir, { live: true, crossUser: true, delayMs: 0 }, { env: { ...env, ...users }, transport: leak.transport });
    // profiles is readable by everyone in this fake, so A also sees B's profile; notes is the owner-scoped leak.
    const cross = res.liveFindings.filter((f) => f.rule === 'supabase-cross-user-read' && f.title.includes('notes'));
    expect(cross).toHaveLength(1);
    expect(cross[0]!.proof!.request).toContain('--oauth2-bearer "${USER_A_ACCESS_TOKEN}"');
    expect(cross[0]!.proof!.request).toContain('user_id=eq.user-b-id');
    expect(cross[0]!.evidence).toBe('signed in as A: 3 row(s) where user_id = B');
    expect(cross[0]!.proof!.control).toMatch(/user B .*3 row/);
    const out = JSON.stringify(res);
    for (const secret of [USER_A, USER_B, 'pw-a-123456', 'pw-b-123456', SERVICE]) expect(out).not.toContain(secret);

    const safe = fakeProject({ crossLeak: false });
    const ok = await runSupabase(dir, { live: true, crossUser: true, delayMs: 0 }, { env: { ...env, ...users }, transport: safe.transport });
    expect(ok.liveFindings.filter((f) => f.rule === 'supabase-cross-user-read' && f.title.includes('notes'))).toEqual([]);
  });

  it('cross-user test is skipped with a clear note when test users are not configured', async () => {
    const m = fakeProject();
    const res = await runSupabase(dir, { live: true, crossUser: true, delayMs: 0 }, { env, transport: m.transport });
    expect(res.notes.join('\n')).toMatch(/SUPABASE_TEST_USER_A_EMAIL/);
    expect(m.sent.some((s) => s.path.startsWith('/auth/v1/token'))).toBe(false);
  });

  it('rate-limits between requests and stops at the request budget', async () => {
    const m = fakeProject();
    const sleeps: number[] = [];
    let t = 0;
    const http = new SupabaseHttp({
      origin: URL_HOSTED,
      transport: m.transport,
      minIntervalMs: 300,
      maxRequests: 4,
      sleep: async (ms) => {
        sleeps.push(ms);
        t += ms;
      },
      now: () => t,
    });
    const res = await runLiveChecks({ http, anonKey: ANON, serviceKey: SERVICE });
    expect(m.sent).toHaveLength(4);
    expect(sleeps).toEqual([300, 300, 300]);
    expect(res.notes.join('\n')).toMatch(/budget \(4\) reached/);
  });

  it('falls back to migration tables when no schema is readable', async () => {
    fs.mkdirSync(path.join(dir, 'supabase', 'migrations'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'supabase', 'migrations', '1.sql'), 'create table public.orders (id int);');
    const m = mockTransport((r) =>
      r.method === 'HEAD' && r.path.startsWith('/rest/v1/orders') ? { status: 200, headers: { 'content-range': '0-0/2' } } : { status: 401 },
    );
    const res = await runSupabase(dir, { live: true, delayMs: 0 }, { env: { SUPABASE_URL: LOCAL, SUPABASE_ANON_KEY: ANON }, transport: m.transport });
    expect(res.liveFindings.map((f) => f.rule)).toEqual(['supabase-anon-read']);
    expect(res.notes.join('\n')).toMatch(/local SQL migrations/);
  });

  it('flags precedence: flags > env > project files; secrets only from flags or env', () => {
    const c = resolveCredentials(
      { url: 'https://flag.supabase.co' },
      { SUPABASE_URL: 'https://env.supabase.co', SUPABASE_ANON_KEY: 'env-anon' },
      { url: 'https://file.supabase.co', anonKey: 'file-anon', migrationTables: [] },
    );
    expect(c).toMatchObject({ url: 'https://flag.supabase.co', anonKey: 'env-anon' });
    expect(c.serviceKey).toBeUndefined();
    expect(c.users).toBeUndefined();
  });
});

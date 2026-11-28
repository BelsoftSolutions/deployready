import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PlaywrightSessionProvider } from '../src/auth/provider';
import {
  SessionExpiredError,
  describeSession,
  ensureGitignored,
  extractHeaders,
  redactHeaders,
  saveSession,
  sessionPath,
  type SessionState,
} from '../src/auth/session';

function jwt(payload: Record<string, unknown>): string {
  const b = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b({ alg: 'HS256', typ: 'JWT' })}.${b(payload)}.c2lnbmF0dXJlLXNpZw`;
}
const FUTURE = Math.floor(Date.now() / 1000) + 3600;
const PAST = Math.floor(Date.now() / 1000) - 3600;
const T = new URL('http://localhost:3000/');

const ck = (name: string, value: string, extra: object = {}) => ({ name, value, domain: 'localhost', path: '/', expires: -1, ...extra });
const st = (over: Partial<SessionState>): SessionState => ({ cookies: [], origins: [], ...over });

describe('extractHeaders', () => {
  it('builds a Cookie header for the target origin only', () => {
    const r = extractHeaders(st({ cookies: [ck('a', '1'), ck('b', '2'), { ...ck('c', '3'), domain: 'evil.com' }] }), T);
    expect(r.headers.Cookie).toBe('a=1; b=2');
    expect(r.hasBearer).toBe(false);
  });

  it('reads supabase sb-*-auth-token JSON access_token', () => {
    const j = jwt({ exp: FUTURE, sub: 'u1' });
    const state = st({ origins: [{ origin: T.origin, localStorage: [{ name: 'sb-abc-auth-token', value: JSON.stringify({ access_token: j, refresh_token: 'r' }) }] }] });
    expect(extractHeaders(state, T).headers.Authorization).toBe(`Bearer ${j}`);
  });

  it.each(['token', 'accessToken', 'jwt'])('reads a raw JWT under %s (also sessionStorage)', (key) => {
    const j = jwt({ exp: FUTURE });
    const ls = st({ origins: [{ origin: T.origin, localStorage: [{ name: key, value: j }] }] });
    expect(extractHeaders(ls, T).headers.Authorization).toBe(`Bearer ${j}`);
    const ss = st({ origins: [{ origin: T.origin, localStorage: [], sessionStorage: [{ name: key, value: j }] }] });
    expect(extractHeaders(ss, T).headers.Authorization).toBe(`Bearer ${j}`);
  });

  it('ignores storage from other origins and non-JWT values', () => {
    const j = jwt({ exp: FUTURE });
    const state = st({
      cookies: [ck('sid', 'x')],
      origins: [
        { origin: 'http://localhost:4000', localStorage: [{ name: 'token', value: j }] },
        { origin: T.origin, localStorage: [{ name: 'token', value: 'not-a-jwt' }] },
      ],
    });
    expect(extractHeaders(state, T).headers.Authorization).toBeUndefined();
  });

  it('keeps a next-auth session cookie as a cookie', () => {
    const r = extractHeaders(st({ cookies: [ck('next-auth.session-token', 'abc', { httpOnly: true })] }), T);
    expect(r.headers.Cookie).toBe('next-auth.session-token=abc');
    expect(r.headers.Authorization).toBeUndefined();
  });

  it('skips Secure cookies on plain http non-loopback but sends them on https', () => {
    const state = st({ cookies: [{ ...ck('s', '1', { secure: true }), domain: 'app.example.com' }] });
    expect(() => extractHeaders(state, new URL('http://app.example.com/'))).toThrow(SessionExpiredError);
    expect(extractHeaders(state, new URL('https://app.example.com/')).headers.Cookie).toBe('s=1');
  });

  it('reports an expired JWT without leaking it', () => {
    const j = jwt({ exp: PAST });
    const state = st({ origins: [{ origin: T.origin, localStorage: [{ name: 'token', value: j }] }] });
    try {
      extractHeaders(state, T);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(SessionExpiredError);
      expect((e as Error).message).toMatch(/session expired.*auth record.*auth login/);
      expect((e as Error).message).not.toContain(j);
    }
  });

  it('reports expired cookies', () => {
    expect(() => extractHeaders(st({ cookies: [ck('a', 'secretvalue', { expires: PAST })] }), T)).toThrow(/expired/);
  });
});

describe('redaction and files', () => {
  it('redacts Cookie/Authorization headers and session summaries', () => {
    const j = jwt({ exp: FUTURE });
    const h = redactHeaders({ Cookie: 'sid=abcdef123456', Authorization: `Bearer ${j}`, Accept: 'x' });
    expect(JSON.stringify(h)).not.toContain('abcdef123456');
    expect(JSON.stringify(h)).not.toContain(j);
    const d = describeSession(st({ cookies: [ck('sid', 'abcdef123456')] }));
    expect(d).not.toContain('abcdef123456');
    expect(d).toContain('1 cookie');
  });

  it('saves with mode 0600 and rejects traversal names', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-auth-'));
    const file = saveSession(root, 'admin', st({ cookies: [ck('a', '1')] }));
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(file).toBe(sessionPath(root, 'admin'));
    expect(() => sessionPath(root, '../x')).toThrow();
  });

  it('adds .deployready/ to .gitignore only when missing', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-gi-'));
    expect(ensureGitignored(root)).toBe(true);
    expect(fs.readFileSync(path.join(root, '.gitignore'), 'utf8')).toContain('.deployready/');
    expect(ensureGitignored(root)).toBe(false);
  });
});

describe('PlaywrightSessionProvider', () => {
  const state = st({ cookies: [ck('sid', 'v1')] });

  it('produces headers for a loopback target', async () => {
    const p = new PlaywrightSessionProvider({ name: 'alice', role: 'user', tenant: 't1', target: 'http://localhost:3000', state });
    expect(p.tenant).toBe('t1');
    expect((await p.headers()).Cookie).toBe('sid=v1');
  });

  it('refuses non-loopback unless owned', () => {
    expect(() => new PlaywrightSessionProvider({ name: 'a', role: 'user', target: 'https://prod.example.com', state })).toThrow(/Refusing/);
    expect(() => new PlaywrightSessionProvider({ name: 'a', role: 'user', target: 'https://prod.example.com', state, ownedHosts: ['prod.example.com'] })).not.toThrow();
  });

  it('refuses to use a session recorded for another origin', async () => {
    const p = new PlaywrightSessionProvider({ name: 'a', role: 'user', target: 'http://localhost:3000', state: { ...state, deployreadyOrigin: 'http://localhost:9999' } });
    await expect(p.headers()).rejects.toThrow(/refusing to use it/);
  });

  it('check() returns the expiry message', async () => {
    const p = new PlaywrightSessionProvider({ name: 'a', role: 'user', target: 'http://localhost:3000', state: st({ cookies: [ck('a', '1', { expires: PAST })] }) });
    expect(await p.check()).toMatch(/session expired/);
  });
});

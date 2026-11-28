import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { scriptedLogin } from '../src/auth/browser';
import { PlaywrightSessionProvider } from '../src/auth/provider';
import { loadSession } from '../src/auth/session';

function jwt(payload: object): string {
  const b = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b({ alg: 'HS256' })}.${b(payload)}.c2lnbmF0dXJlLXNpZw`;
}

let chromiumOk = false;
let server: http.Server;
let base = '';
const TOKEN = jwt({ exp: Math.floor(Date.now() / 1000) + 3600, sub: 'u1' });

beforeAll(async () => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { chromium } = require('playwright');
    const b = await chromium.launch();
    await b.close();
    chromiumOk = true;
  } catch {
    chromiumOk = false;
  }
  server = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/login') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const p = new URLSearchParams(body);
        if (p.get('u') === 'tester' && p.get('p') === 'hunter2pass') {
          res.writeHead(200, { 'Set-Cookie': 'sid=sess123; Path=/; HttpOnly', 'Content-Type': 'text/html' });
          res.end(`<html><body>Welcome<script>localStorage.setItem('token','${TOKEN}')</script></body></html>`);
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body>Bad login<form method="post" action="/login"><input type="password" name="p"></form></body></html>');
        }
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    if (req.url === '/captcha') return void res.end('<html><body><div class="g-recaptcha"></div><input type="password"></body></html>');
    res.end('<html><body><form method="post" action="/login"><input name="u" type="text"><input name="p" type="password"><button type="submit">Go</button></form></body></html>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}, 60_000);

afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe('auth login (Playwright)', () => {
  it('logs in, saves a 0600 session and the provider extracts headers', async () => {
    if (!chromiumOk) return console.warn('chromium unavailable: skipping');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-login-'));
    const file = await scriptedLogin({ root, name: 'tester', url: `${base}/`, username: 'tester', password: 'hunter2pass' });
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(fs.readFileSync(path.join(root, '.gitignore'), 'utf8')).toContain('.deployready/');
    const state = loadSession(root, 'tester');
    const p = new PlaywrightSessionProvider({ name: 'tester', role: 'user', target: base, root });
    const h = await p.headers();
    expect(h.Cookie).toContain('sid=sess123');
    expect(h.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(state.deployreadyOrigin).toBe(new URL(base).origin);
  }, 60_000);

  it('fails clearly on wrong credentials without echoing them', async () => {
    if (!chromiumOk) return console.warn('chromium unavailable: skipping');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-login-'));
    const err = await scriptedLogin({ root, name: 'bad', url: `${base}/`, username: 'tester', password: 'wrongpass99' }).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/did not complete/);
    expect((err as Error).message).not.toContain('wrongpass99');
  }, 60_000);

  it('points to auth record on CAPTCHA', async () => {
    if (!chromiumOk) return console.warn('chromium unavailable: skipping');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-login-'));
    await expect(scriptedLogin({ root, name: 'c', url: `${base}/captcha`, username: 'a', password: 'b' })).rejects.toThrow(/CAPTCHA.*auth record/);
  }, 60_000);

  it('refuses a non-loopback login URL unless owned', async () => {
    await expect(scriptedLogin({ root: os.tmpdir(), name: 'x', url: 'https://prod.example.com/login', username: 'a', password: 'b' })).rejects.toThrow(/Refusing/);
  });
});

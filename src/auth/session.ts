/**
 * Saved browser sessions (Playwright storage state) and pure header extraction.
 *
 * A session file is a SECRET: it holds live cookies and tokens. Nothing in this
 * module ever puts a value into an error message or log line; callers that must
 * show something run it through `redact` (see `describeSession`).
 */
import * as fs from 'fs';
import * as path from 'path';
import { decodeJwt } from '../active/jwt';
import { redact } from '../utils/redact';
import { isIgnored, parseGitignore } from '../utils/GitIgnore';

export interface StoredCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  /** Unix seconds; -1 or undefined for a session cookie. */
  expires?: number;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: string;
}

export interface StoredOrigin {
  origin: string;
  localStorage: Array<{ name: string; value: string }>;
  sessionStorage?: Array<{ name: string; value: string }>;
}

export interface SessionState {
  cookies: StoredCookie[];
  origins: StoredOrigin[];
  /** Origin the user logged in at (set by `auth record` / `auth login`). */
  deployreadyOrigin?: string;
}

export class SessionExpiredError extends Error {
  constructor(reason: string) {
    super(`${reason} - session expired: re-run \`deployready auth record\` or \`deployready auth login\`.`);
    this.name = 'SessionExpiredError';
  }
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function assertSessionName(name: string): string {
  if (!NAME_RE.test(name)) {
    throw new Error('Session name must be 1-64 characters: letters, digits, ".", "_" or "-" (no path separators).');
  }
  return name;
}

export function sessionsDir(root: string): string {
  return path.join(path.resolve(root), '.deployready', 'sessions');
}

export function sessionPath(root: string, name: string): string {
  return path.join(sessionsDir(root), `${assertSessionName(name)}.json`);
}

/** Write a session with mode 0600 (directory 0700). Never prints values. */
export function saveSession(root: string, name: string, state: SessionState): string {
  const file = sessionPath(root, name);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(state), { mode: 0o600 });
  fs.chmodSync(file, 0o600); // writeFileSync's mode is ignored when the file already exists
  return file;
}

export function loadSessionFile(file: string): SessionState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    throw new Error(`Cannot read session file ${file}. Re-run \`deployready auth record\` or \`deployready auth login\`.`);
  }
  const s = parsed as Partial<SessionState> | null;
  if (!s || !Array.isArray(s.cookies) || !Array.isArray(s.origins)) {
    throw new Error(`${file} is not a saved session. Re-run \`deployready auth record\` or \`deployready auth login\`.`);
  }
  return s as SessionState;
}

export function loadSession(root: string, name: string): SessionState {
  return loadSessionFile(sessionPath(root, name));
}

/** Make sure `.deployready/` is git-ignored; append it when it is not. Returns true if the file was changed. */
export function ensureGitignored(root: string): boolean {
  const file = path.join(path.resolve(root), '.gitignore');
  const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  const probe = '.deployready';
  if (isIgnored([{ base: '', rules: parseGitignore(text) }], probe, true)) return false;
  const sep = text === '' || text.endsWith('\n') ? '' : '\n';
  fs.writeFileSync(file, `${text}${sep}# DeployReady saved login sessions (secrets)\n.deployready/\n`);
  return true;
}

// ---------- header extraction ----------

const TOKEN_KEYS = ['token', 'accesstoken', 'access_token', 'jwt', 'idtoken', 'id_token', 'authtoken', 'auth_token'];

function isJwtShape(v: unknown): v is string {
  return typeof v === 'string' && decodeJwt(v) !== null;
}

/** Pull a JWT out of one storage value (raw JWT, JSON object, or JSON-encoded string). */
function jwtFromValue(raw: string, depth = 0): string | null {
  const v = raw.trim();
  if (isJwtShape(v)) return v;
  if (depth > 2 || (v[0] !== '{' && v[0] !== '"' && v[0] !== '[')) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(v);
  } catch {
    return null;
  }
  return jwtFromParsed(parsed, depth);
}

function jwtFromParsed(parsed: unknown, depth: number): string | null {
  if (typeof parsed === 'string') return jwtFromValue(parsed, depth + 1);
  if (Array.isArray(parsed)) {
    for (const item of parsed) if (isJwtShape(item)) return item; // supabase legacy: [access, refresh, ...]
    return null;
  }
  if (parsed && typeof parsed === 'object') {
    const o = parsed as Record<string, unknown>;
    if (isJwtShape(o.access_token)) return o.access_token;
    for (const k of Object.keys(o)) {
      if (TOKEN_KEYS.includes(k.toLowerCase()) && isJwtShape(o[k])) return o[k] as string;
    }
    if (o.currentSession) return jwtFromParsed(o.currentSession, depth + 1);
  }
  return null;
}

/** Find a bearer JWT in a list of storage entries under common keys. */
export function findBearer(entries: Array<{ name: string; value: string }>): string | null {
  const rank = (name: string): number => {
    const n = name.toLowerCase();
    if (/^sb-.+-auth-token$/.test(n) || n === 'supabase.auth.token') return 0;
    if (TOKEN_KEYS.includes(n)) return 1;
    if (/(token|jwt|auth|session)/.test(n)) return 2;
    return 9;
  };
  const sorted = entries.filter((e) => rank(e.name) < 9).sort((a, b) => rank(a.name) - rank(b.name));
  for (const e of sorted) {
    const jwt = jwtFromValue(e.value);
    if (jwt) return jwt;
  }
  return null;
}

function hostMatches(cookieDomain: string, host: string): boolean {
  const d = cookieDomain.toLowerCase();
  if (d.startsWith('.')) return host === d.slice(1) || host.endsWith(d);
  return host === d;
}

export function cookiesForUrl(cookies: StoredCookie[], url: URL, nowSec = Date.now() / 1000): StoredCookie[] {
  const host = url.hostname.toLowerCase();
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  return cookies.filter((c) => {
    if (c.expires !== undefined && c.expires > 0 && c.expires <= nowSec) return false;
    if (!hostMatches(c.domain, host)) return false;
    const p = c.path || '/';
    if (!(url.pathname === p || url.pathname.startsWith(p.endsWith('/') ? p : `${p}/`) || p === '/')) return false;
    if (c.secure && url.protocol !== 'https:' && !loopback) return false;
    return true;
  });
}

export interface ExtractedAuth {
  headers: Record<string, string>;
  cookieNames: string[];
  hasBearer: boolean;
}

/**
 * Build request headers for `target` from a saved session. Throws
 * SessionExpiredError (value-free message) when the session has lapsed.
 */
export function extractHeaders(state: SessionState, target: URL, nowMs = Date.now()): ExtractedAuth {
  const nowSec = nowMs / 1000;
  const headers: Record<string, string> = {};
  const origin = target.origin;

  const live = cookiesForUrl(state.cookies, target, nowSec);
  const sameOrigin = state.origins.filter((o) => o.origin === origin);
  const entries = sameOrigin.flatMap((o) => [...(o.localStorage ?? []), ...(o.sessionStorage ?? [])]);
  const jwt = findBearer(entries);

  if (jwt) {
    const exp = decodeJwt(jwt)?.payload.exp;
    if (typeof exp === 'number' && exp <= nowSec) throw new SessionExpiredError('The saved access token has expired');
    headers.Authorization = `Bearer ${jwt}`;
  }
  if (live.length > 0) headers.Cookie = live.map((c) => `${c.name}=${c.value}`).join('; ');

  if (!headers.Authorization && !headers.Cookie) {
    const lapsed = state.cookies.some((c) => hostMatches(c.domain, target.hostname.toLowerCase()) && c.expires !== undefined && c.expires > 0 && c.expires <= nowSec);
    throw new SessionExpiredError(
      lapsed ? 'All saved cookies for the target have expired' : `The saved session holds no credentials for ${origin}`,
    );
  }
  return { headers, cookieNames: live.map((c) => c.name), hasBearer: Boolean(headers.Authorization) };
}

/** A value-free, redacted one-line summary safe to print. */
export function describeSession(state: SessionState): string {
  const origins = [...new Set([...state.origins.map((o) => o.origin), ...state.cookies.map((c) => c.domain)])];
  const storage = state.origins.reduce((n, o) => n + (o.localStorage?.length ?? 0) + (o.sessionStorage?.length ?? 0), 0);
  return redact(`${state.cookies.length} cookie(s), ${storage} storage item(s) for ${origins.join(', ') || 'no origins'}`);
}

/** Redact request headers (Cookie / Authorization) for logging. */
export function redactHeaders(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) out[k] = /^(cookie|authorization|set-cookie)$/i.test(k) ? '«REDACTED»' : redact(v);
  return out;
}

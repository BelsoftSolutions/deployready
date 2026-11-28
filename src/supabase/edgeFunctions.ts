/**
 * Edge Functions with JWT verification turned off (`[functions.<name>] verify_jwt = false` in
 * supabase/config.toml). The platform then lets ANY request through to the function, signed in or
 * not, so the code itself must authenticate the caller. We read the function's entrypoint (plus
 * the files it imports with a relative path) and report it when it holds the service-role key or
 * touches the database without any of:
 *
 *  - a user check: `supabase.auth.getUser(...)`, `jwtVerify(...)`, `jwt.verify(...)`, a helper
 *    such as `requireUser(req)` / `verifyAuth(req)`;
 *  - a webhook signature check: `stripe.webhooks.constructEvent[Async]`, `new Webhook(...).verify`,
 *    `crypto.subtle.verify`, an HMAC compare, a known signature header (stripe-signature, ...);
 *  - a shared-secret compare against an env var (`req.headers.get('x-cron-secret') !== Deno.env.get(...)`).
 *
 * A function that uses only the anon key and forwards the caller's Authorization header to
 * `createClient` stays under RLS, so it is not reported. Pure; the caller reads the files.
 */
import * as path from 'path';
import { makeFinding } from '../utils/finding';
import type { Finding } from '../types';

export interface EdgeSourceFile {
  relPath: string;
  source: string;
}

export interface FunctionConfig {
  name: string;
  verifyJwt?: boolean;
  entrypoint?: string;
  /** 1-based line of the `[functions.<name>]` header. */
  line: number;
}

export interface EdgeFunctionResult {
  findings: Finding[];
  /** Functions with verify_jwt = false whose code we found and read. */
  checked: number;
  /** verify_jwt = false functions whose entrypoint was not found. */
  missing: string[];
}

/** `[functions.<name>]` sections of supabase/config.toml (only the keys we need). */
export function parseFunctionsToml(toml: string): FunctionConfig[] {
  const out: FunctionConfig[] = [];
  let cur: FunctionConfig | null = null;
  const lines = toml.replace(/\r/g, '').split('\n');
  lines.forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, '').replace(/^#.*$/, '').trim();
    const sec = /^\[\s*functions\.(?:"([^"]+)"|([A-Za-z0-9_-]+))\s*\]$/.exec(line);
    if (sec) {
      cur = { name: sec[1] ?? sec[2]!, line: i + 1 };
      out.push(cur);
      return;
    }
    if (/^\[/.test(line)) {
      cur = null;
      return;
    }
    if (!cur) return;
    const kv = /^([A-Za-z_]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) return;
    const [, key, value] = kv as unknown as [string, string, string];
    if (key === 'verify_jwt') (cur as FunctionConfig).verifyJwt = /^true$/i.test(value.trim()) ? true : /^false$/i.test(value.trim()) ? false : undefined;
    if (key === 'entrypoint') (cur as FunctionConfig).entrypoint = value.trim().replace(/^["']|["']$/g, '');
  });
  return out;
}

const SERVICE_ROLE_RE = /SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY|\bsb_secret_|['"`]service_role['"`]/;
const DB_ACCESS_RE = /\.from\(\s*['"`][\w.-]+['"`]\s*\)|\.rpc\(\s*['"`]|\bauth\.admin\.|\.storage\s*\.from\(|\bnew\s+Pool\s*\(|\bpostgres\s*\(\s*(?:Deno\.env|process\.env|['"`]postgres)|SUPABASE_DB_URL/;
const WRITE_RE = /\.(?:insert|update|upsert|delete)\s*\(|\bauth\.admin\.(?:createUser|deleteUser|updateUserById|inviteUserByEmail)/;
const USER_CHECK_RE =
  /\bauth\.getUser\s*\(|\bauth\.getClaims\s*\(|\bjwtVerify\s*\(|\bjwt\.verify\s*\(|\bverify(?:Jwt|JWT|Token|Auth|User|Request)\w*\s*\(|\b(?:require|ensure|check|get|assert|authenticate)(?:Auth|User|Session|Admin|Caller)\w*\s*\(\s*req\b/;
const SIGNATURE_RE =
  /webhooks\.constructEvent(?:Async)?\s*\(|\bnew\s+Webhook\s*\(|\bverifySignature\w*\s*\(|\bverifyWebhook\w*\s*\(|crypto\.subtle\.verify\s*\(|\btimingSafeEqual\s*\(|\bcreateHmac\s*\(|['"`](?:stripe-signature|x-hub-signature(?:-256)?|x-signature(?:-ed25519)?|svix-signature|webhook-signature|x-webhook-signature|x-slack-signature|x-twilio-signature|x-shopify-hmac-sha256|paddle-signature|x-razorpay-signature)['"`]/i;
const SECRET_COMPARE_RE =
  /(?:headers\.get\([^)]*\)|\b\w*(?:secret|token|key)\w*)\s*[!=]==?\s*(?:Deno\.env\.get|process\.env)|(?:Deno\.env\.get\([^)]*\)|process\.env\.\w+)\s*[!=]==?\s*(?:req\.headers\.get|\w*(?:secret|token|key))/i;
const FORWARDS_AUTH_RE = /headers\.get\(\s*['"`]authorization['"`]\s*\)/i;

function lineOf(source: string, re: RegExp): number {
  const m = re.exec(source);
  if (!m) return 1;
  return source.slice(0, m.index).split('\n').length;
}

/** Entry file + the files it imports by relative path (one level; enough for `_shared/` helpers). */
function functionSources(entry: EdgeSourceFile, byPath: Map<string, EdgeSourceFile>): EdgeSourceFile[] {
  const out = [entry];
  const dir = path.posix.dirname(entry.relPath);
  for (const m of entry.source.matchAll(/\bfrom\s+['"](\.{1,2}\/[^'"]+)['"]|\bimport\s*\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g)) {
    const rel = path.posix.normalize(path.posix.join(dir, m[1] ?? m[2]!));
    const hit = byPath.get(rel) ?? ['.ts', '.js', '/index.ts', '/index.js'].map((x) => byPath.get(rel + x)).find(Boolean);
    if (hit && !out.includes(hit)) out.push(hit);
  }
  return out;
}

/**
 * `configs` are the parsed `[functions.*]` sections of the config.toml at `tomlRelPath`
 * (e.g. `supabase/config.toml`); `files` are the project's source files.
 */
export function analyzeEdgeFunctions(tomlRelPath: string, configs: FunctionConfig[], files: EdgeSourceFile[]): EdgeFunctionResult {
  const res: EdgeFunctionResult = { findings: [], checked: 0, missing: [] };
  const base = path.posix.dirname(tomlRelPath); // .../supabase
  const byPath = new Map(files.map((f) => [f.relPath, f]));
  for (const cfg of configs) {
    if (cfg.verifyJwt !== false) continue;
    const candidates = cfg.entrypoint
      ? [path.posix.normalize(path.posix.join(base, cfg.entrypoint))]
      : ['index.ts', 'index.js', 'index.tsx', 'index.mjs'].map((f) => path.posix.join(base, 'functions', cfg.name, f));
    const entry = candidates.map((c) => byPath.get(c.replace(/^\.\//, ''))).find(Boolean);
    if (!entry) {
      res.missing.push(cfg.name);
      continue;
    }
    res.checked++;
    const srcs = functionSources(entry, byPath);
    const all = srcs.map((s) => s.source).join('\n');
    const service = SERVICE_ROLE_RE.test(all);
    const db = DB_ACCESS_RE.test(all);
    if (!service && !db) continue;
    if (USER_CHECK_RE.test(all) || SIGNATURE_RE.test(all) || SECRET_COMPARE_RE.test(all)) continue;
    // Anon key + the caller's own JWT forwarded to the client: Postgres still applies RLS as the caller.
    if (!service && FORWARDS_AUTH_RE.test(all)) continue;
    const writes = WRITE_RE.test(all);
    const line = lineOf(entry.source, service ? SERVICE_ROLE_RE : DB_ACCESS_RE);
    const url = `https://<project-ref>.supabase.co/functions/v1/${cfg.name}`;
    res.findings.push(
      makeFinding({
        rule: 'edge-function-no-auth',
        title: service
          ? `Edge Function "${cfg.name}" uses the service-role key with JWT verification off and no auth check`
          : `Edge Function "${cfg.name}" reads or writes data with JWT verification off and no auth check`,
        severity: service ? 'critical' : 'warning',
        category: 'security',
        source: 'static',
        file: entry.relPath,
        line,
        owasp: 'A07:2025',
        cwe: 'CWE-306',
        description:
          `Anyone on the internet can call ${url} without signing in and the function will ${writes ? 'change' : 'read'} your data${service ? ' with the service-role key, which bypasses every RLS policy' : ''}. ` +
          `${tomlRelPath}:${cfg.line} sets verify_jwt = false for "${cfg.name}", so the Supabase gateway no longer requires a valid JWT, and the code never authenticates the request ` +
          '(no supabase.auth.getUser() / JWT verification, no webhook signature check, no shared-secret compare).',
        recommendation: service
          ? `Remove verify_jwt = false (the default is true), or authenticate inside the function before using the admin client: const { data: { user } } = await createClient(url, anonKey, { global: { headers: { Authorization: req.headers.get('Authorization')! } } }).auth.getUser(); if (!user) return new Response('Unauthorized', { status: 401 }); ` +
            'For a webhook, verify the provider\'s signature (e.g. await stripe.webhooks.constructEventAsync(body, req.headers.get(\'stripe-signature\')!, secret)).'
          : "Remove verify_jwt = false, or forward the caller's Authorization header to createClient and check supabase.auth.getUser() so RLS applies to the real user; for a webhook, verify its signature.",
        evidence: `${tomlRelPath}: [functions.${cfg.name}] verify_jwt = false`,
      }),
    );
  }
  return res;
}

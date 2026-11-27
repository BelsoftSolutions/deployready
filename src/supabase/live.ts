/**
 * Live, read-only Supabase checks against a project whose ownership the guard
 * has already established. Proves exposure without dumping data:
 *   - row visibility is measured with HEAD + `Prefer: count=exact` + limit=1,
 *     so no row content is ever transferred; evidence is a count plus at most a
 *     few column names taken from the schema (never from rows);
 *   - RPC exposure is read from the anon role's PostgREST OpenAPI document
 *     (functions anon may EXECUTE); no function is invoked;
 *   - storage: bucket metadata plus an anon `list` of at most 1 object (names
 *     are not reported);
 *   - auth: the public /auth/v1/settings document.
 * Optional two-user cross-read (opt-in, test accounts only) uses the same
 * HEAD/count technique. No writes are performed.
 */
import { makeFinding } from '../utils/finding';
import { redact } from '../utils/redact';
import { BudgetExceededError, type SupabaseHttp } from './http';
import { decodeJwt } from '../active/jwt';
import type { Finding } from '../types';

export interface TestUser {
  email: string;
  password: string;
}

export interface LiveContext {
  http: SupabaseHttp;
  anonKey: string;
  serviceKey?: string;
  /** Table names to fall back on when no OpenAPI document is readable (e.g. from migrations). */
  fallbackTables?: string[];
  /** Max tables to probe (default 50). */
  maxTables?: number;
  /** Opt-in two-user cross-read test. */
  crossUser?: { a: TestUser; b: TestUser };
}

export interface LiveResult {
  findings: Finding[];
  /** Plain progress / could-not-check lines for the user (no secrets). */
  notes: string[];
  tablesChecked: number;
}

interface Schema {
  tables: string[];
  rpc: string[];
  /** table -> column names */
  columns: Record<string, string[]>;
}

const OWNER_COLUMNS = ['user_id', 'owner_id', 'owner', 'created_by', 'author_id', 'profile_id', 'account_id', 'uid'];
const SELF_ID_TABLES = new Set(['profiles', 'users', 'accounts', 'user_profiles']);
const MAX_RPC = 20;
const MAX_BUCKETS = 20;

function isJwt(key: string): boolean {
  return decodeJwt(key) !== null;
}

/** Headers for a project key (anon / service). New-format keys go in `apikey` only. */
export function keyHeaders(key: string): Record<string, string> {
  return isJwt(key) ? { apikey: key, Authorization: `Bearer ${key}` } : { apikey: key };
}

function userHeaders(anonKey: string, userJwt: string): Record<string, string> {
  return { apikey: anonKey, Authorization: `Bearer ${userJwt}` };
}

/** Parse the total from a PostgREST Content-Range header ("0-0/42", "*\/0"). */
export function parseCount(contentRange: string | undefined): number | undefined {
  if (!contentRange) return undefined;
  const m = /\/(\d+)\s*$/.exec(contentRange);
  return m ? Number(m[1]) : undefined;
}

/** Tables, RPC functions and column names from a PostgREST OpenAPI (Swagger 2) document. */
export function parseOpenApi(bodyText: string): Schema | undefined {
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(bodyText) as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const paths = doc.paths;
  if (!paths || typeof paths !== 'object') return undefined;
  const tables: string[] = [];
  const rpc: string[] = [];
  for (const p of Object.keys(paths)) {
    if (p === '/') continue;
    if (p.startsWith('/rpc/')) rpc.push(p.slice(5));
    else if (/^\/[^/]+$/.test(p)) tables.push(p.slice(1));
  }
  const columns: Record<string, string[]> = {};
  const defs = doc.definitions;
  if (defs && typeof defs === 'object') {
    for (const [name, def] of Object.entries(defs as Record<string, unknown>)) {
      const props = (def as { properties?: unknown })?.properties;
      if (props && typeof props === 'object') columns[name] = Object.keys(props as object);
    }
  }
  return { tables, rpc, columns };
}

/** Reproducible curl; keys appear only as ${ENV_VAR} placeholders (which redact leaves readable). */
function curl(method: string, url: string, headers: string[], extra = ''): string {
  const flag = method === 'HEAD' ? '-I' : `-X ${method}`;
  const parts = [`curl ${flag} '${url}'`, ...headers.map((h) => `-H "${h}"`)];
  if (extra) parts.push(extra);
  return redact(parts.join(' '));
}

const ANON_H = 'apikey: ${SUPABASE_ANON_KEY}';

function columnHint(cols: string[] | undefined): string {
  if (!cols || cols.length === 0) return '';
  const shown = cols.slice(0, 10).map((c) => redact(c));
  return ` Columns: ${shown.join(', ')}${cols.length > shown.length ? `, … (+${cols.length - shown.length})` : ''}.`;
}

export async function runLiveChecks(ctx: LiveContext): Promise<LiveResult> {
  const findings: Finding[] = [];
  const notes: string[] = [];
  const { http, anonKey } = ctx;
  const base = http.origin;
  let tablesChecked = 0;

  try {
    // ---- 1. Schema discovery ----
    const spec = async (key: string): Promise<Schema | undefined> => {
      const res = await http.request({
        method: 'GET',
        path: '/rest/v1/',
        headers: { ...keyHeaders(key), Accept: 'application/openapi+json' },
      });
      return res.status === 200 ? parseOpenApi(res.bodyText) : undefined;
    };
    const serviceSchema = ctx.serviceKey ? await spec(ctx.serviceKey) : undefined;
    const anonSchema = await spec(anonKey);
    let tables = serviceSchema?.tables ?? anonSchema?.tables ?? [];
    if (tables.length === 0 && ctx.fallbackTables?.length) {
      tables = ctx.fallbackTables;
      notes.push(`No readable OpenAPI schema; checking ${tables.length} table(s) found in local SQL migrations.`);
    }
    const columns = { ...(anonSchema?.columns ?? {}), ...(serviceSchema?.columns ?? {}) };
    const max = ctx.maxTables ?? 50;
    if (tables.length > max) {
      notes.push(`Checking the first ${max} of ${tables.length} tables (cap).`);
      tables = tables.slice(0, max);
    }

    const count = async (table: string, headers: Record<string, string>, filter?: Record<string, string>) => {
      const res = await http.request({
        method: 'HEAD',
        path: `/rest/v1/${encodeURIComponent(table)}`,
        query: { select: '*', limit: 1, ...(filter ?? {}) },
        headers: { ...headers, Prefer: 'count=exact' },
      });
      const ok = res.status === 200 || res.status === 206;
      return { status: res.status, count: ok ? parseCount(res.headers['content-range']) : undefined };
    };

    // ---- 2. Anon read per table ----
    for (const table of tables) {
      tablesChecked++;
      const anon = await count(table, keyHeaders(anonKey));
      if (!anon.count) continue; // denied, empty, or filtered to nothing by RLS
      const total = ctx.serviceKey ? (await count(table, keyHeaders(ctx.serviceKey))).count : undefined;
      const url = http.buildUrl(`/rest/v1/${encodeURIComponent(table)}`, { select: '*', limit: 1 });
      const of = total !== undefined ? ` of ${total}` : '';
      findings.push(
        makeFinding({
          rule: 'supabase-anon-read',
          title: `Supabase table "${redact(table)}" is readable with the public anon key`,
          severity: 'critical',
          category: 'security',
          source: 'dynamic',
          endpoint: `${base}/rest/v1/${table}`,
          owasp: 'A01:2025',
          cwe: 'CWE-284',
          evidence: `anon can read ${anon.count}${of} rows`,
          description: `Anyone with the anon key (it ships in your frontend) can read ${anon.count}${of} row(s) of "${redact(table)}".${columnHint(columns[table])} Row contents were not fetched.`,
          recommendation: `Enable RLS on "${table}" (ALTER TABLE public."${table}" ENABLE ROW LEVEL SECURITY;) and add policies that scope reads to the owner, e.g. USING (auth.uid() = user_id). If the table must be public, expose only the columns you intend via a view.`,
          proof: {
            request: curl('HEAD', url, [ANON_H, 'Prefer: count=exact']),
            status: anon.status,
            response: `Content-Range: 0-0/${anon.count}`,
            control: total !== undefined ? `Same request with the service_role key: ${total} row(s) in total.` : undefined,
          },
        }),
      );
    }

    // ---- 3. RPC functions anon may execute (from anon's own OpenAPI view; nothing invoked) ----
    if (anonSchema) {
      const fns = anonSchema.rpc.slice(0, MAX_RPC);
      for (const fn of fns) {
        findings.push(
          makeFinding({
            rule: 'supabase-rpc-anon-executable',
            title: `RPC function "${redact(fn)}" is callable with the anon key`,
            severity: 'warning',
            category: 'security',
            source: 'dynamic',
            endpoint: `${base}/rest/v1/rpc/${fn}`,
            owasp: 'A01:2025',
            cwe: 'CWE-285',
            evidence: 'listed in the anon role\'s PostgREST OpenAPI schema',
            description: `The anon role has EXECUTE on "${redact(fn)}", so any visitor can call POST /rest/v1/rpc/${redact(fn)}. If it is SECURITY DEFINER or touches other users' data without checking auth.uid(), it bypasses RLS. (The function was not invoked.)`,
            recommendation: `If anon should not call it: REVOKE EXECUTE ON FUNCTION public."${fn}" FROM anon, public; Otherwise make sure it is SECURITY INVOKER or checks auth.uid() itself.`,
          }),
        );
      }
      if (anonSchema.rpc.length > fns.length) notes.push(`${anonSchema.rpc.length - fns.length} more anon-callable RPC function(s) not listed (cap).`);
    } else {
      notes.push('Anon OpenAPI schema not readable: could not determine which RPC functions anon can call.');
    }

    // ---- 4. Storage buckets ----
    const bucketKey = ctx.serviceKey ?? anonKey;
    const bres = await http.request({ method: 'GET', path: '/storage/v1/bucket', headers: keyHeaders(bucketKey) });
    let buckets: { id: string; public?: boolean }[] = [];
    if (bres.status === 200) {
      try {
        const parsed = JSON.parse(bres.bodyText) as unknown;
        if (Array.isArray(parsed)) {
          buckets = parsed
            .filter((b) => b && typeof (b as { id?: unknown }).id === 'string')
            .map((b) => ({ id: (b as { id: string }).id, public: (b as { public?: boolean }).public === true }));
        }
      } catch {
        /* not JSON */
      }
    } else {
      notes.push(`Storage bucket list not readable (HTTP ${bres.status}).`);
    }
    for (const b of buckets.slice(0, MAX_BUCKETS)) {
      if (b.public) {
        findings.push(
          makeFinding({
            rule: 'supabase-storage-public-bucket',
            title: `Storage bucket "${redact(b.id)}" is public`,
            severity: 'warning',
            category: 'security',
            source: 'dynamic',
            endpoint: `${base}/storage/v1/bucket/${b.id}`,
            owasp: 'A01:2025',
            cwe: 'CWE-284',
            evidence: 'bucket.public = true',
            description: `Every object in "${redact(b.id)}" can be downloaded by anyone who has (or guesses) its URL, without auth.`,
            recommendation: 'Keep only truly public assets here. For user files make the bucket private and serve signed URLs (createSignedUrl).',
          }),
        );
      }
      const lres = await http.request({
        method: 'POST',
        path: `/storage/v1/object/list/${encodeURIComponent(b.id)}`,
        headers: keyHeaders(anonKey),
        body: { prefix: '', limit: 1, offset: 0 },
      });
      let listed = 0;
      if (lres.status === 200) {
        try {
          const arr = JSON.parse(lres.bodyText) as unknown;
          listed = Array.isArray(arr) ? arr.length : 0;
        } catch {
          listed = 0;
        }
      }
      if (listed > 0) {
        const url = http.buildUrl(`/storage/v1/object/list/${encodeURIComponent(b.id)}`);
        findings.push(
          makeFinding({
            rule: 'supabase-storage-anon-list',
            title: `Anon can list files in storage bucket "${redact(b.id)}"`,
            severity: 'critical',
            category: 'security',
            source: 'dynamic',
            endpoint: `${base}/storage/v1/object/list/${b.id}`,
            owasp: 'A01:2025',
            cwe: 'CWE-284',
            evidence: 'anon list returned at least 1 object (names not shown)',
            description: `With only the public anon key, anyone can enumerate the files in "${redact(b.id)}"${b.public ? ' and, since the bucket is public, download them' : ''}.`,
            recommendation: 'Remove or narrow the SELECT policy on storage.objects for this bucket (e.g. restrict to auth.uid() = owner, or to a per-user folder).',
            proof: {
              request: curl('POST', url, [ANON_H, 'Content-Type: application/json'], `--data '{"prefix":"","limit":1}'`),
              status: lres.status,
              response: '[1 object] (name withheld)',
            },
          }),
        );
      }
    }

    // ---- 5. Auth settings (public endpoint) ----
    const ares = await http.request({ method: 'GET', path: '/auth/v1/settings', headers: { apikey: anonKey } });
    if (ares.status === 200) {
      try {
        const s = JSON.parse(ares.bodyText) as Record<string, unknown>;
        if (s.disable_signup === false) {
          findings.push(
            makeFinding({
              rule: 'supabase-open-signups',
              title: 'Supabase Auth allows open sign-ups',
              severity: 'info',
              category: 'config',
              source: 'dynamic',
              endpoint: `${base}/auth/v1/settings`,
              evidence: 'disable_signup = false',
              description: 'Anyone can create an account. Every RLS policy written for "authenticated" users therefore applies to strangers too.',
              recommendation: 'If the app is invite-only, disable sign-ups (Authentication → Providers). Otherwise make sure "authenticated" policies still scope rows to auth.uid().',
            }),
          );
        }
        if (s.mailer_autoconfirm === true) {
          findings.push(
            makeFinding({
              rule: 'supabase-email-confirm-off',
              title: 'Supabase Auth does not require email confirmation',
              severity: 'info',
              category: 'config',
              source: 'dynamic',
              endpoint: `${base}/auth/v1/settings#mailer_autoconfirm`,
              evidence: 'mailer_autoconfirm = true',
              description: 'Accounts are usable immediately with any email address, including addresses the person does not own.',
              recommendation: 'Enable "Confirm email" (Authentication → Providers → Email) unless you verify addresses another way.',
            }),
          );
        }
      } catch {
        notes.push('Auth settings were not JSON; skipped.');
      }
    } else {
      notes.push(`Auth settings not readable (HTTP ${ares.status}).`);
    }

    // ---- 6. Two-user cross-read (opt-in) ----
    if (ctx.crossUser) {
      const r = await crossUserRead(ctx, tables, columns, count);
      findings.push(...r.findings);
      notes.push(...r.notes);
    }
  } catch (err) {
    if (err instanceof BudgetExceededError) notes.push(err.message);
    else notes.push(`Live Supabase checks stopped: ${redact((err as Error).message)}`);
  }

  return { findings, notes, tablesChecked };
}

type CountFn = (
  table: string,
  headers: Record<string, string>,
  filter?: Record<string, string>,
) => Promise<{ status: number; count?: number }>;

async function signIn(http: SupabaseHttp, anonKey: string, user: TestUser): Promise<{ jwt: string; id: string } | undefined> {
  const res = await http.request({
    method: 'POST',
    path: '/auth/v1/token',
    query: { grant_type: 'password' },
    headers: { apikey: anonKey },
    body: { email: user.email, password: user.password },
  });
  if (res.status !== 200) return undefined;
  try {
    const j = JSON.parse(res.bodyText) as { access_token?: string; user?: { id?: string } };
    if (typeof j.access_token === 'string' && typeof j.user?.id === 'string') return { jwt: j.access_token, id: j.user.id };
  } catch {
    /* fallthrough */
  }
  return undefined;
}

export function ownerColumn(table: string, cols: string[] | undefined): string | undefined {
  if (!cols) return undefined;
  const hit = OWNER_COLUMNS.find((c) => cols.includes(c));
  if (hit) return hit;
  if (SELF_ID_TABLES.has(table) && cols.includes('id')) return 'id';
  return undefined;
}

async function crossUserRead(
  ctx: LiveContext,
  tables: string[],
  columns: Record<string, string[]>,
  count: CountFn,
): Promise<{ findings: Finding[]; notes: string[] }> {
  const findings: Finding[] = [];
  const notes: string[] = [];
  const { http, anonKey } = ctx;
  const a = await signIn(http, anonKey, ctx.crossUser!.a);
  const b = await signIn(http, anonKey, ctx.crossUser!.b);
  if (!a || !b) {
    notes.push(`Cross-user test skipped: could not sign in test user ${!a ? 'A' : 'B'} with email/password.`);
    return { findings, notes };
  }
  if (a.id === b.id) {
    notes.push('Cross-user test skipped: test users A and B are the same account.');
    return { findings, notes };
  }
  let candidates = 0;
  for (const table of tables) {
    const col = ownerColumn(table, columns[table]);
    if (!col) continue;
    candidates++;
    const filter = { [col]: `eq.${b.id}` };
    const control = await count(table, userHeaders(anonKey, b.jwt), filter);
    if (!control.count) continue; // B owns no visible rows here: nothing to prove
    const leak = await count(table, userHeaders(anonKey, a.jwt), filter);
    if (!leak.count) continue;
    const url = http.buildUrl(`/rest/v1/${encodeURIComponent(table)}`, { select: '*', limit: 1, [col]: `eq.${b.id}` });
    findings.push(
      makeFinding({
        rule: 'supabase-cross-user-read',
        title: `User A can read user B's rows in "${redact(table)}"`,
        severity: 'critical',
        category: 'security',
        source: 'dynamic',
        endpoint: `${http.origin}/rest/v1/${table}#cross-user`,
        owasp: 'A01:2025',
        cwe: 'CWE-639',
        evidence: `signed in as A: ${leak.count} row(s) where ${col} = B`,
        description: `Signed in as test user A, ${leak.count} row(s) of "${redact(table)}" owned by test user B (${col} = B) are visible. RLS does not scope reads to the owner. Row contents were not fetched.`,
        recommendation: `Add/repair the SELECT policy on "${table}": USING (auth.uid() = ${col}). Check that no permissive policy such as USING (true) for "authenticated" remains.`,
        proof: {
          request: curl('HEAD', url, [ANON_H, 'Prefer: count=exact'], '--oauth2-bearer "${USER_A_ACCESS_TOKEN}"'),
          status: leak.status,
          response: `Content-Range: 0-0/${leak.count}`,
          control: `Same request as user B (the owner): ${control.count} row(s).`,
        },
      }),
    );
  }
  if (candidates === 0) notes.push('Cross-user test: no table with an owner column (user_id, owner_id, …) was found in the schema.');
  return { findings, notes };
}

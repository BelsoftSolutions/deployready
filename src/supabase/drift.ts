/**
 * Drift: does the live database still match what the migrations say? Opt-in with
 * `--supabase-db-url` (or `--supabase-db-url` + env SUPABASE_DB_URL), a connection string the
 * user owns. READ-ONLY: the session is opened with `default_transaction_read_only=on`, every query
 * runs inside `BEGIN READ ONLY`, and only pg_catalog / information_schema / storage.buckets
 * (id + public flag, never objects) are read. No row of application data is ever selected.
 *
 * `compareDrift` is pure (model from the migration replay vs a catalog snapshot), so it is tested
 * without a server; `readCatalog` does the I/O through the `pg` package.
 */
import { tokenize } from '../analysis/postgres/lexer';
import { alwaysTrueFor, parseExpr, type Role } from '../analysis/postgres/expr';
import { DEFAULT_EXPOSED, ROLES } from '../analysis/postgres/access';
import { fnKey, tableKey, type DbModel, type PolicyState, type TableState } from '../analysis/postgres/model';
import { classifyBucket, classifyTable, type RlsProjectConfig, type Sensitivity } from '../analysis/postgres/sensitivity';
import { makeFinding } from '../utils/finding';
import { redact } from '../utils/redact';
import type { Finding, Severity } from '../types';

export interface LiveTable {
  schema: string;
  name: string;
  rls: boolean;
  forced: boolean;
}
export interface LivePolicy {
  schema: string;
  table: string;
  name: string;
  permissive: boolean;
  roles: string[];
  cmd: string;
  qual: string | null;
  withCheck: string | null;
}
export interface LiveGrant {
  schema: string;
  table: string;
  grantee: string;
  privilege: string;
}
export interface LiveFunction {
  schema: string;
  name: string;
  securityDefiner: boolean;
  searchPathSet: boolean;
  anonExecute: boolean;
  authenticatedExecute: boolean;
  returnsTrigger: boolean;
}
export interface LiveView {
  schema: string;
  name: string;
  materialized: boolean;
  securityInvoker: boolean;
}
export interface LiveCatalog {
  tables: LiveTable[];
  policies: LivePolicy[];
  grants: LiveGrant[];
  functions: LiveFunction[];
  views: LiveView[];
  realtime: { schema: string; table: string }[];
  buckets: { id: string; public: boolean }[] | null;
}

const SYSTEM = new Set(['auth', 'storage', 'extensions', 'realtime', 'graphql', 'graphql_public', 'vault', 'pgsodium', 'net', 'supabase_functions', 'cron']);
const rank: Record<Sensitivity, number> = { sensitive: 2, unknown: 1, public: 0 };

function sevFor(level: Sensitivity, high: Severity = 'critical', mid: Severity = 'warning'): Severity | null {
  return level === 'sensitive' ? high : level === 'unknown' ? mid : null;
}

/** Is a live policy expression true for every row for `role`? (pg_policies text, re-parsed) */
function liveOpen(text: string | null, role: Role): boolean {
  if (text === null) return false;
  return alwaysTrueFor(parseExpr(tokenize(text)), { role });
}

function modelOpen(p: PolicyState, role: Role): boolean {
  return (p.hasUsing && alwaysTrueFor(p.using, { role })) || (p.hasCheck && alwaysTrueFor(p.check, { role }));
}

function appliesLive(p: LivePolicy, role: Role): boolean {
  return p.roles.some((r) => r === 'public' || r === role);
}

export interface DriftIssue {
  rule: string;
  severity: Severity;
  object: string;
  title: string;
  description: string;
  recommendation: string;
  /** Where the migrations define the object, when they do. */
  file?: string;
  line?: number;
}

/** Compare the migration final state with the live catalog. Pure. */
export function compareDrift(model: DbModel, live: LiveCatalog, cfg: RlsProjectConfig = {}): DriftIssue[] {
  const out: DriftIssue[] = [];
  const exposed = new Set((cfg.exposedSchemas ?? DEFAULT_EXPOSED).map((s) => s.trim().replace(/"/g, '')));
  const managed = [...model.tables.values()].filter((t) => !t.stub);
  const liveTables = new Map(live.tables.map((t) => [tableKey(t.schema, t.name), t]));
  const ruleLoc = (t?: TableState): { file?: string; line?: number } => (t ? { file: t.loc.file, line: t.loc.line } : {});

  // ---- tables + RLS
  for (const lt of live.tables) {
    if (!exposed.has(lt.schema)) continue;
    const mt = model.tables.get(tableKey(lt.schema, lt.name));
    const name = `${lt.schema}.${lt.name}`;
    const v = classifyTable(mt ?? ({ schema: lt.schema, name: lt.name, columns: null } as unknown as TableState), cfg);
    if (mt && !mt.stub) {
      if (mt.rls && !lt.rls) {
        out.push({
          rule: 'drift-rls-disabled',
          severity: sevFor(v.level, 'critical', 'critical') ?? 'warning',
          object: name,
          ...ruleLoc(mt),
          title: `RLS is enabled in the migrations but disabled in the database on ${name}`,
          description: `Your migrations enable Row-Level Security on ${name}, but the live database has it turned off (pg_class.relrowsecurity = false), so every policy is ignored and anyone with the anon key can read and write every row. Someone probably disabled it in the dashboard or with a manual statement.${v.level === 'sensitive' ? ` ${name} holds private data (${v.reason}).` : ''}`,
          recommendation: `alter table ${name} enable row level security; (and keep further changes in migrations, so the database and the repository agree).`,
        });
      }
      continue;
    }
    if (managed.length === 0 || lt.rls) continue;
    const sev = sevFor(v.level);
    if (!sev) continue;
    out.push({
      rule: 'drift-table-unmanaged',
      severity: sev,
      object: name,
      title: `${name} exists in the database without RLS and is not in your migrations`,
      description: `${name} is served by the API but no migration creates it, and it has no Row-Level Security, so anyone with the anon key can read and write every row. Tables created in the dashboard are easy to forget.${v.level === 'sensitive' ? ` The table looks private (${v.reason}).` : ''}`,
      recommendation: `Add it to a migration with RLS: alter table ${name} enable row level security; plus owner-scoped policies (supabase db diff can generate the migration).`,
    });
  }

  // ---- policies
  const livePolicies = new Map<string, LivePolicy[]>();
  for (const p of live.policies) {
    const k = tableKey(p.schema, p.table);
    livePolicies.set(k, [...(livePolicies.get(k) ?? []), p]);
  }
  for (const [k, lps] of livePolicies) {
    const mt = model.tables.get(k);
    const lt = liveTables.get(k);
    const schema = lps[0]!.schema;
    if (!mt || mt.stub || (!exposed.has(schema) && schema !== 'storage')) continue;
    const name = `${schema}.${lps[0]!.table}`;
    const v = classifyTable(mt, cfg);
    for (const lp of lps) {
      const mp = mt.policies.get(lp.name);
      const openRoles = ROLES.filter((r) => lp.permissive && appliesLive(lp, r) && (liveOpen(lp.qual, r) || liveOpen(lp.withCheck, r)));
      if (!mp) {
        const sev = openRoles.length && (lt?.rls ?? true) ? sevFor(v.level) ?? 'info' : 'info';
        out.push({
          rule: 'drift-policy-added',
          severity: sev,
          object: `${name} policy "${lp.name}"`,
          ...ruleLoc(mt),
          title: `Policy "${lp.name}" on ${name} exists only in the database${openRoles.length ? ` and opens every row to ${openRoles.join(', ')}` : ''}`,
          description: `The live database has a ${lp.permissive ? 'permissive' : 'restrictive'} policy "${lp.name}" (FOR ${lp.cmd}, TO ${lp.roles.join(', ')}, USING ${lp.qual ?? '—'}, WITH CHECK ${lp.withCheck ?? '—'}) that no migration creates.${openRoles.length ? ` It is true for every row, so ${openRoles.join(' and ')} can reach all of ${name}, whatever your migrations say.` : ' Review it and either add it to a migration or drop it.'}`,
          recommendation: `drop policy "${lp.name}" on ${name}; or, if it is intended, add it to a migration so code review sees it.`,
        });
        continue;
      }
      const mOpen = ROLES.filter((r) => mp.permissive && mp.roles.some((x) => x === 'public' || x === r) && modelOpen(mp, r));
      const widened = openRoles.filter((r) => !mOpen.includes(r));
      const shapeChanged = mp.permissive !== lp.permissive || (mp.command === 'all' ? 'ALL' : mp.command.toUpperCase()) !== lp.cmd.toUpperCase();
      if (widened.length || shapeChanged) {
        out.push({
          rule: 'drift-policy-changed',
          severity: widened.length ? sevFor(v.level) ?? 'warning' : 'warning',
          object: `${name} policy "${lp.name}"`,
          file: mp.loc.file,
          line: mp.loc.line,
          title: `Policy "${lp.name}" on ${name} differs between the migrations and the database`,
          description: `In the database the policy is ${lp.permissive ? 'permissive' : 'restrictive'} FOR ${lp.cmd} USING ${lp.qual ?? '—'} WITH CHECK ${lp.withCheck ?? '—'}; the migrations define it as ${mp.permissive ? 'permissive' : 'restrictive'} FOR ${mp.command.toUpperCase()} USING ${mp.usingText || '—'} WITH CHECK ${mp.checkText || '—'}.${widened.length ? ` The live version is true for every row for ${widened.join(' and ')}.` : ''}`,
          recommendation: `Re-apply the migration's definition (drop policy "${lp.name}" on ${name}; then create it as in ${mp.loc.file}), and make future changes through migrations.`,
        });
      }
    }
    for (const mp of mt.policies.values()) {
      if (lps.some((lp) => lp.name === mp.name)) continue;
      out.push({
        rule: 'drift-policy-missing',
        severity: mp.permissive ? 'info' : 'warning',
        object: `${name} policy "${mp.name}"`,
        file: mp.loc.file,
        line: mp.loc.line,
        title: `Policy "${mp.name}" on ${name} is in the migrations but not in the database`,
        description: `The migrations create ${mp.permissive ? 'permissive' : 'restrictive'} policy "${mp.name}" on ${name}, but the live database has no such policy.${mp.permissive ? ' Requests it should allow are denied (or allowed by another policy).' : ' A missing restrictive policy means rows it should hide are visible.'}`,
        recommendation: 'Re-run the migration that creates it (supabase db push) or find out who dropped it.',
      });
    }
  }
  // tables with policies in the model but none live
  for (const mt of managed) {
    const k = tableKey(mt.schema, mt.name);
    if (!exposed.has(mt.schema) || livePolicies.has(k) || !liveTables.has(k)) continue;
    for (const mp of mt.policies.values()) {
      out.push({
        rule: 'drift-policy-missing',
        severity: mp.permissive ? 'info' : 'warning',
        object: `${mt.schema}.${mt.name} policy "${mp.name}"`,
        file: mp.loc.file,
        line: mp.loc.line,
        title: `Policy "${mp.name}" on ${mt.schema}.${mt.name} is in the migrations but not in the database`,
        description: `The migrations create policy "${mp.name}" on ${mt.schema}.${mt.name}, but the live database has no policy on that table.`,
        recommendation: 'Re-run the migration that creates it (supabase db push) or find out who dropped it.',
      });
    }
  }

  // ---- table grants: anon / authenticated privileges the migrations revoked
  const liveGrants = new Map<string, Set<string>>();
  for (const g of live.grants) {
    const k = `${tableKey(g.schema, g.table)}\u0000${g.grantee.toLowerCase()}`;
    liveGrants.set(k, (liveGrants.get(k) ?? new Set()).add(g.privilege.toLowerCase()));
  }
  for (const mt of managed) {
    if (!exposed.has(mt.schema) || !liveTables.has(tableKey(mt.schema, mt.name))) continue;
    for (const role of ROLES) {
      const lg = liveGrants.get(`${tableKey(mt.schema, mt.name)}\u0000${role}`) ?? new Set<string>();
      const mg = mt.grants.get(role) ?? new Set<string>();
      const extra = [...lg].filter((p) => ['select', 'insert', 'update', 'delete'].includes(p) && !mg.has(p as never) && !mt.grants.get('public')?.has(p as never));
      if (!extra.length) continue;
      const v = classifyTable(mt, cfg);
      out.push({
        rule: 'drift-grant-added',
        severity: rank[v.level] >= 1 ? 'warning' : 'info',
        object: `${mt.schema}.${mt.name} (${role})`,
        file: mt.loc.file,
        line: mt.loc.line,
        title: `${role} holds ${extra.join(', ').toUpperCase()} on ${mt.schema}.${mt.name} in the database but not in the migrations`,
        description: `Your migrations leave ${role} without ${extra.join(', ')} on ${mt.schema}.${mt.name} (a REVOKE locked it down), but the live database grants it. Only RLS now stands in the way.`,
        recommendation: `revoke ${extra.join(', ')} on ${mt.schema}.${mt.name} from ${role};`,
      });
    }
  }

  // ---- functions
  for (const lf of live.functions) {
    if (SYSTEM.has(lf.schema) || lf.returnsTrigger) continue;
    const mf = model.functions.get(fnKey(lf.schema, lf.name));
    const name = `${lf.schema}.${lf.name}`;
    const callers = [lf.anonExecute ? 'anon' : '', lf.authenticatedExecute ? 'authenticated' : ''].filter(Boolean);
    if (!mf) {
      if (lf.securityDefiner && exposed.has(lf.schema) && callers.length && model.functions.size > 0) {
        out.push({
          rule: 'drift-function-unmanaged',
          severity: 'warning',
          object: name,
          title: `SECURITY DEFINER function ${name} exists only in the database and is callable by ${callers.join(', ')}`,
          description: `${name} runs with its owner's privileges, ${callers.join(' and ')} can call it through /rest/v1/rpc/${lf.name}, and no migration defines it, so nobody reviewed it.`,
          recommendation: `Add it to a migration (with set search_path = '' and the narrowest EXECUTE grants), or drop it.`,
        });
      }
      continue;
    }
    const loc = { file: mf.loc.file, line: mf.loc.line };
    if (lf.securityDefiner && !mf.securityDefiner) {
      out.push({
        rule: 'drift-function-definer',
        severity: exposed.has(lf.schema) && callers.length ? 'critical' : 'warning',
        object: name,
        ...loc,
        title: `${name} is SECURITY DEFINER in the database but SECURITY INVOKER in the migrations`,
        description: `The live function runs with its owner's privileges and so bypasses RLS on every table it touches; the migrations define it as security invoker.${callers.length ? ` ${callers.join(' and ')} can call it.` : ''}`,
        recommendation: `alter function ${name} security invoker;`,
      });
    }
    if (lf.securityDefiner && mf.searchPath !== null && !lf.searchPathSet) {
      out.push({
        rule: 'drift-function-search-path',
        severity: 'warning',
        object: name,
        ...loc,
        title: `${name} lost its fixed search_path in the database`,
        description: `The migrations pin search_path on this SECURITY DEFINER function, but the live function has none (pg_proc.proconfig), so it resolves names through the caller's search_path (CWE-426).`,
        recommendation: `alter function ${name} set search_path = '${mf.searchPath.replace(/'/g, '')}';`,
      });
    }
    const mCallers = ROLES.filter((r) => mf.execute.has(r) || mf.execute.has('public'));
    const extra = callers.filter((r) => !mCallers.includes(r as Role));
    if (extra.length && mf.securityDefiner) {
      out.push({
        rule: 'drift-function-execute',
        severity: 'warning',
        object: name,
        ...loc,
        title: `${extra.join(', ')} can execute ${name} in the database although the migrations revoke it`,
        description: `The migrations revoke EXECUTE on this SECURITY DEFINER function from ${extra.join(' and ')}, but the live database lets ${extra.join(' and ')} call it via /rest/v1/rpc/${lf.name}.`,
        recommendation: `revoke execute on function ${name} from public, ${extra.join(', ')};`,
      });
    }
  }

  // ---- views
  for (const lv of live.views) {
    if (!exposed.has(lv.schema)) continue;
    const mv = model.views.get(tableKey(lv.schema, lv.name));
    if (!mv || !mv.securityInvoker || lv.securityInvoker || lv.materialized) continue;
    let level: Sensitivity = 'unknown';
    for (const t of mv.sources) if (rank[classifyTable(t, cfg).level] > rank[level]) level = classifyTable(t, cfg).level;
    out.push({
      rule: 'drift-view-invoker',
      severity: sevFor(level) ?? 'info',
      object: `${lv.schema}.${lv.name}`,
      file: mv.loc.file,
      line: mv.loc.line,
      title: `View ${lv.schema}.${lv.name} lost security_invoker in the database`,
      description: `The migrations create the view WITH (security_invoker = true), but the live view has no such option, so it runs as its owner and bypasses RLS on ${mv.sources.map((t) => `${t.schema}.${t.name}`).join(', ') || 'its tables'}.`,
      recommendation: `alter view ${lv.schema}.${lv.name} set (security_invoker = true);`,
    });
  }

  // ---- realtime
  const mPub = model.publications.get('supabase_realtime');
  const inModel = (schema: string, table: string): boolean =>
    Boolean(mPub && (mPub.allTables || mPub.schemas.has(schema) || [...mPub.tables.keys()].some((t) => t.schema === schema && t.name === table)));
  for (const r of live.realtime) {
    if (!exposed.has(r.schema) || inModel(r.schema, r.table)) continue;
    const mt = model.tables.get(tableKey(r.schema, r.table));
    const lt = liveTables.get(tableKey(r.schema, r.table));
    const v = classifyTable(mt ?? ({ schema: r.schema, name: r.table, columns: null } as unknown as TableState), cfg);
    const sev = sevFor(v.level, lt && !lt.rls ? 'critical' : 'warning', 'warning');
    if (!sev) continue;
    out.push({
      rule: 'drift-realtime-added',
      severity: sev,
      object: `${r.schema}.${r.table}`,
      ...ruleLoc(mt),
      title: `${r.schema}.${r.table} is broadcast by Realtime in the database but not in your migrations`,
      description: `The live supabase_realtime publication includes ${r.schema}.${r.table}; no migration adds it. Every change is pushed to subscribers that its SELECT policies allow${lt && !lt.rls ? ', and the table has no RLS, so that is everyone' : ''}.`,
      recommendation: `alter publication supabase_realtime drop table ${r.schema}.${r.table}; or add it in a migration after checking its SELECT policies.`,
    });
  }

  // ---- buckets
  for (const b of live.buckets ?? []) {
    if (!b.public) continue;
    const mb = model.buckets.get(b.id);
    if (mb?.public) continue;
    const v = classifyBucket(b.id, cfg);
    const sev = sevFor(v.level);
    if (!sev) continue;
    out.push({
      rule: 'drift-bucket-public',
      severity: sev,
      object: `storage bucket "${b.id}"`,
      ...(mb ? { file: mb.loc.file, line: mb.loc.line } : {}),
      title: `Storage bucket "${b.id}" is public in the database${mb ? ' but private in the migrations' : ''}`,
      description: `Anyone with a file's path can download it from "${b.id}" without signing in. ${mb ? 'Your migrations create it as private; someone switched it to public.' : 'No migration creates this bucket.'}${v.level === 'sensitive' ? ` The name suggests private files (${v.reason}).` : ''}`,
      recommendation: `update storage.buckets set public = false where id = '${b.id}';`,
    });
  }
  return out;
}

// ------------------------------------------------------------------ I/O

/** A connection string with the password masked, for messages. */
export function maskDbUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.password) u.password = '****';
    return redact(u.toString());
  } catch {
    return 'postgres://<invalid url>';
  }
}

export function isDbUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return (u.protocol === 'postgres:' || u.protocol === 'postgresql:') && Boolean(u.hostname);
  } catch {
    return false;
  }
}

export type QueryFn = (sql: string) => Promise<Record<string, unknown>[]>;

/** The catalog queries (all read-only, catalog / information_schema only). */
export const CATALOG_SQL = {
  roles: `select rolname from pg_roles where rolname in ('anon', 'authenticated')`,
  tables: `select n.nspname as schema, c.relname as name, c.relrowsecurity as rls, c.relforcerowsecurity as forced
             from pg_class c join pg_namespace n on n.oid = c.relnamespace
            where c.relkind in ('r', 'p') and n.nspname = any($SCHEMAS)`,
  policies: `select schemaname as schema, tablename as "table", policyname as name, permissive = 'PERMISSIVE' as permissive,
                    roles::text[] as roles, cmd, qual, with_check as "withCheck"
               from pg_policies where schemaname = any($SCHEMAS) or (schemaname = 'storage' and tablename = 'objects')`,
  grants: `select table_schema as schema, table_name as "table", grantee, privilege_type as privilege
             from information_schema.role_table_grants
            where grantee in ('anon', 'authenticated', 'PUBLIC') and table_schema = any($SCHEMAS)`,
  functions: `select n.nspname as schema, p.proname as name, p.prosecdef as "securityDefiner",
                     coalesce(exists (select 1 from unnest(p.proconfig) x where x like 'search_path=%'), false) as "searchPathSet",
                     $ANON as "anonExecute", $AUTH as "authenticatedExecute",
                     p.prorettype = 'trigger'::regtype or p.prorettype = 'event_trigger'::regtype as "returnsTrigger"
                from pg_proc p join pg_namespace n on n.oid = p.pronamespace
               where p.prokind = 'f' and n.nspname = any($SCHEMAS)`,
  views: `select n.nspname as schema, c.relname as name, c.relkind = 'm' as materialized,
                 coalesce(exists (select 1 from unnest(c.reloptions) o where o in ('security_invoker=true', 'security_invoker=on', 'security_invoker=1', 'security_invoker=yes')), false) as "securityInvoker"
            from pg_class c join pg_namespace n on n.oid = c.relnamespace
           where c.relkind in ('v', 'm') and n.nspname = any($SCHEMAS)`,
  realtime: `select schemaname as schema, tablename as "table" from pg_publication_tables where pubname = 'supabase_realtime'`,
  bucketsExists: `select to_regclass('storage.buckets') is not null as ok`,
  buckets: `select id::text as id, public from storage.buckets`,
} as const;

function schemasLiteral(schemas: string[]): string {
  return `array[${schemas.map((s) => `'${s.replace(/'/g, "''")}'`).join(', ')}]::text[]`;
}

/** Read the catalog snapshot. Every query goes through `q`, which must run read-only. */
export async function readCatalog(q: QueryFn, schemas: string[]): Promise<LiveCatalog> {
  const all = [...new Set([...schemas, 'storage'])];
  const sub = (sql: string): string => sql.replace(/\$SCHEMAS/g, schemasLiteral(all));
  const roles = new Set((await q(CATALOG_SQL.roles)).map((r) => String(r.rolname)));
  const exec = (role: string): string => (roles.has(role) ? `has_function_privilege('${role}', p.oid, 'execute')` : 'false');
  const tables = (await q(sub(CATALOG_SQL.tables))) as unknown as LiveTable[];
  const policies = ((await q(sub(CATALOG_SQL.policies))) as unknown as LivePolicy[]).map((p) => ({
    ...p,
    roles: (Array.isArray(p.roles) ? p.roles : String(p.roles).replace(/[{}]/g, '').split(',')).map((r) => String(r).trim().toLowerCase()),
  }));
  const grants = (await q(sub(CATALOG_SQL.grants))) as unknown as LiveGrant[];
  const functions = (await q(sub(CATALOG_SQL.functions).replace('$ANON', exec('anon')).replace('$AUTH', exec('authenticated')))) as unknown as LiveFunction[];
  const views = (await q(sub(CATALOG_SQL.views))) as unknown as LiveView[];
  const realtime = (await q(CATALOG_SQL.realtime)) as unknown as LiveCatalog['realtime'];
  const hasBuckets = Boolean((await q(CATALOG_SQL.bucketsExists))[0]?.ok);
  const buckets = hasBuckets ? ((await q(CATALOG_SQL.buckets)) as unknown as { id: string; public: boolean }[]) : null;
  return { tables, policies, grants, functions, views, realtime, buckets };
}

export interface DriftConnectOptions {
  /** Statement timeout per query (ms). */
  timeoutMs?: number;
}

/**
 * Open a read-only session with `pg`, run `fn`, always close. The session is started with
 * `-c default_transaction_read_only=on`, re-checked with `SHOW`, and every query runs inside
 * `BEGIN READ ONLY ... ROLLBACK`.
 */
export async function withReadOnlyDb<T>(dbUrl: string, fn: (q: QueryFn) => Promise<T>, o: DriftConnectOptions = {}): Promise<T> {
  // Loaded lazily: only drift runs need a Postgres driver.
  const pg = require('pg') as typeof import('pg');
  const timeout = o.timeoutMs ?? 15000;
  const client = new pg.Client({
    connectionString: dbUrl,
    options: `-c default_transaction_read_only=on -c statement_timeout=${timeout}`,
    connectionTimeoutMillis: timeout,
    application_name: 'deployready-drift',
  });
  await client.connect();
  try {
    await client.query('set session characteristics as transaction read only');
    const ro = await client.query('show default_transaction_read_only');
    if (String(ro.rows[0]?.default_transaction_read_only) !== 'on') throw new Error('could not make the session read-only; refusing to continue');
    const q: QueryFn = async (sql) => {
      await client.query('begin read only');
      try {
        return (await client.query(sql)).rows as Record<string, unknown>[];
      } finally {
        await client.query('rollback');
      }
    };
    return await fn(q);
  } finally {
    await client.end().catch(() => undefined);
  }
}

export function driftFindings(issues: DriftIssue[], dbUrl: string): Finding[] {
  const where = maskDbUrl(dbUrl);
  return issues.map((i) =>
    makeFinding({
      rule: i.rule,
      title: i.title,
      severity: i.severity,
      category: 'security',
      source: 'dynamic',
      file: i.file,
      line: i.line,
      endpoint: `postgres:${i.object}`,
      owasp: 'A01:2025',
      cwe: i.rule.includes('search-path') ? 'CWE-426' : 'CWE-284',
      description: i.description,
      recommendation: i.recommendation,
      proof: { request: redact(`read-only catalog query on ${where} (pg_class, pg_policies, information_schema.role_table_grants, pg_proc, pg_publication_tables, storage.buckets)`) },
    }),
  );
}

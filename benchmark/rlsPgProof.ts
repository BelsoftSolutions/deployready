/**
 * Ground-truth check for the RLS corpus against a REAL PostgreSQL server.
 *
 *   PGHOST=/tmp PGPORT=5432 PGUSER=postgres npx tsx benchmark/rlsPgProof.ts [case-id-substring]
 *
 * Not part of `benchmark/run.ts` (it needs a superuser on a disposable Postgres). For every
 * `corpus/rls/<case>` it creates a fresh database, installs a minimal Supabase-like
 * environment (anon / authenticated / service_role roles, default table grants in `public`,
 * `auth.uid()` / `auth.role()` / `auth.jwt()` reading `request.jwt.claims`), applies the
 * case's migrations in filename order, seeds rows owned by user B as superuser, and then runs
 * each `groundTruth.probes` entry as anon or as signed-in user A:
 *
 *  - `read`  is open when the count query returns more than 0 rows (B's rows are visible);
 *  - `write` is open when the statement succeeds and touches at least one row.
 *
 * Each probe states the expected `open`; `groundTruth.insecure` must equal "any probe open".
 * Exit code 1 if any label disagrees with what Postgres actually does.
 */
import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';

const ROOT = path.join(__dirname, 'corpus', 'rls');
const USER_A = '00000000-0000-0000-0000-00000000000a';

interface Probe {
  as: 'anon' | 'user_a';
  kind: 'read' | 'write';
  sql: string;
  open: boolean;
}
interface GroundTruth {
  insecure: boolean;
  seed: string;
  probes: Probe[];
}

const BOOTSTRAP_ROLES = `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin noinherit; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin noinherit; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin noinherit bypassrls; end if;
end $$;`;

const BOOTSTRAP_DB = `
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
create schema auth;
grant usage on schema auth to anon, authenticated, service_role;
create table auth.users (id uuid primary key);
create function auth.jwt() returns jsonb language sql stable as
  $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
create function auth.uid() returns uuid language sql stable as $$ select nullif(auth.jwt() ->> 'sub', '')::uuid $$;
create function auth.role() returns text language sql stable as $$ select auth.jwt() ->> 'role' $$;
grant execute on all functions in schema auth to anon, authenticated, service_role;`;

function psql(db: string, sql: string): { ok: boolean; out: string; err: string } {
  const r = spawnSync('psql', ['-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1', '-d', db], { input: sql, encoding: 'utf8' });
  return { ok: r.status === 0, out: r.stdout ?? '', err: r.stderr ?? String(r.error ?? '') };
}

function migrationsOf(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.sql')) out.push(p);
    }
  };
  walk(dir);
  return out.sort();
}

function asRole(p: Probe): string {
  const claims = p.as === 'anon' ? { role: 'anon' } : { sub: USER_A, role: 'authenticated' };
  return `set role ${p.as === 'anon' ? 'anon' : 'authenticated'};\nselect set_config('request.jwt.claims', '${JSON.stringify(claims)}', true);\n`;
}

function runProbe(db: string, p: Probe): { open: boolean; detail: string } {
  if (p.kind === 'read') {
    const r = psql(db, `begin;\n${asRole(p)}${p.sql};\nrollback;\n`);
    if (!r.ok) return { open: false, detail: r.err.trim().split('\n')[0] ?? 'error' };
    const lines = r.out.trim().split('\n');
    const n = Number(lines[lines.length - 1]);
    return { open: n > 0, detail: `count=${n}` };
  }
  const body = `do $probe$ declare n int; begin ${p.sql}; get diagnostics n = row_count; raise notice 'rows=%', n; end $probe$;`;
  const r = psql(db, `begin;\n${asRole(p)}${body}\nrollback;\n`);
  if (!r.ok) return { open: false, detail: r.err.trim().split('\n')[0] ?? 'error' };
  const rows = Number(/rows=(\d+)/.exec(r.err)?.[1] ?? '0');
  return { open: rows > 0, detail: `rows=${rows}` };
}

function main(): void {
  const filter = process.argv[2] ?? '';
  const admin = process.env.PGDATABASE ?? 'postgres';
  if (!psql(admin, 'select 1;').ok) {
    console.error('Cannot reach PostgreSQL (set PGHOST/PGPORT/PGUSER to a disposable server).');
    process.exit(2);
  }
  psql(admin, BOOTSTRAP_ROLES);
  let bad = 0;
  const ids = fs.readdirSync(ROOT).filter((d) => d.includes(filter)).sort();
  for (const id of ids) {
    const dir = path.join(ROOT, id);
    const spec = JSON.parse(fs.readFileSync(path.join(dir, 'expect.json'), 'utf8')) as { groundTruth?: GroundTruth };
    const gt = spec.groundTruth;
    if (!gt) continue;
    const db = `rls_${id.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`.slice(0, 60);
    psql(admin, `drop database if exists ${db};`);
    psql(admin, `create database ${db};`);
    const boot = psql(db, BOOTSTRAP_DB);
    if (!boot.ok) throw new Error(`${id}: bootstrap failed: ${boot.err}`);
    let failed = '';
    for (const file of migrationsOf(dir)) {
      const r = psql(db, fs.readFileSync(file, 'utf8'));
      if (!r.ok) failed = `${path.relative(dir, file)}: ${r.err.trim().split('\n')[0]}`;
      if (failed) break;
    }
    if (!failed && gt.seed) {
      const r = psql(db, gt.seed);
      if (!r.ok) failed = `seed: ${r.err.trim().split('\n')[0]}`;
    }
    const results = failed ? [] : gt.probes.map((p) => ({ p, ...runProbe(db, p) }));
    const anyOpen = results.some((r) => r.open);
    const wrong = results.filter((r) => r.open !== r.p.open);
    const ok = !failed && wrong.length === 0 && anyOpen === gt.insecure;
    if (!ok) bad++;
    console.log(`${ok ? 'OK  ' : 'FAIL'} ${id}  insecure=${anyOpen}${failed ? `  (${failed})` : ''}`);
    for (const r of results) console.log(`       ${r.p.as.padEnd(6)} ${r.p.kind.padEnd(5)} open=${r.open} (expected ${r.p.open}) ${r.detail}  ${r.p.sql.slice(0, 70)}`);
    psql(admin, `drop database if exists ${db};`);
  }
  console.log(bad === 0 ? `\nAll ${ids.length} ground-truth labels confirmed by PostgreSQL.` : `\n${bad} case(s) disagree with PostgreSQL.`);
  process.exit(bad === 0 ? 0 : 1);
}

main();

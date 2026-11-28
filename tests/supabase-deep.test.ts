import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { fnKey, replayMigrations, tableKey } from '../src/analysis/postgres/model';
import { analyzeSupabaseObjects } from '../src/analysis/postgres/deep';
import { classifyBucket, columnSensitivity } from '../src/analysis/postgres/sensitivity';
import { parseRlsConfig } from '../src/analysis/postgres/config';
import { analyzeSql } from '../src/analysis/rls';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { analyzeEdgeFunctions, parseFunctionsToml } from '../src/supabase/edgeFunctions';
import { scanSupabaseFiles, scanSupabaseStatic } from '../src/supabase/static';
import { compareDrift, isDbUrl, maskDbUrl, readCatalog, withReadOnlyDb, type LiveCatalog } from '../src/supabase/drift';
import { runSupabase, supabaseCoverage } from '../src/supabase';
import { buildCoverage, CoverageRecorder } from '../src/core/coverage';

const FILE = 'supabase/migrations/001.sql';
const model = (sql: string) => replayMigrations([{ relPath: FILE, source: sql }]);
const objects = (sql: string, config = {}) => analyzeSupabaseObjects(model(sql), { supabase: true, config });
const rules = (sql: string, config = {}) => objects(sql, config).map((i) => `${i.rule}:${i.severity}`);

const INV = `create table public.invoices (id bigint primary key, user_id uuid not null, amount int);
alter table public.invoices enable row level security;
create policy "own" on public.invoices for select to authenticated using ((select auth.uid()) = user_id);
`;

describe('postgres/model — functions, views, triggers, buckets, publications, column grants', () => {
  it('tracks SECURITY DEFINER, SET search_path, and EXECUTE (PUBLIC + Supabase anon/authenticated defaults)', () => {
    const m = model(`create function public.f(p uuid) returns int language sql security definer set search_path = '' as $$ select 1 $$;
      create function private.g() returns int language plpgsql as $$ begin return 1; end $$;
      revoke execute on function public.f(uuid) from public;`);
    const f = m.functions.get(fnKey('public', 'f'))!;
    expect([f.securityDefiner, f.searchPath, [...f.execute].sort()]).toEqual([true, "''", ['anon', 'authenticated', 'service_role']]);
    const g = m.functions.get(fnKey('private', 'g'))!;
    expect([g.securityDefiner, g.searchPath, [...g.execute]]).toEqual([false, null, ['public']]);
  });

  it('applies ALTER FUNCTION, CREATE OR REPLACE (keeps grants), DROP and default privileges on functions', () => {
    const m = model(`alter default privileges in schema public revoke execute on functions from anon, authenticated;
      alter default privileges revoke execute on functions from public;
      create function public.f() returns int language sql as $$ select 1 $$;
      alter function public.f() security definer;
      alter function public.f() set search_path to public, pg_temp;
      grant execute on function public.f to authenticated;
      create or replace function public.f() returns int language sql security definer as $$ select 2 $$;
      create function public.gone() returns int language sql as $$ select 1 $$;
      drop function public.gone();`);
    const f = m.functions.get(fnKey('public', 'f'))!;
    expect([f.securityDefiner, f.searchPath, [...f.execute].sort()]).toEqual([true, null, ['authenticated', 'service_role']]);
    expect(m.functions.has(fnKey('public', 'gone'))).toBe(false);
  });

  it('CREATE OR REPLACE VIEW without WITH resets security_invoker (as Postgres 16 does); ALTER VIEW SET / RESET', () => {
    const base = INV + 'create view public.v with (security_invoker = true) as select * from public.invoices;\n';
    expect(model(base).views.get(tableKey('public', 'v'))!.securityInvoker).toBe(true);
    expect(model(base + 'create or replace view public.v as select * from public.invoices;').views.get(tableKey('public', 'v'))!.securityInvoker).toBe(false);
    expect(model(base + 'alter view public.v reset (security_invoker);').views.get(tableKey('public', 'v'))!.securityInvoker).toBe(false);
    const v = model(INV + 'create view public.v as select i.id from public.invoices i join public.invoices j on j.id = i.id; alter view public.v set (security_invoker);').views.get(tableKey('public', 'v'))!;
    expect([v.securityInvoker, v.sources.map((t) => t.name)]).toEqual([true, ['invoices']]);
  });

  it('a grant on a view goes to the view, not a stub table', () => {
    const m = model(INV + 'create view public.v as select * from public.invoices; revoke select on public.v from anon;');
    expect(m.tables.has(tableKey('public', 'v'))).toBe(false);
    expect(m.views.get(tableKey('public', 'v'))!.grants.get('anon')?.has('select')).toBe(false);
  });

  it('replays storage.buckets inserts, ON CONFLICT, UPDATE and DELETE', () => {
    const m = model(`insert into storage.buckets (id, name, public) values ('a', 'a', false), ('b', 'b', true);
      insert into storage.buckets (id, name, public) values ('a', 'a', true) on conflict (id) do nothing;
      insert into storage.buckets (id, name, public) values ('b', 'b', false) on conflict (id) do update set public = excluded.public;
      insert into storage.buckets (id, name) values ('c', 'c');
      update storage.buckets set public = true where id = 'c';
      insert into storage.buckets (id, name, public) values ('d', 'd', true);
      delete from storage.buckets where id = 'd';`);
    expect([...m.buckets.values()].map((b) => `${b.id}:${b.public}`)).toEqual(['a:false', 'b:false', 'c:true']);
  });

  it('tracks the supabase_realtime publication, and DROP TABLE takes the table out', () => {
    const m = model(`create table public.a (id int); create table public.b (id int);
      alter publication supabase_realtime add table public.a, public.b;
      alter publication supabase_realtime drop table public.b;
      drop table public.a;`);
    const pub = m.publications.get('supabase_realtime')!;
    expect([...pub.tables.keys()].filter((t) => m.tables.get(tableKey(t.schema, t.name)) === t)).toEqual([]);
    expect(model('create publication supabase_realtime for all tables;').publications.get('supabase_realtime')!.allTables).toBe(true);
  });

  it('triggers move with RENAME and resolve their function', () => {
    const m = model(`create table public.t (id int);
      create function public.tf() returns trigger language plpgsql security definer as $$ begin return new; end $$;
      create trigger tr before insert or update on public.t for each row execute procedure public.tf();
      alter table public.t rename to t2;`);
    const tr = m.tables.get(tableKey('public', 't2'))!.triggers.get('tr')!;
    expect([tr.timing, tr.events, tr.fnParts]).toEqual(['before', ['insert', 'update'], ['public', 'tf']]);
  });

  it('keeps column-level grants apart from table privileges; REVOKE removes them', () => {
    const m = model(`create table public.p (id uuid, email text); revoke select on public.p from anon;
      grant select (id, email) on public.p to anon; revoke select (email) on public.p from anon; grant select (id) on public.p to anon;`);
    const t = m.tables.get(tableKey('public', 'p'))!;
    expect(t.grants.get('anon')?.has('select')).toBe(false);
    expect([...new Set(t.columnGrants.flatMap((g) => g.columns))]).toEqual(['id']);
  });
});

describe('postgres/deep — storage', () => {
  it('public bucket: critical when the name looks private, warning when unknown, nothing for avatars', () => {
    expect(rules("insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);")).toEqual(['storage-bucket-public:critical']);
    expect(rules("insert into storage.buckets (id, name, public) values ('stuff', 'stuff', true);")).toEqual(['storage-bucket-public:warning']);
    expect(rules("insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);")).toEqual([]);
    expect(rules("insert into storage.buckets (id, name, public) values ('stuff', 'stuff', true);", { publicBuckets: ['stuff'] })).toEqual([]);
    expect(rules("insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);", { sensitiveBuckets: ['avatars'] })).toEqual(['storage-bucket-public:critical']);
  });

  it('bucket-only policies are reported; owner / folder checks are not', () => {
    const b = "insert into storage.buckets (id, name) values ('docs', 'docs');\n";
    expect(rules(b + "create policy r on storage.objects for select to authenticated using (bucket_id = 'docs');")).toEqual(['storage-policy-permissive:critical']);
    expect(rules(b + "create policy w on storage.objects for insert to anon with check (bucket_id = 'docs');")).toEqual(['storage-policy-permissive:critical']);
    expect(rules(b + "create policy r on storage.objects for select to authenticated using (bucket_id = 'docs' and (storage.foldername(name))[1] = auth.uid()::text);")).toEqual([]);
    expect(rules(b + "create policy r on storage.objects for select using (bucket_id = 'docs' and owner_id = (select auth.uid())::text);")).toEqual([]);
    // a policy with no bucket filter covers every bucket
    expect(rules(b + 'create policy r on storage.objects for select to authenticated using (true);')).toEqual(['storage-policy-permissive:critical']);
  });

  it('judges each bucket of an OR separately, and a restrictive policy closes the gap', () => {
    const sql = "create policy r on storage.objects for select to authenticated using ((bucket_id = 'documents' and owner_id = auth.uid()::text) or bucket_id = 'avatars');";
    expect(rules(sql)).toEqual([]);
    expect(rules("create policy r on storage.objects for select to authenticated using (bucket_id = 'documents'); create policy g on storage.objects as restrictive for select to authenticated using (owner_id = auth.uid()::text);")).toEqual([]);
  });

  it('upload to a public-assets bucket by any signed-in user is fine; by anon it is a warning', () => {
    expect(rules("create policy u on storage.objects for insert to authenticated with check (bucket_id = 'avatars');")).toEqual([]);
    expect(rules("create policy u on storage.objects for insert to anon with check (bucket_id = 'avatars');")).toEqual(['storage-policy-permissive:warning']);
  });
});

describe('postgres/deep — SECURITY DEFINER functions', () => {
  it('a definer RPC reading an RLS table without checking the caller bypasses RLS (critical)', () => {
    const issues = objects(INV + "create function public.inv(u uuid) returns setof public.invoices language sql security definer set search_path = public as $$ select * from invoices where user_id = u $$;");
    expect(issues.map((i) => [i.rule, i.severity])).toEqual([['security-definer-rls-bypass', 'critical']]);
    expect(issues[0]!.description).toMatch(/rpc\/inv/);
    expect(issues[0]!.recommendation).toMatch(/security invoker/);
  });

  it('revoking from PUBLIC alone leaves anon (Supabase default); revoking from anon and authenticated closes it', () => {
    const fn = "create function public.inv(u uuid) returns bigint language sql security definer set search_path = '' as $$ select count(*) from public.invoices where user_id = u $$;\n";
    expect(rules(INV + fn + 'revoke execute on function public.inv(uuid) from public;')).toEqual(['security-definer-rls-bypass:critical']);
    expect(rules(INV + fn + 'revoke execute on function public.inv(uuid) from public, anon, authenticated;')).toEqual([]);
    expect(rules(INV + fn + "alter function public.inv(uuid) security invoker;")).toEqual([]);
  });

  it('missing search_path is a CWE-426 warning in any project schema, not in Supabase-owned ones', () => {
    const i = objects('create function private.h() returns int language sql security definer as $$ select 1 $$;');
    expect(i.map((x) => [x.rule, x.severity, x.cwe])).toEqual([['security-definer-search-path', 'warning', 'CWE-426']]);
    expect(rules('create function auth.h() returns int language sql security definer as $$ select 1 $$;')).toEqual([]);
    expect(rules("create function private.h() returns int language sql security definer as $$ select 1 $$; alter function private.h() set search_path = '';")).toEqual([]);
  });

  it('an exposed definer function that does not touch private data: warning for anon, info once it checks the caller', () => {
    expect(rules("create function public.ping() returns int language sql security definer set search_path = '' as $$ select 1 $$;")).toEqual(['security-definer-exposed:warning']);
    expect(rules("create function public.me() returns uuid language sql security definer set search_path = '' as $$ select auth.uid() $$;")).toEqual(['security-definer-exposed:info']);
    expect(rules("create function public.me() returns uuid language sql security definer set search_path = '' as $$ select auth.uid() $$; revoke execute on function public.me from public, anon, authenticated;")).toEqual([]);
  });
});

describe('postgres/deep — views, triggers, Realtime, grants', () => {
  it('a view over an RLS table without security_invoker is critical; invoker, caller-scoped or revoked views are not', () => {
    expect(rules(INV + 'create view public.v as select * from public.invoices;')).toEqual(['view-rls-bypass:critical']);
    expect(rules(INV + 'create view public.v with (security_invoker = on) as select * from public.invoices;')).toEqual([]);
    expect(rules(INV + 'create view public.v as select * from public.invoices where user_id = auth.uid();')).toEqual([]);
    expect(rules(INV + 'create view public.v as select * from public.invoices; revoke all on public.v from anon, authenticated;')).toEqual([]);
    expect(rules(INV + 'create schema private; create view private.v as select * from public.invoices;')).toEqual([]);
    expect(rules(INV + 'create materialized view public.mv as select * from public.invoices;')).toEqual(['view-rls-bypass:critical']);
  });

  it('flags a definer trigger copying new.role into a roles table, not a fixed value or app metadata', () => {
    const t = `create table public.profiles (id uuid primary key, role text default 'user');
      alter table public.profiles enable row level security;
      create policy own on public.profiles for update to authenticated using (auth.uid() = id);
      create table public.admins (user_id uuid);
      alter table public.admins enable row level security;\n`;
    const fn = (v: string) => `create function public.sync() returns trigger language plpgsql security definer set search_path = '' as $$ begin if ${v} = 'admin' then insert into public.admins (user_id) values (new.id); end if; return new; end $$;
      create trigger s after update on public.profiles for each row execute function public.sync();`;
    expect(rules(t + fn('new.role'))).toEqual(['trigger-privilege-escalation:critical']);
    expect(rules(t + fn("new.raw_app_meta_data->>'role'"))).toEqual([]);
    expect(rules(t + fn('new.role') + ' revoke update on public.profiles from authenticated;')).toEqual([]);
  });

  it('Realtime on a sensitive table with an open SELECT policy is critical; owner policies or public tables are fine', () => {
    const base = 'create table public.chat_messages (id int, user_id uuid); alter table public.chat_messages enable row level security; alter publication supabase_realtime add table public.chat_messages;\n';
    expect(rules(base + 'create policy p on public.chat_messages for select using (true);')).toEqual(['realtime-table-exposed:critical']);
    expect(rules(base + 'create policy p on public.chat_messages for select using (auth.uid() = user_id);')).toEqual([]);
    expect(rules('create table public.products (id int); alter publication supabase_realtime add table public.products;')).toEqual([]);
  });

  it('column grants: a secret or personal column readable by everyone is reported; RLS-scoped rows are not', () => {
    const p = 'create table public.accounts (id uuid, username text, api_key text); alter table public.accounts enable row level security; revoke select on public.accounts from anon, authenticated;\n';
    expect(rules(p + 'create policy r on public.accounts for select using (true); grant select (id, api_key) on public.accounts to authenticated;')).toEqual(['grant-sensitive-column:critical']);
    expect(rules(p + 'create policy r on public.accounts for select using (auth.uid() = id); grant select (id, api_key) on public.accounts to authenticated;')).toEqual([]);
    expect(rules(p + 'create policy r on public.accounts for select using (true); grant select (id, username) on public.accounts to anon;')).toEqual([]);
    expect([columnSensitivity('password_hash'), columnSensitivity('Email'), columnSensitivity('username')]).toEqual(['secret', 'pii', null]);
  });

  it('default privileges: skip public (Supabase defaults), warn for every schema or an exposed one, info for private', () => {
    expect(rules('alter default privileges in schema public grant all on tables to anon;')).toEqual([]);
    expect(rules('alter default privileges grant all on tables to anon;')).toEqual(['grant-default-privileges-anon:warning']);
    expect(rules('alter default privileges in schema api grant insert on tables to anon;', { exposedSchemas: ['public', 'api'] })).toEqual(['grant-default-privileges-anon:warning']);
    expect(rules('alter default privileges in schema private grant execute on functions to anon;')).toEqual(['grant-default-privileges-anon:info']);
    expect(rules('alter default privileges in schema api grant select on tables to anon;')).toEqual([]);
  });

  it('a blanket GRANT ON ALL TABLES is reported only when it re-opens tables an earlier REVOKE locked down', () => {
    const t = 'create table public.events (id int); alter table public.events enable row level security; create policy p on public.events for select using (false);\n';
    expect(rules(t + 'grant all on all tables in schema public to anon;')).toEqual([]);
    expect(rules(t + 'revoke all on public.events from anon; grant all on all tables in schema public to anon;')).toEqual(['grant-all-tables-anon:warning']);
    expect(rules(t + 'grant all on all tables in schema public to anon; revoke all on public.events from anon;')).toEqual([]);
  });

  it('plain Postgres projects (no Supabase signal, no RLS) are not checked', () => {
    expect(analyzeSupabaseObjects(model('create function public.f() returns int language sql security definer as $$ select 1 $$;'), {})).toEqual([]);
  });

  it('analyzeSql reports an object-check crash without losing the RLS results', () => {
    const res = analyzeSql([{ relPath: FILE, source: 'create table public.users (id int);' }], { supabase: true, config: { exposedSchemas: null as unknown as string[] } });
    expect(res.rls.map((i) => i.kind)).toEqual(['missing']);
    expect(res.objectsError).toBeUndefined();
  });

  it('config keys for buckets are parsed', () => {
    expect(parseRlsConfig({ publicBuckets: ['a'], sensitiveBuckets: ['b', 3] })).toEqual({ publicBuckets: ['a'], sensitiveBuckets: ['b'] });
    expect(classifyBucket('user-uploads', {}).level).toBe('sensitive');
    expect(classifyBucket('product-images', {}).level).toBe('public');
  });
});

describe('supabase/edgeFunctions', () => {
  const toml = `[api]\nschemas = ["public"]\n\n[functions.hook]\nverify_jwt = false # webhooks\n\n[functions."other-fn"]\nverify_jwt = true\nentrypoint = "./functions/other-fn/main.ts"\n`;
  const fn = (name: string, source: string) => ({ relPath: `supabase/functions/${name}/index.ts`, source });
  const SERVICE = "const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);\n";

  it('parses [functions.<name>] sections', () => {
    expect(parseFunctionsToml(toml).map((c) => [c.name, c.verifyJwt, c.entrypoint ?? null, c.line])).toEqual([
      ['hook', false, null, 4],
      ['other-fn', true, './functions/other-fn/main.ts', 7],
    ]);
  });

  it('service role + no auth = critical; anon-only data access = warning; no data access = nothing', () => {
    const run = (src: string) => analyzeEdgeFunctions('supabase/config.toml', parseFunctionsToml(toml), [fn('hook', src)]);
    expect(run(SERVICE + "Deno.serve(async (req) => { await admin.from('orders').update({ paid: true }); return new Response('ok'); });").findings.map((f) => f.severity)).toEqual(['critical']);
    expect(run("const c = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!); Deno.serve(async () => { await c.from('orders').select('*'); return new Response('ok'); });").findings.map((f) => f.severity)).toEqual(['warning']);
    expect(run("Deno.serve(() => new Response('hello'));").findings).toEqual([]);
  });

  it('accepts getUser, signature checks, shared-secret compares, and imported auth helpers', () => {
    const run = (files: { relPath: string; source: string }[]) => analyzeEdgeFunctions('supabase/config.toml', parseFunctionsToml(toml), files).findings;
    const data = "await admin.from('orders').delete();";
    expect(run([fn('hook', SERVICE + `const { data: { user } } = await anonClient.auth.getUser(token); ${data}`)])).toEqual([]);
    expect(run([fn('hook', SERVICE + `const sig = req.headers.get('x-hub-signature-256'); ${data}`)])).toEqual([]);
    expect(run([fn('hook', SERVICE + `if (req.headers.get('x-cron-secret') !== Deno.env.get('CRON_SECRET')) return new Response('no', { status: 401 }); ${data}`)])).toEqual([]);
    expect(
      run([
        fn('hook', "import { requireUser } from '../_shared/auth.ts';\n" + SERVICE + `await requireUser(req); ${data}`),
        { relPath: 'supabase/functions/_shared/auth.ts', source: 'export async function requireUser(req: Request) {}' },
      ]),
    ).toEqual([]);
    // anon key + forwarded Authorization header: RLS applies as the caller
    expect(run([fn('hook', `const c = createClient(u, Deno.env.get('SUPABASE_ANON_KEY')!, { global: { headers: { Authorization: req.headers.get('Authorization')! } } }); await c.from('orders').select();`)])).toEqual([]);
  });

  it('reports functions whose code is missing, and skips verify_jwt = true', () => {
    const r = analyzeEdgeFunctions('supabase/config.toml', parseFunctionsToml(toml), [fn('other-fn', SERVICE)]);
    expect([r.checked, r.missing, r.findings.length]).toEqual([0, ['hook'], 0]);
  });

  it('runs inside the Supabase static scan, reading supabase/config.toml from disk', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-edge-'));
    fs.mkdirSync(path.join(dir, 'supabase', 'functions', 'hook'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'supabase', 'config.toml'), toml);
    fs.writeFileSync(path.join(dir, 'supabase', 'functions', 'hook', 'index.ts'), SERVICE + "await admin.auth.admin.deleteUser(id);\n");
    const res = await scanSupabaseStatic(dir);
    expect(res.findings.map((f) => [f.rule, f.severity, f.file])).toEqual([['edge-function-no-auth', 'critical', 'supabase/functions/hook/index.ts']]);
    expect(res.edgeFunctions).toEqual({ checked: 1, missing: [] });
    expect(res.detected.configFiles).toBe(1);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('an Edge Function check crash is reported in coverage, not swallowed', () => {
    const res = scanSupabaseFiles([{ relPath: 'supabase/config.toml', source: { split: () => [] } as unknown as string }]);
    expect(res.edgeFunctions?.error).toBeTruthy();
    expect(supabaseCoverage({ staticFindings: [], liveFindings: [], notes: [], detected: true, edge: res.edgeFunctions }, false).static.state).toBe('failed');
  });
});

// Every supabase-deep benchmark case must pass in `npm test` too.
describe('benchmark/corpus/supabase-deep expectations', () => {
  const root = path.join(__dirname, '..', 'benchmark', 'corpus', 'supabase-deep');
  const ids = fs.readdirSync(root).filter((d) => fs.statSync(path.join(root, d)).isDirectory()).sort();
  it('has vulnerable and safe twins for every area', () => {
    for (const area of ['st', 'fn', 'vw', 'tg', 'rt', 'gr', 'ef']) {
      expect(ids.some((i) => i.startsWith(area) && i.endsWith('-tp'))).toBe(true);
      expect(ids.some((i) => i.startsWith(area) && i.endsWith('-tn'))).toBe(true);
    }
  });
  it.each(ids)('%s', async (id) => {
    const dir = path.join(root, id);
    const spec = JSON.parse(fs.readFileSync(path.join(dir, 'expect.json'), 'utf8')) as { expected: { rule: string; present: boolean; file?: string; severity?: string }[] };
    const findings = [...(await VulnerabilityDetector.scan(dir)), ...(await scanSupabaseStatic(dir)).findings];
    for (const e of spec.expected) {
      const hit = findings.some((f) => f.rule === e.rule && (!e.file || f.file === e.file) && (!e.severity || f.severity === e.severity));
      expect(`${e.rule} ${e.present ? 'present' : 'absent'}: ${hit === e.present}`).toBe(`${e.rule} ${e.present ? 'present' : 'absent'}: true`);
    }
    const mentioned = new Set(spec.expected.map((e) => e.rule));
    expect(findings.filter((f) => !mentioned.has(f.rule)).map((f) => f.rule)).toEqual([]);
  });
});

// ------------------------------------------------------------------ drift

const MIGRATION = `create table public.invoices (id bigint primary key, user_id uuid not null);
alter table public.invoices enable row level security;
create policy "own" on public.invoices for select to authenticated using ((select auth.uid()) = user_id);
create view public.v with (security_invoker = true) as select * from public.invoices;
create function public.f() returns int language sql security definer set search_path = '' as $$ select 1 $$;
revoke execute on function public.f() from public, anon;
insert into storage.buckets (id, name) values ('receipts', 'receipts');
`;

function catalog(over: Partial<LiveCatalog> = {}): LiveCatalog {
  return {
    tables: [{ schema: 'public', name: 'invoices', rls: true, forced: false }],
    policies: [{ schema: 'public', table: 'invoices', name: 'own', permissive: true, roles: ['authenticated'], cmd: 'SELECT', qual: '(( SELECT auth.uid() AS uid) = user_id)', withCheck: null }],
    grants: [],
    functions: [{ schema: 'public', name: 'f', securityDefiner: true, searchPathSet: true, anonExecute: false, authenticatedExecute: true, returnsTrigger: false }],
    views: [{ schema: 'public', name: 'v', materialized: false, securityInvoker: true }],
    realtime: [],
    buckets: [{ id: 'receipts', public: false }],
    ...over,
  };
}

describe('supabase/drift — compareDrift (pure)', () => {
  const m = () => model(MIGRATION);
  it('no drift when the catalog matches the migrations', () => {
    expect(compareDrift(m(), catalog())).toEqual([]);
  });

  it('reports RLS disabled, extra open policies, unmanaged tables, lost view/func settings, Realtime and public buckets', () => {
    const live = catalog({
      tables: [
        { schema: 'public', name: 'invoices', rls: false, forced: false },
        { schema: 'public', name: 'customers', rls: false, forced: false },
        { schema: 'public', name: 'notes', rls: true, forced: false },
      ],
      policies: [
        ...catalog().policies,
        { schema: 'public', table: 'invoices', name: 'debug', permissive: true, roles: ['public'], cmd: 'SELECT', qual: 'true', withCheck: null },
      ],
      functions: [{ schema: 'public', name: 'f', securityDefiner: true, searchPathSet: false, anonExecute: true, authenticatedExecute: true, returnsTrigger: false }],
      views: [{ schema: 'public', name: 'v', materialized: false, securityInvoker: false }],
      realtime: [{ schema: 'public', table: 'invoices' }],
      buckets: [{ id: 'receipts', public: true }],
    });
    expect(compareDrift(m(), live).map((i) => `${i.rule}:${i.severity}`)).toEqual([
      'drift-rls-disabled:critical',
      'drift-table-unmanaged:critical',
      'drift-policy-added:info',
      'drift-function-search-path:warning',
      'drift-function-execute:warning',
      'drift-view-invoker:critical',
      'drift-realtime-added:critical',
      'drift-bucket-public:critical',
    ]);
  });

  it('an extra always-true policy on a table that still has RLS is critical; a changed policy that now opens rows too', () => {
    const added = compareDrift(m(), catalog({ policies: [...catalog().policies, { schema: 'public', table: 'invoices', name: 'x', permissive: true, roles: ['anon'], cmd: 'SELECT', qual: '(1 = 1)', withCheck: null }] }));
    expect(added.map((i) => `${i.rule}:${i.severity}`)).toEqual(['drift-policy-added:critical']);
    const changed = compareDrift(m(), catalog({ policies: [{ ...catalog().policies[0]!, qual: 'true' }] }));
    expect(changed.map((i) => `${i.rule}:${i.severity}`)).toEqual(['drift-policy-changed:critical']);
    const missing = compareDrift(m(), catalog({ policies: [] }));
    expect(missing.map((i) => i.rule)).toEqual(['drift-policy-missing']);
  });

  it('privileges the migrations revoked but the database grants', () => {
    const mm = model(MIGRATION + 'revoke all on public.invoices from anon;');
    expect(compareDrift(mm, catalog({ grants: [{ schema: 'public', table: 'invoices', grantee: 'anon', privilege: 'SELECT' }] })).map((i) => i.rule)).toEqual(['drift-grant-added']);
  });

  it('URL helpers never show the password', () => {
    expect(maskDbUrl('postgres://u:hunter2@db.example.com:5432/postgres')).not.toMatch(/hunter2/);
    expect([isDbUrl('postgresql://h/db'), isDbUrl('https://x'), isDbUrl('nope')]).toEqual([true, false, false]);
  });
});

describe('supabase/drift — runSupabase wiring and coverage', () => {
  const project = (): string => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-drift-'));
    fs.mkdirSync(path.join(dir, 'supabase', 'migrations'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'supabase', 'migrations', '001.sql'), MIGRATION);
    return dir;
  };

  it('passed with findings when the catalog is read; the URL is masked everywhere', async () => {
    const dir = project();
    const url = 'postgres://ro:s3cret@db.example.com:5432/postgres';
    const res = await runSupabase(dir, { dbUrl: url }, { env: {}, readCatalog: async () => catalog({ tables: [{ schema: 'public', name: 'invoices', rls: false, forced: false }] }) });
    expect(res.drift?.state).toBe('passed');
    expect(res.liveFindings.map((f) => [f.rule, f.source, f.endpoint])).toEqual([['drift-rls-disabled', 'dynamic', 'postgres:public.invoices']]);
    expect(JSON.stringify(res)).not.toMatch(/s3cret/);
    const cov = supabaseCoverage(res, false, true);
    expect(cov.drift).toMatchObject({ state: 'passed', requested: true });
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('failed when the connection fails; untested without a URL; a set env var alone does not connect', async () => {
    const dir = project();
    const failed = await runSupabase(dir, { dbUrl: 'postgres://ro:s3cret@h/db' }, { env: {}, readCatalog: async () => { throw new Error('connect ECONNREFUSED postgres://ro:s3cret@h/db'); } });
    expect(failed.drift?.state).toBe('failed');
    expect(JSON.stringify(failed)).not.toMatch(/s3cret/);
    const none = await runSupabase(dir, { dbUrl: true }, { env: {} });
    expect(supabaseCoverage(none, false, true).drift).toMatchObject({ state: 'untested', requested: true });
    let called = false;
    const envOnly = await runSupabase(dir, {}, { env: { SUPABASE_DB_URL: 'postgres://h/db' }, readCatalog: async () => ((called = true), catalog()) });
    expect([called, envOnly.drift, envOnly.notes.some((n) => /--supabase-db-url/.test(n))]).toEqual([false, undefined, true]);
    expect(supabaseCoverage(envOnly, false, false).drift.state).toBe('untested');
    const fromEnv = await runSupabase(dir, { dbUrl: true }, { env: { SUPABASE_DB_URL: 'postgres://h/db' }, readCatalog: async () => catalog() });
    expect(fromEnv.drift?.state).toBe('passed');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('the coverage table has a supabase (drift) area, untested by default', () => {
    const area = buildCoverage({ graph: undefined } as never, new CoverageRecorder()).find((a) => a.kind === 'supabase-drift');
    expect(area).toMatchObject({ label: 'supabase (drift)', state: 'untested', live: true });
  });
});

// Against a real server: DEPLOYREADY_TEST_PG_URL=postgres://postgres@127.0.0.1:<port>/postgres (a disposable superuser).
const PG = process.env.DEPLOYREADY_TEST_PG_URL;
(PG ? describe : describe.skip)('supabase/drift — live PostgreSQL', () => {
  it('detects drift after mutating a database built from the migrations, and never writes', async () => {
    const { Client } = require('pg') as typeof import('pg');
    const admin = new Client({ connectionString: PG });
    await admin.connect();
    const db = `dr_drift_${process.pid}`;
    await admin.query(`drop database if exists ${db}`);
    await admin.query(`create database ${db}`);
    await admin.end();
    const url = PG!.replace(/\/[^/]*$/, `/${db}`);
    const c = new Client({ connectionString: url });
    await c.connect();
    try {
      await c.query(`do $$ begin
        if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
        if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
        if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
      end $$;
      create schema auth; create function auth.uid() returns uuid language sql stable as $f$ select null::uuid $f$;
      create schema storage; create table storage.buckets (id text primary key, name text, public boolean default false);
      grant all on all tables in schema public to anon, authenticated;`);
      await c.query(MIGRATION);
      await c.query(`alter table public.invoices disable row level security;
        create policy "debug" on public.invoices for select using (true);
        alter view public.v reset (security_invoker);
        update storage.buckets set public = true where id = 'receipts';`);
      const live = await withReadOnlyDb(url, (q) => readCatalog(q, ['public']));
      const found = compareDrift(model(MIGRATION), live).map((i) => i.rule).sort();
      expect(found).toEqual(['drift-bucket-public', 'drift-policy-added', 'drift-rls-disabled', 'drift-view-invoker']);
      await expect(withReadOnlyDb(url, (q) => q('create table public.nope (x int)'))).rejects.toThrow(/read-only/);
    } finally {
      await c.end();
      const a2 = new Client({ connectionString: PG });
      await a2.connect();
      await a2.query(`drop database if exists ${db}`);
      await a2.end();
    }
  });
});

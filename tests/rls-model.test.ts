import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { splitStatements, tokenize } from '../src/analysis/postgres/lexer';
import { alwaysTrueFor, findSelfCompares, parseExpr } from '../src/analysis/postgres/expr';
import { orderSqlFiles, replayMigrations, tableKey } from '../src/analysis/postgres/model';
import { classifyTable } from '../src/analysis/postgres/sensitivity';
import { exposedSchemasFromToml, loadRlsConfig, parseRlsConfig } from '../src/analysis/postgres/config';
import { analyzeRls } from '../src/analysis/rls';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';

const expr = (s: string) => parseExpr(tokenize(s));
const openFor = (s: string, role: 'anon' | 'authenticated') => alwaysTrueFor(expr(s), { role });
const model = (...sources: string[]) => replayMigrations(sources.map((source, i) => ({ relPath: `supabase/migrations/${String(i).padStart(3, '0')}.sql`, source })));
const rls = (sql: string, config = {}) => analyzeRls([{ relPath: 'supabase/migrations/001.sql', source: sql }], { supabase: true, config });

describe('postgres/lexer', () => {
  it('keeps semicolons inside strings, dollar quotes, comments and BEGIN ATOMIC bodies', () => {
    const sql = [
      "insert into t values ('a;b', E'c\\';d');",
      'create function f() returns int language plpgsql as $fn$ begin return 1; end $fn$;',
      '/* outer /* nested; */ still comment; */ select 1;',
      'create function g() returns int language sql begin atomic select 1; select 2; end;',
      'select "we;ird" from x -- trailing; comment',
    ].join('\n');
    const st = splitStatements(sql);
    expect(st.map((s) => s.tokens[0]!.value)).toEqual(['insert', 'create', 'select', 'create', 'select']);
    expect(st.map((s) => s.line)).toEqual([1, 2, 3, 4, 5]);
  });

  it('folds unquoted identifiers to lower case and keeps quoted ones exact', () => {
    const t = tokenize('ALTER TABLE "Public"."Invoices" ENABLE');
    expect(t.map((x) => [x.type, x.value])).toEqual([
      ['word', 'alter'], ['word', 'table'], ['qident', 'Public'], ['punct', '.'], ['qident', 'Invoices'], ['word', 'enable'],
    ]);
  });
});

describe('postgres/expr — always-true classification', () => {
  it.each([
    'true', '1 = 1', "'a' = 'a'", 'true and true', 'not false', '(true)', "'t'::boolean", '1::int = 1', 'org_id = org_id',
    'user_id = auth.uid() or true', 'true or (select false)', "2 > 1", "1 in (1, 2)", 'null is null', "'x' is not null", 'not (1 <> 1)',
    'coalesce(true, false)', 'cast(1 as text) = \'1\'', "1 = 1 and 'a' = 'a'",
  ])('%s is open for anon', (s) => expect(openFor(s, 'anon')).toBe(true));

  it.each([
    "auth.role() = 'authenticated'", 'auth.uid() is not null', '(select auth.uid()) is not null', "auth.jwt() ->> 'role' = 'authenticated'",
    "current_user = 'authenticated'", "auth.role() in ('anon', 'authenticated')", 'auth.uid() = auth.uid()',
    "current_setting('request.jwt.claim.role', true) = 'authenticated'",
  ])('%s is open for any signed-in user but not anon (unless it names anon)', (s) => {
    expect(openFor(s, 'authenticated')).toBe(true);
    expect(openFor(s, 'anon')).toBe(s.includes("'anon'"));
  });

  it.each([
    'auth.uid() = user_id', '(select auth.uid()) = user_id', 'published', 'published = true', 'false', '1 = 2', 'true and false',
    "auth.jwt() ->> 'role' = 'admin'", 'org_id in (select org_id from members where user_id = auth.uid())', 'is_admin()', 'x = 1 or y = 2',
    'case when true then true end', 'null', 'not true',
  ])('%s is not open', (s) => {
    expect(openFor(s, 'anon')).toBe(false);
    expect(openFor(s, 'authenticated')).toBe(false);
  });

  it('returns null for expressions it cannot parse (treated as restrictive)', () => {
    expect(expr('select from where')).toBeNull();
    expect(alwaysTrueFor(null, { role: 'anon' })).toBe(false);
  });

  it('finds a subquery column compared with itself, using the inner table columns', () => {
    const e = expr('exists (select 1 from memberships m where m.user_id = auth.uid() and m.org_id = org_id)');
    const cols = (t: string[], c: string) => (t[t.length - 1] === 'memberships' ? ['org_id', 'user_id'].includes(c) : null);
    expect(findSelfCompares(e, cols).map((s) => s.text)).toEqual(['m.org_id = org_id']);
    const ok = expr('exists (select 1 from memberships m where m.user_id = auth.uid() and m.org_id = projects.org_id)');
    expect(findSelfCompares(ok, cols)).toEqual([]);
    // unknown inner columns: no claim
    expect(findSelfCompares(e, () => null)).toEqual([]);
  });
});

describe('postgres/model — replay', () => {
  it('sorts migrations naturally and before other SQL', () => {
    const files = ['seed.sql', 'supabase/migrations/10_b.sql', 'supabase/migrations/9_a.sql', 'db/schema.sql'].map((relPath) => ({ relPath, source: '' }));
    expect(orderSqlFiles(files).map((f) => f.relPath)).toEqual(['supabase/migrations/9_a.sql', 'supabase/migrations/10_b.sql', 'db/schema.sql', 'seed.sql']);
  });

  it('tracks rename, set schema, alter schema rename and drop', () => {
    const m = model(
      'create table a (id int); alter table a enable row level security; create schema s1;',
      'alter table a rename to b; create table c (id int); alter table c set schema s1;',
      'alter schema s1 rename to s2; create table d (id int); drop table if exists d, nope;',
    );
    expect([...m.tables.keys()].sort()).toEqual([tableKey('public', 'b'), tableKey('s2', 'c')].sort());
    expect(m.tables.get(tableKey('public', 'b'))!.rls).toBe(true);
  });

  it('applies CREATE / ALTER / DROP POLICY and ALTER POLICY RENAME in order', () => {
    const m = model(
      'create table t (id int, user_id uuid); alter table t enable row level security;\ncreate policy "p" on t as restrictive for update to authenticated, anon using (true) with check (false);',
      'alter policy "p" on t to authenticated using (user_id = auth.uid());\nalter policy "p" on t rename to q;\ncreate policy gone on t using (true); drop policy if exists gone on t;',
    );
    const t = m.tables.get(tableKey('public', 't'))!;
    expect([...t.policies.keys()]).toEqual(['q']);
    const q = t.policies.get('q')!;
    expect([q.permissive, q.command, q.roles, q.usingText, q.checkText, q.loc.line]).toEqual([false, 'update', ['authenticated'], 'user_id = auth.uid()', 'false', 1]);
  });

  it('models Supabase default grants, GRANT/REVOKE, ALL TABLES IN SCHEMA and default privileges', () => {
    const m = model(
      'create table a (id int); create schema api; create table api.b (id int);',
      'revoke all on table a from anon; grant select on all tables in schema api to anon;',
      'alter default privileges in schema public revoke all on tables from authenticated; create table c (id int);',
    );
    expect(m.tables.get(tableKey('public', 'a'))!.grants.get('anon')?.size).toBe(0);
    expect([...(m.tables.get(tableKey('api', 'b'))!.grants.get('anon') ?? [])]).toEqual(['select']);
    expect(m.tables.get(tableKey('public', 'c'))!.grants.get('authenticated')?.size).toBe(0);
  });

  it('honours search_path (SET, RESET, pg_dump set_config) per file', () => {
    const m = model(
      "set search_path to internal, public; create table j (id int); reset search_path; create table k (id int);\nselect pg_catalog.set_config('search_path', 'x', false); create table l (id int);",
      'create table n (id int);',
    );
    expect([...m.tables.keys()].sort()).toEqual([tableKey('internal', 'j'), tableKey('public', 'k'), tableKey('x', 'l'), tableKey('public', 'n')].sort());
  });

  it('understands unlogged / partitioned / partition-of tables and ignores temp tables', () => {
    const m = model(
      "create unlogged table u (id int); create temporary table tmp (id int); create table p (id int, at date) partition by range (at);\ncreate table p1 partition of p for values from ('2024-01-01') to ('2025-01-01');",
    );
    expect([...m.tables.values()].map((t) => [t.name, t.kind]).sort()).toEqual([['p', 'partitioned'], ['p1', 'partition'], ['u', 'unlogged']]);
    expect([...m.tables.get(tableKey('public', 'p1'))!.columns!]).toEqual(['id', 'at']);
  });

  it('applies plain statements inside DO blocks and marks dynamic RLS SQL as uncertain', () => {
    const m = model(
      'create table a (id int, user_id uuid); create table b (id int);',
      "do $$ begin\n  if not exists (select 1 from pg_policies where policyname = 'own') then\n    create policy own on a using (user_id = auth.uid());\n  end if;\n  execute 'alter table a enable row level security';\nend $$;",
      "do $$ declare t text; begin for t in select tablename from pg_tables loop execute format('alter table %I enable row level security', t); end loop; end $$;",
    );
    const a = m.tables.get(tableKey('public', 'a'))!;
    expect([a.rls, [...a.policies.keys()], a.policies.get('own')!.loc.line]).toEqual([true, ['own'], 3]);
    expect(m.tables.get(tableKey('public', 'b'))!.rlsUncertain).toBe(true);
  });

  it('never throws on garbage', () => {
    expect(() => model('create table ( ; alter policy on; grant on to; $$ unterminated', "do 'x'; create policy p on")).not.toThrow();
  });
});

describe('postgres/sensitivity + config', () => {
  const t = (name: string, columns: string[] = []) => ({ ...model(`create table "${name}" (${columns.map((c) => `${c} int`).join(', ') || 'id int'})`).tables.values().next().value! });
  it('classifies by config, name, publish flag and tenant columns', () => {
    expect(classifyTable(t('invoices'), {}).level).toBe('sensitive');
    expect(classifyTable(t('UserProfiles'), {}).level).toBe('sensitive');
    expect(classifyTable(t('products'), {}).level).toBe('public');
    expect(classifyTable(t('posts', ['published']), {}).level).toBe('public');
    expect(classifyTable(t('posts'), {}).level).toBe('unknown');
    expect(classifyTable(t('widgets', ['org_id']), {}).level).toBe('sensitive');
    expect(classifyTable(t('widgets', ['shop']), { tenantColumns: ['shop'] }).level).toBe('sensitive');
    expect(classifyTable(t('widgets'), { sensitiveTables: ['public.widgets'] }).level).toBe('sensitive');
    expect(classifyTable(t('invoices'), { publicTables: ['invoices'] }).level).toBe('public');
  });

  it('parses .deployready.json (top level or under "rls") and supabase/config.toml', async () => {
    expect(parseRlsConfig({ rls: { publicTables: ['a', 7], exposedSchemas: ['public', 'api'] } })).toEqual({ publicTables: ['a'], exposedSchemas: ['public', 'api'] });
    expect(parseRlsConfig('nope')).toEqual({});
    expect(exposedSchemasFromToml('[db]\nschemas = ["x"]\n[api]\n# comment\nschemas = [\n  "public",\n  "api", # inline\n]\n')).toEqual(['public', 'api']);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-rlscfg-'));
    fs.mkdirSync(path.join(dir, 'supabase'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ deployready: { sensitiveTables: ['widgets'] } }));
    fs.writeFileSync(path.join(dir, 'supabase', 'config.toml'), '[api]\nschemas = ["public", "api"]\n');
    expect(await loadRlsConfig(dir)).toEqual({ sensitiveTables: ['widgets'], exposedSchemas: ['public', 'api'] });
    fs.writeFileSync(path.join(dir, '.deployready.json'), '{ broken');
    expect(await loadRlsConfig(dir)).toEqual({ exposedSchemas: ['public', 'api'] });
  });
});

describe('analyzeRls — final-state evaluation', () => {
  const enable = (t: string) => `create table ${t} (id int, user_id uuid); alter table ${t} enable row level security;\n`;

  it('does not flag an open policy that a later migration dropped (audit false positive)', () => {
    const files = [
      { relPath: 'supabase/migrations/1.sql', source: enable('invoices') + 'create policy "all" on invoices for all using (true) with check (true);' },
      { relPath: 'supabase/migrations/2.sql', source: 'drop policy "all" on invoices; create policy own on invoices for all using (user_id = auth.uid());' },
    ];
    expect(analyzeRls(files, { supabase: true })).toEqual([]);
  });

  it('a restrictive policy narrows an open permissive one; an open restrictive one does not', () => {
    const base = enable('invoices') + 'create policy wide on invoices for select to authenticated using (true);\n';
    expect(rls(base + 'create policy guard on invoices as restrictive for select using (user_id = auth.uid());')).toEqual([]);
    expect(rls(base + 'create policy guard on invoices as restrictive for select using (1 = 1);')).toHaveLength(1);
  });

  it('ignores open policies for roles without the table privilege, and service_role-only policies', () => {
    const base = enable('invoices');
    expect(rls(base + 'create policy a on invoices for select to anon using (true); revoke select on invoices from anon;')).toEqual([]);
    expect(rls(base + 'create policy s on invoices for all to service_role using (true);')).toEqual([]);
  });

  it('reports which roles and commands a policy opens, with the clause', () => {
    const [i] = rls(enable('orders') + "create policy p on orders for all using (auth.role() = 'authenticated');");
    expect([i!.severity, i!.roles, i!.commands, i!.clause]).toEqual(['critical', ['authenticated'], ['select', 'insert', 'update', 'delete'], "using (auth.role() = 'authenticated')"]);
  });

  it('exposed schemas come from config; other schemas are ignored', () => {
    const sql = 'create schema api; create table api.secrets (id int); grant select on api.secrets to anon; create table public.n (id int); alter table public.n enable row level security; create policy p on public.n using (false);';
    expect(rls(sql)).toEqual([]);
    expect(rls(sql, { exposedSchemas: ['public', 'api'] }).map((i) => [i.kind, i.schema, i.table, i.severity])).toEqual([['missing', 'api', 'secrets', 'critical']]);
  });

  it('reports an explicit DISABLE that stays the final state, even without other RLS', () => {
    expect(analyzeRls([{ relPath: 'm.sql', source: 'ALTER TABLE users DISABLE ROW LEVEL SECURITY;' }]).map((i) => [i.kind, i.severity])).toEqual([['disabled', 'critical']]);
  });
});

// Every RLS benchmark case (16 audit reconstructions + variations) must pass in `npm test` too.
describe('benchmark/corpus/rls expectations', () => {
  const root = path.join(__dirname, '..', 'benchmark', 'corpus', 'rls');
  const ids = fs.readdirSync(root).filter((d) => fs.statSync(path.join(root, d)).isDirectory()).sort();
  it('has the 16 audit cases and at least 10 variations', () => {
    expect(ids.filter((i) => /^[as]\d\d-/.test(i))).toHaveLength(16);
    expect(ids.filter((i) => /^v\d\d-/.test(i)).length).toBeGreaterThanOrEqual(10);
  });
  it.each(ids)('%s', async (id) => {
    const spec = JSON.parse(fs.readFileSync(path.join(root, id, 'expect.json'), 'utf8')) as {
      expected: { rule: string; present: boolean; file?: string; severity?: string }[];
    };
    const findings = await VulnerabilityDetector.scan(path.join(root, id));
    for (const e of spec.expected) {
      const hit = findings.some((f) => f.rule === e.rule && (!e.file || f.file === e.file) && (!e.severity || f.severity === e.severity));
      expect(`${e.rule} ${e.present ? 'present' : 'absent'}: ${hit === e.present}`).toBe(`${e.rule} ${e.present ? 'present' : 'absent'}: true`);
    }
    // strict: nothing outside the expected rules
    const mentioned = new Set(spec.expected.map((e) => e.rule));
    expect(findings.filter((f) => !mentioned.has(f.rule)).map((f) => f.rule)).toEqual([]);
  });
});

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PassThrough, Writable } from 'stream';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { analyzeRls, tablesMissingRls } from '../src/analysis/rls';
import { InteractiveShell } from '../src/cli/InteractiveShell';

function proj(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'er-trust-'));
  for (const [name, content] of Object.entries(files)) {
    const abs = path.join(root, name);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

const vcs = (root: string, ...args: string[]) =>
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', '-C', root, ...args], {
    stdio: 'ignore',
  });

const envFinding = async (root: string) => (await VulnerabilityDetector.scan(root)).find((f) => f.rule === 'env-not-ignored');

describe('env-not-ignored severity', () => {
  it('is critical when .env is tracked', async () => {
    const root = proj({ '.env': 'DB_PASSWORD=hunter2hunter2\n', 'a.js': 'x\n' });
    vcs(root, 'init');
    vcs(root, 'add', '-f', '.env', 'a.js');
    vcs(root, 'commit', '-m', 'init');
    const f = await envFinding(root);
    expect(f?.severity).toBe('critical');
    expect(f?.description).toMatch(/tracked by git/);
  });

  it('stays critical when tracked even though .gitignore now lists it', async () => {
    const root = proj({ '.env': 'A=bbbbbbbb\n', '.gitignore': '.env\n' });
    vcs(root, 'init');
    vcs(root, 'add', '-f', '.env', '.gitignore');
    vcs(root, 'commit', '-m', 'init');
    expect((await envFinding(root))?.severity).toBe('critical');
  });

  it('is critical when .env was committed earlier and later untracked', async () => {
    const root = proj({ '.env': 'A=bbbbbbbb\n', 'a.js': 'x\n' });
    vcs(root, 'init');
    vcs(root, 'add', '-f', '.env', 'a.js');
    vcs(root, 'commit', '-m', 'init');
    vcs(root, 'rm', '--cached', '.env');
    vcs(root, 'commit', '-m', 'untrack');
    const f = await envFinding(root);
    expect(f?.severity).toBe('critical');
    expect(f?.description).toMatch(/history/);
  });

  it('is a warning in a repo when never committed and not ignored', async () => {
    const root = proj({ '.env': 'A=bbbbbbbb\n', 'a.js': 'x\n' });
    vcs(root, 'init');
    vcs(root, 'add', 'a.js');
    vcs(root, 'commit', '-m', 'init');
    const f = await envFinding(root);
    expect(f?.severity).toBe('warning');
    expect(f?.description).toMatch(/not tracked by git yet/);
  });

  it('is a warning outside a repository', async () => {
    const f = await envFinding(proj({ '.env': 'A=bbbbbbbb\n' }));
    expect(f?.severity).toBe('warning');
    expect(f?.description).toMatch(/No git repository/);
  });

  it('is not reported for an untracked, gitignored .env', async () => {
    const root = proj({ '.env': 'A=bbbbbbbb\n', '.gitignore': '.env\n' });
    vcs(root, 'init');
    expect(await envFinding(root)).toBeUndefined();
  });
});

describe('jwt-hardcoded-secret', () => {
  const scan = async (name: string, line: string) =>
    (await VulnerabilityDetector.scan(proj({ [name]: `${line}\n` }))).filter((f) => f.file === name);

  it.each([
    ['a.js', "const t = jwt.sign({ id: user.id }, 'supersecretvalue', { expiresIn: '1h' });"],
    ['a.ts', 'const t = jsonwebtoken.sign(payload, "my-key-123");'],
    ['a.js', "jwt.verify(token, 'supersecretvalue')"],
    ['a.js', "const j = await new SignJWT({ a: 1 }).setProtectedHeader({ alg: 'HS256' }).sign(new TextEncoder().encode('topsecret1'));"],
    ['a.py', 'token = jwt.encode(payload, "supersecretvalue", algorithm="HS256")'],
    ['a.py', "jwt.decode(token, key='supersecretvalue', algorithms=['HS256'])"],
  ])('flags %s: %s as a single critical finding', async (name, line) => {
    const found = await scan(name, line);
    expect(found).toHaveLength(1);
    expect(found[0]!.rule).toBe('jwt-hardcoded-secret');
    expect(found[0]!.severity).toBe('critical');
    expect(found[0]!.title).toMatch(/forge login tokens/);
  });

  it('does not duplicate when the literal also looks like a known secret shape', async () => {
    const found = await scan('a.js', "jwt.sign(p, 'sk-ant-abcdefghijklmnopqrstuvwxyz0123');");
    expect(found).toHaveLength(1);
    expect(found[0]!.rule).toBe('jwt-hardcoded-secret');
  });

  it('does not flag env-sourced keys, template literals or array payloads', async () => {
    expect(await scan('a.js', 'jwt.sign({ id: 1 }, process.env.JWT_SECRET);')).toHaveLength(0);
    expect(await scan('a.js', 'jwt.sign({ id: 1 }, `${prefix}-key`);')).toHaveLength(0);
    expect(await scan('a.js', "jwt.sign({ roles: ['admin', 'user', 'guest'] }, secret);")).toHaveLength(0);
    expect(await scan('a.py', 'jwt.encode(payload, os.environ["JWT_KEY"], algorithm="HS256")')).toHaveLength(0);
    expect(await scan('a.py', 'jwt.encode(payload, f"{prefix}-key", algorithm="HS256")')).toHaveLength(0);
  });

  it('keeps the generic warning for other secret-named literals', async () => {
    const found = await scan('a.js', "const API_TOKEN = 'abcdef123456';");
    expect(found.map((x) => x.rule)).toEqual(['possible-hardcoded-secret']);
  });
});

describe('RLS (Supabase-aware)', () => {
  it('flags tables when RLS is enabled nowhere but the project is Supabase (migrations dir)', async () => {
    const root = proj({ 'supabase/migrations/001.sql': 'create table public.notes (id int);\n' });
    const found = (await VulnerabilityDetector.scan(root)).filter((x) => x.rule === 'rls-not-enabled');
    expect(found).toHaveLength(1);
    expect(found[0]!.description).toMatch(/anon key/);
  });

  it('flags via the @supabase/supabase-js dependency', async () => {
    const root = proj({
      'package.json': '{"dependencies":{"@supabase/supabase-js":"^2.0.0"}}',
      'db/schema.sql': 'create table notes (id int);\n',
    });
    const found = (await VulnerabilityDetector.scan(root)).filter((x) => x.rule === 'rls-not-enabled');
    expect(found).toHaveLength(1);
  });

  it('stays quiet for a plain Postgres project that never enables RLS', async () => {
    const root = proj({
      'package.json': '{"dependencies":{"pg":"^8"}}',
      'db/schema.sql': 'create table notes (id int);\n',
    });
    expect((await VulnerabilityDetector.scan(root)).some((x) => x.rule.startsWith('rls-'))).toBe(false);
  });

  it('ignores non-public schemas, temp tables and commented-out SQL', () => {
    const sql = 'create table private.audit (id int);\ncreate temp table t (id int);\n-- create table ghost (id int);\n';
    expect(tablesMissingRls([{ relPath: 'supabase/m.sql', source: sql }], { supabase: true })).toEqual([]);
  });

  it('reports RLS enabled with no policy as info and notes it denies everything', async () => {
    const root = proj({
      'supabase/migrations/1.sql': 'create table notes (id int);\nalter table notes enable row level security;\n',
    });
    const found = (await VulnerabilityDetector.scan(root)).find((x) => x.rule === 'rls-no-policy');
    expect(found?.severity).toBe('info');
    expect(found?.description).toMatch(/denied/);
  });

  it('does not report no-policy when a policy exists', () => {
    const sql =
      'create table notes (id int, uid uuid);\nalter table notes enable row level security;\n' +
      'create policy "own" on public.notes for select to authenticated using (auth.uid() = uid);\n';
    expect(analyzeRls([{ relPath: 'a.sql', source: sql }], { supabase: true })).toEqual([]);
  });

  it('warns on using (true) / with check (true) for non-select commands, including multi-line', () => {
    const sql = [
      'create table notes (id int);',
      'alter table notes enable row level security;',
      'create policy "w" on notes',
      '  for insert to authenticated',
      '  with check (true);',
      'create policy "all" on notes for all using (true);',
    ].join('\n');
    const perm = analyzeRls([{ relPath: 'a.sql', source: sql }]).filter((i) => i.kind === 'permissive');
    expect(perm.map((i) => [i.command, i.clause, i.line])).toEqual([
      ['insert', 'with check (true)', 3],
      ['all', 'using (true)', 6],
    ]);
  });

  it('allows a public SELECT using (true) on published content and service_role-only true policies', () => {
    const sql = [
      'create table posts (id int, published boolean);',
      'alter table posts enable row level security;',
      'create policy "read" on posts for select using (true);',
      'create policy "svc" on posts for all to service_role using (true) with check (true);',
    ].join('\n');
    expect(analyzeRls([{ relPath: 'a.sql', source: sql }])).toEqual([]);
  });

  it('asks for review (warning) when a table of unknown sensitivity is world-readable', () => {
    const sql = ['create table posts (id int);', 'alter table posts enable row level security;', 'create policy "read" on posts for select using (true);'].join('\n');
    const [i] = analyzeRls([{ relPath: 'a.sql', source: sql }]);
    expect([i?.kind, i?.severity, i?.readOnly]).toEqual(['permissive', 'warning', true]);
  });
});

describe('InteractiveShell.printDiff', () => {
  function capture(oldText: string, newText: string): string[] {
    const sink = new Writable({ write: (_c, _e, cb) => cb() });
    const shell = new InteractiveShell(os.tmpdir(), { input: new PassThrough(), output: sink });
    const logs: string[] = [];
    const spy = jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(' ')));
    try {
      (shell as unknown as { printDiff(...a: unknown[]): void }).printDiff('f.js', 1, 4, oldText, newText);
    } finally {
      spy.mockRestore();
      (shell as unknown as { rl: { close(): void } }).rl.close();
    }
    // eslint-disable-next-line no-control-regex
    return logs.map((l) => l.replace(/\x1B\[[0-9;]*[A-Za-z]/g, ''));
  }

  it('renders blank and trailing lines in both old and new text', () => {
    const out = capture('a\n\nb\n', 'a\n\n\nb\n');
    expect(out).toEqual(['  ── f.js:1-4 ──', '  - a', '  - ', '  - b', '  - ', '  + a', '  + ', '  + ', '  + b', '  + ', '']);
  });

  it('treats CRLF text like LF so no stray carriage returns hide blank lines', () => {
    const out = capture('a\r\n\r\nb', 'a\r\n\r\nc');
    expect(out.join('\n')).not.toContain('\r');
    expect(out.slice(1, 4)).toEqual(['  - a', '  - ', '  - b']);
  });
});

describe('FileWalker skips .deployready backups', () => {
  it('never walks <root>/.deployready', async () => {
    const { FileWalker } = await import('../src/utils/FileWalker');
    const root = proj({ 'a.js': 'x\n', '.deployready/backups/a.js.2026.bak': "eval('x')\n", '.deployready/x.js': 'y\n' });
    const files = (await FileWalker.walk(root)).map((f) => f.relPath);
    expect(files).toEqual(['a.js']);
  });
});

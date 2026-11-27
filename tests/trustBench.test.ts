import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';

async function rules(files: Record<string, string>): Promise<Array<[string, string]>> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'er-tb-'));
  for (const [name, content] of Object.entries(files)) {
    const abs = path.join(root, name);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return (await VulnerabilityDetector.scan(root)).map((f) => [f.file as string, f.rule]);
}
const has = (r: Array<[string, string]>, rule: string, file?: string) => r.some(([f, x]) => x === rule && (!file || f === file));

describe('supabase-service-role is only for client-reachable code', () => {
  it('skips a server-only module and an API route', async () => {
    const r = await rules({
      'lib/admin.ts': "import 'server-only';\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY!;\n",
      'app/api/x/route.ts': 'const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n',
      'svc.py': 'key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]\n',
    });
    expect(has(r, 'supabase-service-role')).toBe(false);
  });

  it('still flags a client module and any NEXT_PUBLIC_ service role key', async () => {
    const r = await rules({
      'lib/supabase.ts': "'use client';\nconst k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!;\n",
      'lib/other.ts': 'const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n',
      'app/api/y/route.ts': 'const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n',
    });
    expect(has(r, 'supabase-service-role', 'lib/supabase.ts')).toBe(true);
    expect(has(r, 'supabase-service-role', 'lib/other.ts')).toBe(true);
    expect(has(r, 'supabase-service-role', 'app/api/y/route.ts')).toBe(true);
  });
});

describe('NEXT_PUBLIC_/VITE_ secrets', () => {
  it('flags secret-named and vendor-key client env vars, not public-by-design ones', async () => {
    const r = await rules({
      'a.tsx': 'const a = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n',
      'b.ts': 'const b = import.meta.env.VITE_STRIPE_SECRET_KEY;\n',
      'c.ts': 'const c = process.env.NEXT_PUBLIC_APP_PRIVATE_KEY;\n',
      'd.ts': 'const d = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\n',
      'e.ts': 'const e = import.meta.env.VITE_FIREBASE_API_KEY;\n',
    });
    for (const f of ['a.tsx', 'b.ts', 'c.ts']) expect(has(r, 'next-public-secret', f)).toBe(true);
    expect(has(r, 'next-public-secret', 'd.ts')).toBe(false);
    expect(has(r, 'next-public-secret', 'e.ts')).toBe(false);
  });
});

describe('sql-injection with bound template parameters', () => {
  it('does not flag a parameterized query whose LIKE value is a template literal param', async () => {
    const r = await rules({
      'a.js': "const q = await pool.query('SELECT * FROM products WHERE name ILIKE $1', [`%${req.query.q}%`]);\n",
    });
    expect(has(r, 'sql-injection')).toBe(false);
  });

  it('still flags real interpolation', async () => {
    const r = await rules({
      'a.js': 'const q = await pool.query(`SELECT * FROM products WHERE name = \'${req.query.q}\'`);\n',
      'b.js': "pool.query('SELECT * FROM t WHERE id = ' + req.params.id, [x]);\n",
    });
    expect(has(r, 'sql-injection', 'a.js')).toBe(true);
    expect(has(r, 'sql-injection', 'b.js')).toBe(true);
  });
});

describe('possible-hardcoded-secret false positives', () => {
  it('ignores expressions and type-annotated dependencies in code files', async () => {
    const r = await rules({
      'a.js': "const token = (req.headers.authorization || '').replace('Bearer ', '');\n",
      'b.py': 'def current_user(token: str = Depends(oauth2)):\n    if token != "valid":\n        pass\n',
    });
    expect(has(r, 'possible-hardcoded-secret')).toBe(false);
  });

  it('still flags a quoted literal', async () => {
    const r = await rules({ 'a.js': "const apiToken = 'abcdef123456';\n", 'b.py': 'token: str = "abcdef123456"\n' });
    expect(has(r, 'possible-hardcoded-secret', 'a.js')).toBe(true);
    expect(has(r, 'possible-hardcoded-secret', 'b.py')).toBe(true);
  });
});

describe('py-sql-fstring', () => {
  it('catches single-quoted values inside a double-quoted f-string', async () => {
    const r = await rules({
      'a.py': 'cur.execute(f"SELECT id FROM users WHERE name = \'{name}\'")\n',
      'b.py': "cur.execute(f'DELETE FROM users WHERE id = {uid}')\n",
    });
    expect(has(r, 'py-sql-fstring', 'a.py')).toBe(true);
    expect(has(r, 'py-sql-fstring', 'b.py')).toBe(true);
  });

  it('does not flag prose f-strings', async () => {
    const r = await rules({ 'a.py': 'print(f"please update {thing} and select one")\n' });
    expect(has(r, 'py-sql-fstring')).toBe(false);
  });
});

describe('flask-hardcoded-secret-key', () => {
  it('flags literal keys once, without a duplicate generic secret finding', async () => {
    const r = await rules({
      'a.py': 'app.config["SECRET_KEY"] = "dev-secret-key-123"\n',
      'b.py': "app.secret_key = 'hunter2hunter2'\n",
      'settings.py': 'SECRET_KEY = "django-insecure-abc"\n',
    });
    for (const f of ['a.py', 'b.py', 'settings.py']) {
      expect(r.filter(([file]) => file === f).map(([, rule]) => rule)).toEqual(['flask-hardcoded-secret-key']);
    }
  });

  it('ignores env-sourced keys and placeholders', async () => {
    const r = await rules({
      'a.py': 'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]\n',
      'b.py': 'SECRET_KEY = "changeme"\n',
    });
    expect(has(r, 'flask-hardcoded-secret-key')).toBe(false);
  });
});

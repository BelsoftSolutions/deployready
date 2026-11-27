import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { unauthenticatedRoutes } from '../src/analysis/routeAuth';
import type { Finding } from '../src/types';

function proj(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'er-tr-'));
  for (const [name, content] of Object.entries(files)) {
    const abs = path.join(root, name);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}
const scan = async (files: Record<string, string>): Promise<Finding[]> => VulnerabilityDetector.scan(proj(files));
const authFindings = async (files: Record<string, string>) => (await scan(files)).filter((f) => f.rule === 'missing-auth-route');

describe('missing-auth-route', () => {
  it('flags an unguarded Express DELETE and admin route as critical', async () => {
    const f = await authFindings({
      'server.js': [
        "const app = require('express')();",
        "app.get('/api/products', (req, res) => res.json([]));",
        "app.get('/api/admin/users', (req, res) => res.json([]));",
        "app.delete('/api/items/:id', (req, res) => res.json({ ok: true }));",
      ].join('\n'),
    });
    expect(f.map((x) => [x.line, x.severity])).toEqual([
      [3, 'critical'],
      [4, 'critical'],
    ]);
    expect(f[1]!.title).toMatch(/no auth check/);
    expect(f[1]!.description).toContain('DELETE /api/items/:id');
  });

  it('accepts per-route and router-level middleware', async () => {
    const f = await authFindings({
      'server.js': [
        "const app = require('express')();",
        "app.delete('/api/a/:id', requireAuth, (req, res) => res.json({}));",
        'app.use(authenticate);',
        "app.delete('/api/b/:id', (req, res) => res.json({}));",
      ].join('\n'),
    });
    expect(f).toEqual([]);
  });

  it('accepts FastAPI Depends and Flask login_required', async () => {
    const f = await authFindings({
      'main.py': [
        'from fastapi import FastAPI, Depends',
        'app = FastAPI()',
        '@app.delete("/items/{item_id}")',
        'def delete_item(item_id: int, user=Depends(get_user)):',
        '    return {}',
      ].join('\n'),
      'web.py': [
        'from flask import Flask',
        'app = Flask(__name__)',
        '@app.route("/admin/users", methods=["DELETE"])',
        '@login_required',
        'def remove():',
        '    return ""',
      ].join('\n'),
    });
    expect(f).toEqual([]);
  });

  it('flags an unguarded FastAPI delete next to a guarded route (guard does not leak across handlers)', async () => {
    const f = await authFindings({
      'main.py': [
        'from fastapi import FastAPI, Depends',
        'app = FastAPI()',
        '@app.delete("/items/{item_id}")',
        'def delete_item(item_id: int):',
        '    return {}',
        '',
        '@app.get("/me")',
        'def me(user=Depends(get_user)):',
        '    return user',
      ].join('\n'),
    });
    expect(f.map((x) => [x.file, x.line, x.severity])).toEqual([['main.py', 3, 'critical']]);
  });

  it('warns on POST/PUT/PATCH only when the project uses auth, and skips public-by-design paths', async () => {
    const noAuth = await authFindings({
      'server.js': "const app = require('express')();\napp.post('/api/notes', (req, res) => res.json({}));\n",
    });
    expect(noAuth).toEqual([]);

    const withAuth = await authFindings({
      'server.js': [
        "const app = require('express')();",
        "app.get('/api/me', requireAuth, (req, res) => res.json(req.user));",
        "app.post('/api/notes', (req, res) => res.json({}));",
        "app.post('/api/login', (req, res) => res.json({}));",
        "app.post('/api/webhooks/stripe', (req, res) => res.json({}));",
      ].join('\n'),
    });
    expect(withAuth.map((x) => [x.line, x.severity])).toEqual([[3, 'warning']]);
  });

  it('accepts a session check inside a Next.js route handler', async () => {
    const f = await authFindings({
      'app/api/items/[id]/route.ts': [
        "import { getServerSession } from 'next-auth';",
        'export async function DELETE(req: Request) {',
        '  const session = await getServerSession();',
        "  if (!session) return new Response('no', { status: 401 });",
        "  return new Response('ok');",
        '}',
      ].join('\n'),
    });
    expect(f).toEqual([]);
  });

  it('ignores OpenAPI-only routes and GET-only Flask routes (reported as ALL)', () => {
    const out = unauthenticatedRoutes(
      [
        { method: 'DELETE', path: '/x', file: 'openapi.yaml', guarded: false, source: 'openapi' },
        { method: 'ALL', path: '/users', file: 'app.py', line: 1, guarded: false },
      ],
      new Map([['app.py', '@app.route("/users")\ndef users():\n    return ""\n']]),
    );
    expect(out).toEqual([]);
  });
});

describe('jwt-hardcoded-secret via a literal constant', () => {
  it('flags the constant line once as critical, with no generic duplicate', async () => {
    const f = (
      await scan({
        'server.js': [
          "const jwt = require('jsonwebtoken');",
          "const JWT_SECRET = 'my-super-secret-jwt-key';",
          'const t = jwt.sign({ a: 1 }, JWT_SECRET, { expiresIn: "7d" });',
        ].join('\n'),
      })
    ).filter((x) => x.file === 'server.js' && x.rule !== 'missing-auth-route');
    expect(f.map((x) => [x.rule, x.line, x.severity])).toEqual([['jwt-hardcoded-secret', 2, 'critical']]);
  });

  it('works for Python jwt.encode(payload, SECRET)', async () => {
    const f = (await scan({ 'a.py': 'SECRET = "abcdef123456"\ntok = jwt.encode(p, SECRET, algorithm="HS256")\n' })).filter(
      (x) => x.file === 'a.py',
    );
    expect(f.map((x) => x.rule)).toEqual(['jwt-hardcoded-secret']);
  });

  it('does not flag a constant that is never used as a JWT key', async () => {
    const f = await scan({ 'a.js': "const JWT_SECRET = process.env.JWT_SECRET;\nconst label = 'hello-world';\njwt.sign(p, JWT_SECRET);\n" });
    expect(f.some((x) => x.rule === 'jwt-hardcoded-secret')).toBe(false);
  });
});

describe('py-sql-fstring covers str.format and % formatting', () => {
  it('flags .format() and % SQL, not parameterized execute', async () => {
    const f = await scan({
      'a.py': 'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))\n',
      'b.py': 'cursor.execute("DELETE FROM users WHERE id = %s" % uid)\n',
      'c.py': 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n',
    });
    const files = f.filter((x) => x.rule === 'py-sql-fstring').map((x) => x.file);
    expect(files.sort()).toEqual(['a.py', 'b.py']);
  });
});

describe('env-not-ignored inside a larger repository', () => {
  const vcs = (root: string, ...args: string[]) =>
    execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', '-C', root, ...args], {
      stdio: 'ignore',
    });

  it('treats a gitignored, tracked .env in a subfolder as a standalone project (quiet)', async () => {
    const root = proj({ 'pkg/.env': 'A=bbbbbbbb\n', 'pkg/.gitignore': '.env\n' });
    vcs(root, 'init');
    vcs(root, 'add', '-f', 'pkg/.env', 'pkg/.gitignore');
    vcs(root, 'commit', '-m', 'fixture');
    const f = (await VulnerabilityDetector.scan(path.join(root, 'pkg'))).filter((x) => x.rule === 'env-not-ignored');
    expect(f).toEqual([]);
  });

  it('is still critical for a tracked, non-ignored .env in a subfolder', async () => {
    const root = proj({ 'pkg/.env': 'A=bbbbbbbb\n', 'pkg/a.js': 'x\n' });
    vcs(root, 'init');
    vcs(root, 'add', '-f', 'pkg/.env');
    vcs(root, 'commit', '-m', 'oops');
    const f = (await VulnerabilityDetector.scan(path.join(root, 'pkg'))).find((x) => x.rule === 'env-not-ignored');
    expect(f?.severity).toBe('critical');
  });
});

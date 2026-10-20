import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { FileWalker } from '../src/utils/FileWalker';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { CodeParser } from '../src/parser/CodeParser';
import { Orchestrator } from '../src/core/Orchestrator';
import { buildProgram } from '../src/cli/Commands';

const FAKE_AWS = 'AKIAIOSFODNN7EXAMPLE';

let dirs: string[] = [];

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-walk-'));
  dirs.push(dir);
  for (const [rel, body] of Object.entries(files)) {
    const abs = path.join(dir, ...rel.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, body);
  }
  return dir;
}

async function walked(dir: string): Promise<string[]> {
  return (await FileWalker.walk(dir)).map((f) => f.relPath).sort();
}

afterEach(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  dirs = [];
});

describe('FileWalker .env.* coverage', () => {
  it('walks every .env and .env.* file', async () => {
    const dir = project({
      '.env': 'A=1',
      '.env.staging': 'A=1',
      '.env.development': 'A=1',
      '.env.local': 'A=1',
      '.envrc': 'A=1',
      'notenv': 'A=1',
    });
    const files = await walked(dir);
    expect(files).toEqual(['.env', '.env.development', '.env.local', '.env.staging']);
  });

  it('reports a committed .env.staging as env-not-ignored without scanning its contents', async () => {
    const dir = project({ '.env.staging': `STRIPE_SECRET=sk_test_FAKEFAKEFAKEFAKEFAKE\nAWS=${FAKE_AWS}\n` });
    const findings = await VulnerabilityDetector.scan(dir);
    const envHit = findings.filter((f) => f.rule === 'env-not-ignored');
    expect(envHit.map((f) => f.file)).toEqual(['.env.staging']);
    expect(findings.some((f) => f.rule === 'hardcoded-secret' || f.rule === 'possible-hardcoded-secret')).toBe(false);
  });

  it('does not report .env.staging when the gitignore covers it', async () => {
    const dir = project({ '.env.staging': 'A=1', '.gitignore': '.env*\n' });
    const findings = await VulnerabilityDetector.scan(dir);
    expect(findings.some((f) => f.rule === 'env-not-ignored')).toBe(false);
  });

  it.each(['.env.example', '.env.sample', '.env.template'])('does not report template %s as committed', async (name) => {
    const dir = project({ [name]: `API_KEY=changeme\nAWS=${FAKE_AWS}\n` });
    const findings = await VulnerabilityDetector.scan(dir);
    expect(findings).toEqual([]);
  });

  it('still reports a real env file next to a template', async () => {
    const dir = project({ '.env.example': 'A=1', '.env.production': 'A=1' });
    const findings = await VulnerabilityDetector.scan(dir);
    expect(findings.filter((f) => f.rule === 'env-not-ignored').map((f) => f.file)).toEqual(['.env.production']);
  });
});

const FAKE_GH = `ghp_${'FAKE'.repeat(9)}`;

describe('FileWalker .github/workflows coverage', () => {
  it('walks workflow yml/yaml files but nothing else under .git*', async () => {
    const dir = project({
      '.github/workflows/ci.yml': 'name: ci\n',
      '.github/workflows/release.yaml': 'name: release\n',
      '.github/workflows/notes.md': 'x',
      '.github/workflows/nested/deep.yml': 'x: 1',
      '.github/dependabot.yml': 'version: 2',
      '.github/ISSUE_TEMPLATE/bug.yml': 'x: 1',
      '.gitlab/ci.yml': 'x: 1',
      '.git/config.yml': 'x: 1',
      'pkg/.github/workflows/ci.yml': 'x: 1',
    });
    expect(await walked(dir)).toEqual(['.github/workflows/ci.yml', '.github/workflows/release.yaml']);
  });

  it('flags a hardcoded token literal in a workflow', async () => {
    const dir = project({
      '.github/workflows/ci.yml': `jobs:\n  b:\n    env:\n      GH_TOKEN: ${FAKE_GH}\n      AWS: ${FAKE_AWS}\n`,
    });
    const findings = await VulnerabilityDetector.scan(dir);
    const secrets = findings.filter((f) => f.rule === 'hardcoded-secret');
    expect(secrets.map((f) => f.file)).toEqual(['.github/workflows/ci.yml', '.github/workflows/ci.yml']);
    expect(secrets.map((f) => f.line)).toEqual([4, 5]);
  });

  it('does not flag ${{ secrets.X }} references', async () => {
    const dir = project({
      '.github/workflows/ci.yml': [
        'jobs:',
        '  b:',
        '    steps:',
        '      - run: npm publish',
        '        env:',
        '          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}',
        '          SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}',
        '          AUTH: "Bearer ${{ secrets.API_TOKEN }}"',
        '          DATABASE_URL: postgres://app:${{secrets.DB_PW}}@db.example.internal/app',
        '',
      ].join('\n'),
    });
    expect(await VulnerabilityDetector.scan(dir)).toEqual([]);
  });

  it('flags a literal mixed into a line that also has a secrets reference', async () => {
    const dir = project({
      '.github/workflows/ci.yml': `env:\n  A: \${{ secrets.A }} ${FAKE_AWS}\n`,
    });
    const findings = await VulnerabilityDetector.scan(dir);
    expect(findings.some((f) => f.rule === 'hardcoded-secret')).toBe(true);
  });

  it('does not apply JS rules to workflow YAML', async () => {
    const dir = project({ '.github/workflows/ci.yml': 'run: eval(x) && el.innerHTML = y\n' });
    expect(await VulnerabilityDetector.scan(dir)).toEqual([]);
  });
});

describe('FileWalker .gitignore handling', () => {
  const LEAK = `const k = "${FAKE_AWS}";\n`;

  it('skips ignored dirs/files (root + nested rules, negation, anchoring) and scans the rest', async () => {
    const dir = project({
      '.gitignore': 'generated/\n*.min.js\n/build-out\n# comment\n\n*.gen.js\n!keep.gen.js\n',
      'generated/a.js': LEAK,
      'src/app.min.js': LEAK,
      'build-out/x.js': LEAK,
      'src/build-out/y.js': LEAK,
      'x.gen.js': LEAK,
      'keep.gen.js': LEAK,
      'src/app.js': LEAK,
      'pkg/.gitignore': 'local/\n!special.gen.js\n',
      'pkg/local/z.js': LEAK,
      'pkg/special.gen.js': LEAK,
      'pkg/other.gen.js': LEAK,
      'local/z.js': LEAK,
    });
    const { files, ignoredCount } = await FileWalker.walkWithStats(dir);
    expect(files.map((f) => f.relPath).filter((p) => p.endsWith('.js')).sort()).toEqual([
      'keep.gen.js',
      'local/z.js',
      'pkg/special.gen.js',
      'src/app.js',
      'src/build-out/y.js',
    ]);
    expect(ignoredCount).toBe(6);
    const findings = await VulnerabilityDetector.scan(dir);
    expect(findings.filter((f) => f.rule === 'hardcoded-secret').map((f) => f.file).sort()).toEqual([
      'keep.gen.js',
      'local/z.js',
      'pkg/special.gen.js',
      'src/app.js',
      'src/build-out/y.js',
    ]);
  });

  it('supports ** and ? and nested anchoring', async () => {
    const dir = project({
      '.gitignore': '**/cache/\ndocs/**/*.js\nv?.js\n/pkg/*.tmp.js\n',
      'a/b/cache/x.js': LEAK,
      'docs/x/y/z.js': LEAK,
      'docs/z.js': LEAK,
      'v1.js': LEAK,
      'v10.js': LEAK,
      'pkg/a.tmp.js': LEAK,
      'pkg/deep/a.tmp.js': LEAK,
    });
    expect((await walked(dir)).filter((p) => p.endsWith('.js'))).toEqual(['pkg/deep/a.tmp.js', 'v10.js']);
  });

  it('fails open on patterns it does not understand', async () => {
    const dir = project({
      '.gitignore': '[abc].js\nescaped\ name.js\n\#hash.js\n',
      'a.js': LEAK,
      'b.js': LEAK,
      'c.js': LEAK,
      '#hash.js': LEAK,
    });
    const { files, ignoredCount } = await FileWalker.walkWithStats(dir);
    expect(files.map((f) => f.relPath).filter((p) => p.endsWith('.js')).sort()).toEqual(['#hash.js', 'a.js', 'b.js', 'c.js']);
    expect(ignoredCount).toBe(0);
  });

  it('drops the whole file when a negation is not understood', async () => {
    const dir = project({
      '.gitignore': 'generated/\n![ab].js\n',
      'generated/a.js': LEAK,
    });
    const { files, ignoredCount } = await FileWalker.walkWithStats(dir);
    expect(files.map((f) => f.relPath)).toContain('generated/a.js');
    expect(ignoredCount).toBe(0);
  });

  it.each(['*', '/', '**', '/*', '**/*', '*/', '**/', '*/*'])(
    'ignores the whole-project pattern %j instead of scanning nothing',
    async (pattern) => {
      const dir = project({ '.gitignore': `${pattern}\n`, 'src/app.js': LEAK, 'index.js': LEAK });
      const { files, ignoredCount } = await FileWalker.walkWithStats(dir);
      expect(files.map((f) => f.relPath).filter((p) => p.endsWith('.js')).sort()).toEqual(['index.js', 'src/app.js']);
      expect(ignoredCount).toBe(0);
    },
  );

  it('never skips .gitignore, .env*, workflows, Dockerfile or package.json because of ignore rules', async () => {
    const dir = project({
      '.gitignore': '.gitignore\n.env\n.env.*\n.github/\n.github/workflows\nDockerfile\npackage.json\n*.yml\n.*\n',
      '.env': 'A=1',
      '.env.staging': 'A=1',
      'Dockerfile': 'FROM node',
      'package.json': '{}',
      '.github/workflows/ci.yml': 'name: ci\n',
    });
    const { files, ignoredCount } = await FileWalker.walkWithStats(dir);
    expect(files.map((f) => f.relPath).sort()).toEqual([
      '.env',
      '.env.staging',
      '.github/workflows/ci.yml',
      '.gitignore',
      'Dockerfile',
      'package.json',
    ]);
    expect(ignoredCount).toBe(0);
  });

  it('does not report env-not-ignored when the project gitignores .env (normal good case)', async () => {
    const dir = project({ '.gitignore': '.env\n', '.env': 'A=1' });
    expect((await VulnerabilityDetector.scan(dir)).some((f) => f.rule === 'env-not-ignored')).toBe(false);
    expect((await walked(dir)).includes('.env')).toBe(true);
  });

  it('does not follow a symlink/junction out of the project root', async () => {
    const outside = project({ 'secret.js': LEAK });
    const dir = project({ 'src/app.js': 'x' });
    try {
      fs.symlinkSync(outside, path.join(dir, 'link'), 'junction');
    } catch {
      return;
    }
    expect(await walked(dir)).toEqual(['src/app.js']);
  });

  it('reports the skipped count on the graph and prints one line in analyze output', async () => {
    const dir = project({ '.gitignore': 'generated/\n*.min.js\n', 'generated/a.js': LEAK, 'app.min.js': LEAK, 'app.js': 'x' });
    expect((await CodeParser.analyze(dir)).gitignoreSkipped).toBe(2);

    const lines: string[] = [];
    const spy = jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void lines.push(a.join(' ')));
    try {
      await Orchestrator.analyze(dir, { noDynamic: true, noAi: true, yes: true });
    } finally {
      spy.mockRestore();
    }
    expect(lines.filter((l) => l.includes('Skipped 2 path(s) listed in .gitignore'))).toHaveLength(1);
  });

  it('reports a zero count when nothing was skipped', async () => {
    const dir = project({ '.gitignore': 'nothing-here/\n', 'app.js': 'x' });
    expect((await CodeParser.analyze(dir)).gitignoreSkipped).toBe(0);
  });
});

describe('invalid analyze target', () => {
  const missing = () => path.join(os.tmpdir(), 'dr-definitely-missing-dir-xyz');

  it('FileWalker.walk reports a missing path in one friendly line', async () => {
    await expect(FileWalker.walk(missing())).rejects.toThrow(`Path not found: ${missing()}`);
  });

  it('FileWalker.walk reports a file path as not a directory', async () => {
    const dir = project({ 'a.js': 'x' });
    const file = path.join(dir, 'a.js');
    await expect(FileWalker.walk(file)).rejects.toThrow(`Not a directory: ${file}`);
  });

  async function runCli(args: string[]): Promise<{ err: string; exitCode: number | undefined }> {
    const errs: string[] = [];
    const errSpy = jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => void errs.push(a.join(' ')));
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    const prev = process.exitCode;
    process.exitCode = undefined;
    try {
      await buildProgram().parseAsync(['node', 'deployready', ...args]);
      return { err: errs.join('\n'), exitCode: process.exitCode as number | undefined };
    } finally {
      process.exitCode = prev;
      errSpy.mockRestore();
      logSpy.mockRestore();
    }
  }

  it('analyze <missing path> prints one friendly line and exits 1', async () => {
    const { err, exitCode } = await runCli(['analyze', missing(), '--no-ai', '--no-dynamic']);
    expect(exitCode).toBe(1);
    expect(err).toContain(`Path not found: ${missing()}`);
    expect(err.trim().split('\n')).toHaveLength(1);
    expect(err).not.toMatch(/ENOENT|^\s+at |\.ts:\d+/m);
  });

  it('analyze <file> prints "Not a directory" and exits 1', async () => {
    const dir = project({ 'a.js': 'x' });
    const file = path.join(dir, 'a.js');
    const { err, exitCode } = await runCli(['analyze', file, '--no-ai', '--no-dynamic']);
    expect(exitCode).toBe(1);
    expect(err).toContain(`Not a directory: ${file}`);
    expect(err.trim().split('\n')).toHaveLength(1);
  });
});

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { buildProgram } from '../src/cli/Commands';

function project(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-fix-'));
  fs.writeFileSync(path.join(root, '.env'), 'PORT=3000\n');
  fs.writeFileSync(path.join(root, 'app.js'), "const crypto = require('crypto');\ncrypto.createHash('md5');\n");
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"x"}');
  return root;
}

async function run(root: string, ...args: string[]): Promise<any> {
  const chunks: string[] = [];
  jest.spyOn(process.stdout, 'write').mockImplementation(((s: string) => (chunks.push(String(s)), true)) as never);
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
  await buildProgram().parseAsync(['node', 'deployready', 'analyze', root, '--no-ai', '--no-dynamic', ...args]);
  try {
    return JSON.parse(chunks.join(''));
  } catch {
    return undefined;
  }
}

afterEach(() => {
  jest.restoreAllMocks();
  process.exitCode = 0;
});

describe('analyze --fix', () => {
  it('--json --fix applies fixes, re-scans, reports before/after and keeps stdout pure JSON', async () => {
    const root = project();
    const json = await run(root, '--json', '--fix');
    expect(json).toBeDefined();
    expect(json.fix.applied.length).toBeGreaterThanOrEqual(2);
    expect(json.fix.applied[0]).toHaveProperty('backup');
    expect(json.fix.scoreAfter).toBeGreaterThan(json.fix.scoreBefore);
    expect(json.score).toBe(json.fix.scoreAfter);
    expect(json.findings.some((f: any) => f.rule === 'env-not-ignored')).toBe(false);
    expect(fs.readFileSync(path.join(root, '.gitignore'), 'utf8')).toContain('.env');
    expect(fs.readFileSync(path.join(root, 'app.js'), 'utf8')).toContain('sha256');
  });

  it('--yes --fix applies without a prompt', async () => {
    const root = project();
    await run(root, '--yes', '--fix');
    expect(fs.readFileSync(path.join(root, 'app.js'), 'utf8')).toContain('sha256');
  });

  it('without --fix nothing is modified and there is no fix block', async () => {
    const root = project();
    const json = await run(root, '--json');
    expect(json.fix).toBeUndefined();
    expect(fs.existsSync(path.join(root, '.gitignore'))).toBe(false);
  });

  it('without --yes in a non-terminal, makes no changes', async () => {
    const root = project();
    const prev = process.stdin.isTTY;
    (process.stdin as any).isTTY = false;
    try {
      await run(root, '--fix');
    } finally {
      (process.stdin as any).isTTY = prev;
    }
    expect(fs.readFileSync(path.join(root, 'app.js'), 'utf8')).toContain('md5');
  });

  it('works with --fail-on: gates on the post-fix report', async () => {
    const json = await run(project(), '--json', '--fix', '--fail-on', 'critical');
    expect(json.passed).toBe(true);
    expect(process.exitCode ?? 0).toBe(0);
  });
});

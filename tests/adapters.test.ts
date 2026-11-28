import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runEngines, dedupeAgainstNative, dedupeEngineFindings } from '../src/adapters';
import { parseNpmAudit, parsePnpmAudit } from '../src/adapters/npmAudit';
import { parseOsv } from '../src/adapters/osv';
import { parsePipAudit } from '../src/adapters/pipAudit';
import { semgrepAdapter } from '../src/adapters/semgrep';
import { runBinary } from '../src/adapters/exec';
import { makeFinding } from '../src/utils/finding';

const cov = () => ({ checked: [] as string[], skipped: [] as string[], errors: [] as string[] });
let tmp: string, bin: string, proj: string, oldPath: string | undefined;

/** Install a fake executable that prints `stdout` and exits with `code` (records its argv + cwd). */
function fake(name: string, stdout: string, code = 0): void {
  const body = `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "9.9.9"; exit 0; fi\necho "$@" > "${bin}/${name}.args"\npwd > "${bin}/${name}.cwd"\ncat <<'EOF_JSON'\n${stdout}\nEOF_JSON\nexit ${code}\n`;
  fs.writeFileSync(path.join(bin, name), body, { mode: 0o755 });
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-eng-'));
  bin = path.join(tmp, 'bin'); proj = path.join(tmp, 'proj');
  fs.mkdirSync(bin); fs.mkdirSync(proj);
  oldPath = process.env.PATH;
  process.env.PATH = `${bin}:/usr/bin:/bin`;
});
afterEach(() => { process.env.PATH = oldPath; fs.rmSync(tmp, { recursive: true, force: true }); });

const NPM_JSON = JSON.stringify({
  vulnerabilities: {
    lodash: { name: 'lodash', severity: 'critical', isDirect: true, via: [{ source: 1523, name: 'lodash', title: 'Prototype Pollution', url: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz', severity: 'critical', cwe: ['CWE-1321'], range: '<4.17.21' }], fixAvailable: { name: 'lodash', version: '4.17.21', isSemVerMajor: false } },
    express: { name: 'express', severity: 'high', isDirect: true, via: ['lodash', { source: 2, title: 'Open redirect', url: 'https://github.com/advisories/GHSA-aaaa', severity: 'high' }], fixAvailable: false },
    weird: { name: 'weird', severity: 'low', via: ['lodash'] },
  },
});
const LOCK = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/lodash': { version: '4.17.4' } } });

describe('npm audit parsing', () => {
  it('maps advisories to normalized findings with severity policy and fix command', () => {
    const c = cov();
    const f = parseNpmAudit(NPM_JSON, JSON.parse(LOCK), 'package-lock.json', c)!;
    expect(c.errors).toEqual([]);
    const lodash = f.find((x) => x.title.startsWith('lodash@4.17.4'))!;
    expect(lodash).toMatchObject({ rule: 'dependency-vulnerability', severity: 'critical', source: 'engine:npm-audit', cwe: 'CWE-1321', file: 'package-lock.json' });
    expect(lodash.recommendation).toBe('npm install lodash@4.17.21');
    expect(lodash.description).toContain('GHSA-xxxx-yyyy-zzzz');
    expect(f.find((x) => x.title.includes('Open redirect'))!.severity).toBe('warning'); // high -> warning
    expect(f.some((x) => x.title.includes('Depends on a vulnerable package'))).toBe(true);
  });
  it.each([['not json'], ['{"error":{"summary":"ENOTFOUND registry"}}'], ['{"foo":1}'], ['[]']])('reports an error, never a clean pass: %s', (out) => {
    const c = cov();
    expect(parseNpmAudit(out, {}, 'package-lock.json', c)).toBeUndefined();
    expect(c.errors).toHaveLength(1);
  });
  it('parses pnpm audit', () => {
    const c = cov();
    const f = parsePnpmAudit(JSON.stringify({ advisories: { '7': { module_name: 'x', severity: 'high', title: 'T', url: 'https://github.com/advisories/GHSA-1', cves: ['CVE-1'], cwe: 'CWE-79', findings: [{ version: '1.0.0' }], patched_versions: '>=1.0.1' } } }), c)!;
    expect(f[0]).toMatchObject({ severity: 'warning', cwe: 'CWE-79', file: 'pnpm-lock.yaml' });
  });
});

describe('osv / pip-audit parsing', () => {
  it('parses osv-scanner output and rejects paths outside the project', () => {
    const c = cov();
    const out = JSON.stringify({ results: [
      { source: { path: path.join(proj, 'package-lock.json') }, packages: [{ package: { name: 'minimist', version: '1.2.0' }, groups: [{ ids: ['GHSA-1'], max_severity: '9.8' }], vulnerabilities: [{ id: 'GHSA-1', aliases: ['CVE-2020-1'], summary: 'Pollution', affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '1.2.3' }] }] }] }] }] },
      { source: { path: '/etc/evil' }, packages: [] },
    ] });
    const f = parseOsv(out, proj, c)!;
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: 'critical', file: 'package-lock.json', source: 'engine:osv-scanner' });
    expect(f[0]!.recommendation).toContain('1.2.3');
  });
  it('parses pip-audit and errors on garbage', () => {
    const c = cov();
    const f = parsePipAudit(JSON.stringify({ dependencies: [{ name: 'django', version: '2.0', vulns: [{ id: 'PYSEC-1', fix_versions: ['2.2'], aliases: ['CVE-9'] }] }, { name: 'ok', version: '1', vulns: [] }] }), 'requirements.txt', c)!;
    expect(f).toHaveLength(1);
    expect(parsePipAudit('nope', 'requirements.txt', c)).toBeUndefined();
    expect(c.errors).toHaveLength(1);
  });
});

describe('runEngines with fake binaries', () => {
  it('runs npm audit with an arg array in the project cwd and tolerates exit 1', async () => {
    fs.writeFileSync(path.join(proj, 'package-lock.json'), LOCK);
    fake('npm', NPM_JSON, 1);
    const r = await runEngines(proj, {});
    const run = r.runs.find((x) => x.id === 'npm-audit')!;
    expect(run.status).toBe('ran');
    expect(r.findings.length).toBeGreaterThan(0);
    expect(fs.readFileSync(path.join(bin, 'npm.args'), 'utf8').trim()).toBe('audit --json --omit=dev');
    expect(fs.realpathSync(fs.readFileSync(path.join(bin, 'npm.cwd'), 'utf8').trim())).toBe(fs.realpathSync(proj));
  });
  it('reports a failing engine as an error with no findings', async () => {
    fs.writeFileSync(path.join(proj, 'package-lock.json'), LOCK);
    fake('npm', '{"error":{"code":"ENOTFOUND","summary":"request to registry failed"}}', 1);
    const r = await runEngines(proj, {});
    expect(r.findings).toEqual([]);
    expect(r.runs[0]).toMatchObject({ id: 'npm-audit', status: 'error' });
    expect(r.runs[0]!.coverage.errors[0]).toContain('registry');
  });
  it('--offline and --no-deps skip with a recorded reason / no run', async () => {
    fs.writeFileSync(path.join(proj, 'package-lock.json'), LOCK);
    fake('npm', NPM_JSON, 1);
    const off = await runEngines(proj, { offline: true });
    expect(off.runs[0]).toMatchObject({ id: 'npm-audit', status: 'skipped' });
    expect(off.runs[0]!.reason).toContain('--offline');
    expect(fs.existsSync(path.join(bin, 'npm.args'))).toBe(false);
    expect((await runEngines(proj, { noDeps: true })).runs).toEqual([]);
  });
  it('skips yarn with a coverage note and unknown engines are errors', async () => {
    fs.writeFileSync(path.join(proj, 'yarn.lock'), '');
    fake('npm', '{}');
    const r = await runEngines(proj, { engines: 'bogus' });
    expect(r.runs.some((x) => x.id === 'bogus' && x.status === 'error')).toBe(true);
    const y = await runEngines(proj, {});
    expect(y.runs[0]!.coverage.skipped[0]).toContain('yarn');
  });
  it('osv-scanner and pip-audit run only when installed', async () => {
    fs.writeFileSync(path.join(proj, 'requirements.txt'), 'django==2.0\n');
    fs.writeFileSync(path.join(proj, 'pyproject.toml'), '');
    let r = await runEngines(proj, {});
    expect(r.runs.find((x) => x.id === 'pip-audit')!.reason).toContain('not installed');
    fake('pip-audit', JSON.stringify({ dependencies: [{ name: 'django', version: '2.0', vulns: [{ id: 'PYSEC-1', fix_versions: ['2.2'] }] }] }), 1);
    r = await runEngines(proj, {});
    const run = r.runs.find((x) => x.id === 'pip-audit')!;
    expect(run.status).toBe('ran');
    expect(run.coverage.skipped.join()).toContain('pyproject.toml');
    expect(fs.readFileSync(path.join(bin, 'pip-audit.args'), 'utf8')).toContain('--disable-pip');
  });
  it('dedupes the same advisory across npm-audit and osv-scanner', async () => {
    fs.writeFileSync(path.join(proj, 'package-lock.json'), LOCK);
    fake('npm', NPM_JSON, 1);
    fake('osv-scanner', JSON.stringify({ results: [{ source: { path: path.join(proj, 'package-lock.json') }, packages: [{ package: { name: 'lodash', version: '4.17.4' }, vulnerabilities: [{ id: 'GHSA-xxxx-yyyy-zzzz', summary: 'PP', database_specific: { severity: 'CRITICAL' } }] }] }] }), 1);
    const r = await runEngines(proj, {});
    const lodash = r.findings.filter((f) => f.title.startsWith('lodash@4.17.4'));
    expect(lodash).toHaveLength(1);
    expect(lodash[0]!.description).toContain('also reported by osv-scanner');
    expect(dedupeEngineFindings(r.findings)).toHaveLength(r.findings.length);
  });
});

describe('native dedupe', () => {
  it('keeps the native finding and annotates it when file+line+CWE match', () => {
    const native = makeFinding({ rule: 'sql-injection', title: 'SQLi', severity: 'critical', category: 'security', source: 'static', description: 'd', recommendation: 'r', file: 'a.js', line: 3, cwe: 'CWE-89' });
    const dupe = makeFinding({ rule: 'semgrep:x', title: 'x', severity: 'warning', category: 'security', source: 'engine:semgrep', description: 'd', recommendation: 'r', file: 'a.js', line: 3, cwe: 'CWE-89' });
    const other = { ...dupe, id: 'zzz', line: 9 };
    const r = dedupeAgainstNative([native], [dupe, other]);
    expect(r.engine).toEqual([other]);
    expect(r.native[0]!.description).toContain('also reported by semgrep');
  });
});

describe('safe exec', () => {
  it('never uses a shell and enforces timeouts and a minimal env', async () => {
    process.env.SECRET_TOKEN = 'leak';
    fs.writeFileSync(path.join(bin, 'envdump'), '#!/bin/sh\nenv\n', { mode: 0o755 });
    const r = await runBinary(path.join(bin, 'envdump'), ['a; touch /tmp/pwned'], { cwd: proj });
    expect(r.stdout).not.toContain('SECRET_TOKEN');
    delete process.env.SECRET_TOKEN;
    fs.writeFileSync(path.join(bin, 'slow'), '#!/bin/sh\nsleep 5\n', { mode: 0o755 });
    const t = await runBinary(path.join(bin, 'slow'), [], { cwd: proj, timeoutMs: 200 });
    expect(t.timedOut).toBe(true);
    expect((await runBinary('/nonexistent-bin', [], { cwd: proj })).spawnError).toBeDefined();
  });
});

describe('semgrep adapter', () => {
  const opts = { offline: false, timeoutMs: 60_000 };
  it('does nothing without --semgrep-config and refuses auto', async () => {
    expect((await semgrepAdapter.run(proj, opts)).coverage.skipped[0]).toContain('--semgrep-config');
    expect((await semgrepAdapter.run(proj, { ...opts, semgrepConfig: 'auto' })).coverage.errors[0]).toContain('auto');
  });
  it('skips a registry config when offline', async () => {
    expect((await semgrepAdapter.run(proj, { ...opts, offline: true, semgrepConfig: 'p/ci' })).coverage.skipped[0]).toContain('--offline');
  });
  it('parses fake semgrep output and drops paths outside the project', async () => {
    fs.writeFileSync(path.join(proj, 'rules.yml'), 'rules: []');
    fake('semgrep', JSON.stringify({ results: [
      { check_id: 'r.eval', path: 'a.js', start: { line: 2 }, extra: { message: 'eval used', severity: 'ERROR', metadata: { cwe: ['CWE-95: Eval Injection'] } } },
      { check_id: 'r.bad', path: '../../etc/passwd', start: { line: 1 }, extra: { message: 'x', severity: 'ERROR' } },
    ], errors: [] }), 1);
    const r = await semgrepAdapter.run(proj, { ...opts, semgrepConfig: path.join(proj, 'rules.yml') });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ file: 'a.js', line: 2, cwe: 'CWE-95', severity: 'warning', source: 'engine:semgrep' });
    expect(fs.readFileSync(path.join(bin, 'semgrep.args'), 'utf8')).toContain('--metrics=off');
  });
  const real = fs.existsSync('/usr/local/bin/semgrep');
  (real ? it : it.skip)('real semgrep run with a local rule', async () => {
    process.env.PATH = `/usr/local/bin:${oldPath}`;
    fs.writeFileSync(path.join(proj, 'a.js'), 'eval(userInput)\n');
    fs.writeFileSync(path.join(proj, 'rules.yml'), 'rules:\n  - id: no-eval\n    pattern: eval(...)\n    message: avoid eval\n    languages: [javascript]\n    severity: ERROR\n    metadata:\n      cwe: ["CWE-95"]\n');
    const r = await runEngines(proj, { engines: 'semgrep', semgrepConfig: path.join(proj, 'rules.yml') });
    const run = r.runs.find((x) => x.id === 'semgrep')!;
    if (run.status === 'error') { console.warn('semgrep real run unavailable:', run.reason); return; }
    expect(r.findings[0]).toMatchObject({ file: 'a.js', line: 1, cwe: 'CWE-95' });
  }, 90_000);
});

describe('real npm audit (skipped when the registry is unreachable)', () => {
  it('flags a known-vulnerable package', async () => {
    process.env.PATH = oldPath;
    const npm = require('child_process').spawnSync('npm', ['--version']);
    if (npm.status !== 0) return;
    fs.writeFileSync(path.join(proj, 'package.json'), JSON.stringify({ name: 'fx', version: '1.0.0', dependencies: { minimist: '1.2.0' } }));
    const lock = await runBinary('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: proj, timeoutMs: 60_000 });
    if (lock.code !== 0) { console.warn('registry unreachable; skipping real npm audit'); return; }
    const r = await runEngines(proj, { engines: 'npm-audit' });
    const run = r.runs[0]!;
    if (run.status !== 'ran') { console.warn('npm audit unavailable:', run.reason); return; }
    expect(r.findings.some((f) => f.title.startsWith('minimist@1.2.0'))).toBe(true);
  }, 120_000);
});

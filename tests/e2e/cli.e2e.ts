/**
 * End-to-end: `npm pack` the package, install the tarball into a fresh temp project and drive the installed bin
 * exactly like a user would (`npm test` does NOT run this; use `npm run test:e2e`).
 *
 * Portability: the bin is started with process.execPath (no .cmd shim, no shell), paths are built with `path`, and only
 * npm itself is started through a shell on Windows (npm is npm.cmd there). The scan fixtures are written at run time.
 */
import { spawn, spawnSync, type SpawnSyncReturns } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const REPO = path.resolve(__dirname, '..', '..');
const IS_WIN = process.platform === 'win32';
const SCAN_FLAGS = ['--no-dynamic', '--no-ai', '--offline'];

let work: string;
let bin: string;
let vuln: string;
let clean: string;
let empty: string;

function npm(args: string[], cwd: string): SpawnSyncReturns<string> {
  return spawnSync(IS_WIN ? 'npm.cmd' : 'npm', args, { cwd, encoding: 'utf8', shell: IS_WIN, maxBuffer: 1 << 26 });
}

function run(args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [bin, ...args], {
    cwd: opts.cwd ?? work,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0', CI: '1', ...opts.env },
    timeout: 120000,
    maxBuffer: 1 << 26,
  });
}

function write(file: string, body: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
}

beforeAll(() => {
  work = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'deployready-e2e-')));
  const build = npm(['run', 'build'], REPO);
  if (build.status !== 0) throw new Error(`npm run build failed:\n${build.stdout}\n${build.stderr}`);

  const packDir = path.join(work, 'pack');
  fs.mkdirSync(packDir);
  const pack = npm(['pack', '--json', '--pack-destination', packDir], REPO);
  if (pack.status !== 0) throw new Error(`npm pack failed:\n${pack.stdout}\n${pack.stderr}`);
  const filename = (JSON.parse(pack.stdout.slice(pack.stdout.indexOf('['))) as Array<{ filename: string }>)[0]!.filename;
  const tarball = path.join(packDir, path.basename(filename));
  expect(fs.existsSync(tarball)).toBe(true);

  const proj = path.join(work, 'install');
  write(path.join(proj, 'package.json'), JSON.stringify({ name: 'e2e-host', version: '1.0.0', private: true }));
  const install = npm(['install', tarball, '--no-audit', '--no-fund', '--loglevel=error'], proj);
  if (install.status !== 0) throw new Error(`npm install of the tarball failed:\n${install.stdout}\n${install.stderr}`);
  bin = path.join(proj, 'node_modules', 'deployready', 'bin', 'deployready.js');
  expect(fs.existsSync(bin)).toBe(true);

  vuln = path.join(work, 'vuln');
  write(path.join(vuln, 'package.json'), JSON.stringify({ name: 'vuln', version: '1.0.0' }));
  write(path.join(vuln, 'server.js'), "const https = require('https')\nmodule.exports = new https.Agent({ rejectUnauthorized: false })\n");
  clean = path.join(work, 'clean');
  write(path.join(clean, 'package.json'), JSON.stringify({ name: 'clean', version: '1.0.0' }));
  write(path.join(clean, 'index.js'), "console.log('hello')\n");
  empty = path.join(work, 'empty');
  fs.mkdirSync(empty);
}, 600000);

afterAll(() => {
  try { fs.rmSync(work, { recursive: true, force: true, maxRetries: 3 }); } catch { /* best effort (Windows file locks) */ }
});

describe('installed tarball', () => {
  it('ships the bin and dist, and the package.json version matches --version', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'package.json'), 'utf8')) as { version: string };
    const r = run(['--version']);
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe(pkg.version);
  });

  it('npm created a bin entry for deployready', () => {
    const shim = path.join(work, 'install', 'node_modules', '.bin', IS_WIN ? 'deployready.cmd' : 'deployready');
    expect(fs.existsSync(shim)).toBe(true);
  });
});

describe('analyze', () => {
  it('--json on a fixture prints a machine-readable report with a confirmed finding', () => {
    const r = run(['analyze', '--json', ...SCAN_FLAGS, vuln]);
    expect(r.status).toBe(0);
    const j = JSON.parse(r.stdout) as { tool: string; version: string; findings: Array<{ rule: string; severity: string }>; release: { state: string } };
    expect(j.tool).toBe('deployready');
    expect(j.findings.some((f) => f.rule === 'tls-verification-disabled' && f.severity === 'critical')).toBe(true);
    expect(j.release.state).toBe('not-ready');
  });

  it('--json on a clean fixture reports a ready release with no findings', () => {
    const j = JSON.parse(run(['analyze', '--json', ...SCAN_FLAGS, clean]).stdout) as { findings: unknown[]; release: { state: string } };
    expect(j.findings).toHaveLength(0);
    expect(j.release.state).toBe('ready');
  });

  it('--offline works even when every outbound connection is black-holed', () => {
    const r = run(['analyze', '--json', ...SCAN_FLAGS, vuln], {
      env: { HTTP_PROXY: 'http://127.0.0.1:9', HTTPS_PROXY: 'http://127.0.0.1:9', http_proxy: 'http://127.0.0.1:9', https_proxy: 'http://127.0.0.1:9' },
    });
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout).findings.length).toBeGreaterThan(0);
  });

  it('--sarif writes a SARIF 2.1.0 file with results', () => {
    const out = path.join(work, 'out.sarif');
    const r = run(['analyze', ...SCAN_FLAGS, '--sarif', out, vuln]);
    expect(r.status).toBe(0);
    const sarif = JSON.parse(fs.readFileSync(out, 'utf8')) as { version: string; runs: Array<{ tool: { driver: { name: string } }; results: unknown[] }> };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.tool.driver.name).toBe('DeployReady');
    expect(sarif.runs[0]!.results.length).toBeGreaterThan(0);
  });
});

describe('exit codes', () => {
  it('0: findings below the gate (or no gate) do not fail', () => {
    expect(run(['analyze', '--json', ...SCAN_FLAGS, '--fail-on', 'critical', clean]).status).toBe(0);
    expect(run(['analyze', '--json', ...SCAN_FLAGS, vuln]).status).toBe(0);
  });

  it('2: findings at/above --fail-on severity', () => {
    expect(run(['analyze', '--json', ...SCAN_FLAGS, '--fail-on', 'critical', vuln]).status).toBe(2);
  });

  it('2: a release state at/worse than --fail-on-release-state', () => {
    expect(run(['analyze', '--json', ...SCAN_FLAGS, '--fail-on-release-state', 'not-ready', vuln]).status).toBe(2);
  });

  it('3: insufficient evidence (nothing scannable) under a release-state gate', () => {
    const r = run(['analyze', '--json', ...SCAN_FLAGS, '--fail-on-release-state', 'review-required', empty]);
    expect(r.status).toBe(3);
    expect(JSON.parse(r.stdout).release.state).toBe('insufficient-evidence');
  });
});

describe('badge', () => {
  it('prints a markdown badge for the score', () => {
    const r = run(['badge', clean]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/!\[DeployReady score\]\(https:\/\/img\.shields\.io\/badge\/DeployReady-100%2F100-brightgreen\)/);
  });
});

describe('mcp (stdio)', () => {
  it('answers initialize and tools/list over JSON-RPC', async () => {
    const child = spawn(process.execPath, [bin, 'mcp', clean], { cwd: work, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, NO_COLOR: '1', CI: '1' } });
    const pending = new Map<number, (m: any) => void>();
    let buf = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (d: string) => {
      buf += d;
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line.startsWith('{')) continue;
        try { const m = JSON.parse(line); if (typeof m.id === 'number') pending.get(m.id)?.(m); } catch { /* not JSON-RPC */ }
      }
    });
    const call = (id: number, method: string, params: unknown) =>
      new Promise<any>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`mcp ${method} timed out`)), 60000);
        pending.set(id, (m) => { clearTimeout(timer); resolve(m); });
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      });
    try {
      const init = await call(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'e2e', version: '0.0.0' } });
      expect(init.result.serverInfo.name).toBeTruthy();
      expect(init.result.capabilities.tools).toBeDefined();
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
      const list = await call(2, 'tools/list', {});
      const names = (list.result.tools as Array<{ name: string }>).map((t) => t.name);
      expect(names.length).toBeGreaterThan(0);
      expect(names.every((n) => typeof n === 'string' && n.length > 0)).toBe(true);
    } finally {
      child.kill();
    }
  }, 120000);
});

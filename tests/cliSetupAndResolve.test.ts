/**
 * CLI-provider resolution, the provider/login step, and the "DeployReady never touches a
 * CLI credential" guarantee. Verified with fakes only: no real CLI, no network, no credentials.
 */
jest.mock('axios');

import * as fs from 'fs';
import * as path from 'path';
import { resolveCli } from '../src/ai/cli/resolve';
import { CLI_PROVIDERS } from '../src/ai/cli/providers';
import { checkCliReady, startCliLogin, CODEX_DISABLED_MESSAGE } from '../src/ai/cli/ready';
import type { CliReadiness } from '../src/ai/cli/ready';
import { CliHandler } from '../src/ai/CliHandler';
import { ModelRouter } from '../src/ai/ModelRouter';
import { setupCliProvider } from '../src/cli/cliSetup';
import { claudeOk, makeFakeCli, realTmp, testEnv } from './helpers/fakeCli';
import type { FakeCli } from './helpers/fakeCli';

jest.setTimeout(60_000);

const WIN = process.platform === 'win32';
let work: string;
let fake: FakeCli | undefined;

beforeEach(() => {
  work = fs.mkdtempSync(path.join(realTmp(), 'dr-setup-work-'));
});
afterEach(() => {
  fake?.cleanup();
  fake = undefined;
  fs.rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  jest.restoreAllMocks();
});

function silentLog(): { info: jest.Mock; warn: jest.Mock; success: jest.Mock } {
  return { info: jest.fn(), warn: jest.fn(), success: jest.fn() };
}

describe('resolveCli', () => {
  const claude = CLI_PROVIDERS['claude-cli'];

  (WIN ? it : it.skip)('prefers a real .exe over a .cmd shim in the same and in a later PATH directory', () => {
    const a = fs.mkdtempSync(path.join(work, 'a '));
    const b = fs.mkdtempSync(path.join(work, 'b '));
    fs.writeFileSync(path.join(a, 'claude.cmd'), '@echo off\r\n');
    fs.writeFileSync(path.join(b, 'claude.exe'), 'MZ');
    const r = resolveCli(claude, { env: { PATH: `${a};${b}` }, platform: 'win32' });
    expect(r).toEqual({ path: path.win32.join(b, 'claude.exe'), kind: 'exe' });
  });

  (WIN ? it : it.skip)('finds a .cmd shim in a directory whose path contains a space and marks it as a shim', () => {
    const dir = fs.mkdtempSync(path.join(work, 'dir with space '));
    fs.writeFileSync(path.join(dir, 'claude.cmd'), '@echo off\r\n');
    const r = resolveCli(claude, { env: { PATH: `"${dir}"` }, platform: 'win32' });
    expect(r?.kind).toBe('shim');
    expect(r?.path).toBe(path.win32.join(dir, 'claude.cmd'));
  });

  it('ignores relative PATH entries and the current directory, so a scanned project cannot plant a CLI', () => {
    const planted = fs.mkdtempSync(path.join(work, 'project-'));
    fs.writeFileSync(path.join(planted, WIN ? 'claude.exe' : 'claude'), 'x', { mode: 0o755 });
    const prev = process.cwd();
    process.chdir(planted);
    try {
      const sep = WIN ? ';' : ':';
      expect(resolveCli(claude, { env: { PATH: `.${sep}${sep}bin${sep}..` } })).toBeNull();
    } finally {
      process.chdir(prev);
    }
  });

  it('returns null when nothing is on PATH', () => {
    expect(resolveCli(claude, { env: { PATH: work } })).toBeNull();
  });

  it('accepts a configured command only when it is an absolute path named claude/codex', () => {
    const wrong = path.join(work, WIN ? 'notclaude.exe' : 'notclaude');
    fs.writeFileSync(wrong, 'x');
    expect(() => resolveCli(claude, { cliCommand: wrong })).toThrow(/file name must be/);
    expect(() => resolveCli(claude, { cliCommand: 'claude' })).toThrow(/absolute/);
    expect(() => resolveCli(claude, { cliCommand: path.join(work, WIN ? 'claude.exe' : 'claude') })).toThrow(/no such file/);
    expect(() => resolveCli(claude, { cliCommand: `${work}${path.sep}claude\0.exe` })).toThrow(/NUL/);
  });
});

// eslint-disable-next-line @typescript-eslint/no-var-requires
const rawFs = require('fs') as Record<string, (...a: unknown[]) => unknown>;

describe('credential safety: DeployReady never opens, lists or stores a CLI login', () => {
  const FAKE_FILES = ['.claude/.credentials.json', '.claude.json', '.codex/auth.json'];

  it('does not read anything under the home directory while checking readiness, running a model call, or logging in', async () => {
    const home = fs.mkdtempSync(path.join(realTmp(), 'dr-fakehome-'));
    for (const f of FAKE_FILES) {
      fs.mkdirSync(path.dirname(path.join(home, f)), { recursive: true });
      fs.writeFileSync(path.join(home, f), '{"token":"SENTINEL-NOT-A-REAL-TOKEN"}');
    }
    fake = makeFakeCli(
      'claude',
      {
        status: { stdout: JSON.stringify({ loggedIn: true, authMethod: 'claude.ai' }) },
        run: { stdout: claudeOk(JSON.stringify({ summary: 'ok', findings: [] })) },
        login: { stdout: '' },
      },
    );
    const env = testEnv({ HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: path.join(home, '.claude') });
    const touched: string[] = [];
    const norm = (p: unknown): string | null => (typeof p === 'string' || p instanceof URL ? String(p).toLowerCase().replace(/\\/g, '/') : null);
    const homeKey = home.toLowerCase().replace(/\\/g, '/');
    for (const fn of ['readFileSync', 'readFile', 'openSync', 'open', 'createReadStream', 'readdirSync', 'readdir', 'statSync', 'lstatSync', 'copyFileSync', 'cpSync', 'existsSync', 'accessSync'] as const) {
      const orig = rawFs[fn];
      if (typeof orig !== 'function') continue;
      jest.spyOn(rawFs as never, fn as never).mockImplementation(((...args: unknown[]) => {
        const p = norm(args[0]);
        if (p && p.startsWith(homeKey)) touched.push(`${fn}:${p}`);
        return orig.apply(rawFs, args);
      }) as never);
    }

    // positive control: the spy sees accesses made from inside src/ too (resolve.ts stats the path it is given)
    try {
      resolveCli(CLI_PROVIDERS['claude-cli'], { cliCommand: path.join(home, '.claude', 'claude.exe') });
    } catch {
      /* expected: wrong file */
    }
    expect(touched.length).toBeGreaterThan(0);
    touched.length = 0;

    const ctx = { cliCommand: fake.command, env, tmpRoot: work };
    expect((await checkCliReady('claude-cli', ctx)).state).toBe('ready');
    const h = new CliHandler('claude-cli', { cliCommand: fake.command, env, tmpRoot: work });
    await h.complete({ system: 's', user: '{"x":1}' }).catch(() => undefined);
    await startCliLogin('claude-cli', ctx).catch(() => undefined);

    expect(touched).toEqual([]);
    // and nothing was copied into the work dir or the config
    expect(fs.readdirSync(work)).toEqual([]);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('the saved config never contains a token field for the CLI providers', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'types.ts'), 'utf8');
    const cfg = /interface AppConfig \{[\s\S]*?\n\}/.exec(src)?.[0] ?? '';
    expect(cfg).toContain('cliCommand');
    expect(cfg).not.toMatch(/cli\w*(token|key|secret|credential|auth)/i);
  });
});

describe('checkCliReady states (fake CLI)', () => {
  it('codex-cli is disabled only when codexEnabled is false, and then runs nothing', async () => {
    fake = makeFakeCli('codex', { status: { exitCode: 0 } });
    const off = await checkCliReady('codex-cli', { cliCommand: fake.command, env: testEnv(), tmpRoot: work, codexEnabled: false });
    expect(off.state).toBe('disabled');
    expect(off.message).toBe(CODEX_DISABLED_MESSAGE);
    expect(fake.records()).toEqual([]);
    for (const flag of [undefined, true]) {
      const on = await checkCliReady('codex-cli', { cliCommand: fake.command, env: testEnv(), tmpRoot: work, codexEnabled: flag });
      expect(on.state).toBe('ready');
    }
  });

  it('codex login status: exit 1 means not logged in; any other code is unknown (output is discarded)', async () => {
    fake = makeFakeCli('codex', { status: { exitCode: 1, stdout: 'Not logged in as someone@example.com' } });
    const ctx = { cliCommand: fake.command, env: testEnv(), tmpRoot: work };
    const r = await checkCliReady('codex-cli', ctx);
    expect(r.state).toBe('not_logged_in');
    expect(JSON.stringify(r)).not.toContain('someone@example.com');
    fake.setBehavior({ status: { exitCode: 7 } });
    expect((await checkCliReady('codex-cli', ctx)).state).toBe('unknown');
  });

  it('claude auth status: reads only loggedIn/authMethod and never echoes other fields', async () => {
    fake = makeFakeCli('claude', { status: { stdout: JSON.stringify({ loggedIn: true, authMethod: 'claude.ai', email: 'a@b.test', token: 'SENTINEL' }) } });
    const r = await checkCliReady('claude-cli', { cliCommand: fake.command, env: testEnv(), tmpRoot: work });
    expect(r.state).toBe('ready');
    expect(JSON.stringify(r)).not.toMatch(/a@b\.test|SENTINEL/);
    fake.setBehavior({ status: { stdout: JSON.stringify({ loggedIn: false }) } });
    expect((await checkCliReady('claude-cli', { cliCommand: fake.command, env: testEnv(), tmpRoot: work })).state).toBe('not_logged_in');
    fake.setBehavior({ status: { stdout: 'garbage' } });
    expect((await checkCliReady('claude-cli', { cliCommand: fake.command, env: testEnv(), tmpRoot: work })).state).toBe('unknown');
  });

  it('reports missing when the CLI is not on PATH', async () => {
    const r = await checkCliReady('claude-cli', { env: { PATH: work }, tmpRoot: work });
    expect(r.state).toBe('missing');
  });
});

describe('setupCliProvider (the provider/login step)', () => {
  const ready = (provider: 'claude-cli' | 'codex-cli'): CliReadiness => ({ state: 'ready', provider, message: 'Logged in.' });
  const notLoggedIn = (provider: 'claude-cli' | 'codex-cli'): CliReadiness => ({ state: 'not_logged_in', provider, message: 'Not logged in.' });

  it('does nothing more when already logged in', async () => {
    const confirm = jest.fn();
    const login = jest.fn();
    const log = silentLog();
    const r = await setupCliProvider('claude-cli', { check: async () => ready('claude-cli'), login, confirm, log });
    expect(r.state).toBe('ready');
    expect(confirm).not.toHaveBeenCalled();
    expect(login).not.toHaveBeenCalled();
    expect(log.success).toHaveBeenCalled();
  });

  it.each(['missing', 'disabled'] as const)('on %s it warns and never offers a login', async (state) => {
    const confirm = jest.fn();
    const login = jest.fn();
    const log = silentLog();
    const r = await setupCliProvider('codex-cli', { check: async () => ({ state, provider: 'codex-cli', message: 'nope' }), login, confirm, log });
    expect(r.state).toBe(state);
    expect(confirm).not.toHaveBeenCalled();
    expect(login).not.toHaveBeenCalled();
    expect(log.warn).toHaveBeenCalledWith('nope');
  });

  it('asks before logging in and does not log in when the user declines', async () => {
    const confirm = jest.fn().mockResolvedValue(false);
    const login = jest.fn();
    const log = silentLog();
    const r = await setupCliProvider('claude-cli', { check: async () => notLoggedIn('claude-cli'), login, confirm, log });
    expect(r.state).toBe('not_logged_in');
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('claude auth login'), false);
    expect(login).not.toHaveBeenCalled();
  });

  it('runs the CLI login after consent and re-checks the status', async () => {
    const states: CliReadiness[] = [notLoggedIn('codex-cli'), ready('codex-cli')];
    const check = jest.fn().mockImplementation(async () => states.shift());
    const login = jest.fn().mockResolvedValue(true);
    const r = await setupCliProvider('codex-cli', { check, login, confirm: async () => true, log: silentLog(), ctx: {} });
    expect(login).toHaveBeenCalledTimes(1);
    expect(check).toHaveBeenCalledTimes(2);
    expect(r.state).toBe('ready');
  });

  it('survives a login that throws and reports the state afterwards', async () => {
    const log = silentLog();
    const check = jest.fn().mockResolvedValue(notLoggedIn('claude-cli'));
    const login = jest.fn().mockRejectedValue(new Error('login blew up'));
    const r = await setupCliProvider('claude-cli', { check, login, confirm: async () => true, log });
    expect(r.state).toBe('not_logged_in');
    expect(log.warn).toHaveBeenCalledWith('login blew up');
  });

  it('end to end against the fake CLI: login flips the fake status to logged in', async () => {
    fake = makeFakeCli('claude', {
      status: { stdout: JSON.stringify({ loggedIn: false }) },
      login: { stdout: '', thenStatus: { stdout: JSON.stringify({ loggedIn: true, authMethod: 'claude.ai' }) } },
    });
    const r = await setupCliProvider('claude-cli', {
      confirm: async () => true,
      log: silentLog(),
      ctx: { cliCommand: fake.command, env: testEnv(), tmpRoot: work },
    });
    expect(r.state).toBe('ready');
    const kinds = fake.records().map((x) => x.kind);
    expect(kinds).toEqual(['status', 'login', 'status']);
    expect(kinds).not.toContain('run');
  });
});

describe('ModelRouter with the CLI providers', () => {
  it('checkReady reports codex-cli as disabled when codexEnabled is false and consent text mentions the plan', async () => {
    const base = {
      model: 'codex-cli' as const, claudeApiKey: null, openaiApiKey: null, ollamaPort: 11434, ollamaModel: 'llama3',
      cliCommand: null, cliModel: null, warnBeforeExternalSend: true, defaultPorts: [3000], probeCommonPaths: false,
    };
    const router = new ModelRouter({ ...base, codexEnabled: false }, { env: testEnv(), tmpRoot: work });
    const r = await router.checkReady();
    expect(r?.state).toBe('disabled');
    expect(router.consentNotice('report')).toMatch(/plan/i);
  });
});

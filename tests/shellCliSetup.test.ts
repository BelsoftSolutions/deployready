/**
 * In-session AI setup with the CLI providers, driven through the real InteractiveShell against a
 * FAKE CLI (verified with fakes only: no real CLI, no network, no credentials).
 */
import { PassThrough, Writable } from 'stream';
import * as fs from 'fs';
import * as path from 'path';
import { InteractiveShell } from '../src/cli/InteractiveShell';
import { ConfigManager } from '../src/config/ConfigManager';
import type { AppConfig } from '../src/types';
import { makeFakeCli } from './helpers/fakeCli';
import type { FakeCli } from './helpers/fakeCli';

jest.mock('../src/config/ConfigManager');
jest.setTimeout(60_000);

const SAMPLE = path.join(__dirname, 'sample-app');
let fake: FakeCli | undefined;
let saved: AppConfig[];
let cfg: Partial<AppConfig>;

function baseConfig(): AppConfig {
  return {
    model: 'ollama', claudeApiKey: null, openaiApiKey: null, ollamaPort: 11434, ollamaModel: 'llama3',
    cliCommand: fake?.command ?? null, cliModel: null, codexEnabled: true,
    warnBeforeExternalSend: true, defaultPorts: [3000], probeCommonPaths: false, ...cfg,
  };
}

async function runSession(commands: string[]): Promise<string> {
  const input = new PassThrough();
  const sink = new Writable({ write: (_c, _e, cb) => cb() });
  const logs: string[] = [];
  const spies = (['log', 'warn', 'error', 'info'] as const).map((m) =>
    jest.spyOn(console, m).mockImplementation((...args: unknown[]) => {
      logs.push(args.map((a) => String(a)).join(' '));
    }),
  );
  try {
    const shell = new InteractiveShell(SAMPLE, { input, output: sink });
    const done = shell.start();
    for (const c of commands) input.write(c + '\n');
    input.end();
    await done;
  } finally {
    spies.forEach((s) => s.mockRestore());
  }
  // eslint-disable-next-line no-control-regex
  return logs.join('\n').replace(/\x1B\[[0-9;]*[A-Za-z]/g, '');
}

beforeEach(() => {
  saved = [];
  cfg = {};
  (ConfigManager.load as jest.Mock).mockImplementation(async () => baseConfig());
  (ConfigManager.save as jest.Mock).mockImplementation(async (c: AppConfig) => {
    saved.push({ ...c });
  });
  (ConfigManager.configPath as jest.Mock).mockReturnValue('<mock>');
});
afterEach(() => {
  fake?.cleanup();
  fake = undefined;
});

const loggedIn = JSON.stringify({ loggedIn: true, authMethod: 'claude.ai' });
const loggedOut = JSON.stringify({ loggedIn: false });

describe('in-session AI setup with the CLI providers', () => {
  it('lists all providers, with the Codex one marked as new and not yet tried live', async () => {
    const out = await runSession(['setup', '6', 'exit']);
    for (const label of ['Claude (Anthropic)', 'OpenAI', 'Ollama', 'Claude CLI', 'Codex CLI']) expect(out).toContain(label);
    expect(out).toMatch(/Codex CLI.*not yet tried with a live account/);
    expect(saved).toHaveLength(0);
  });

  it('option 4 selects claude-cli when the CLI says it is logged in; only the status command runs', async () => {
    fake = makeFakeCli('claude', { status: { stdout: loggedIn } });
    const out = await runSession(['setup', '4', 'exit']);
    expect(saved.map((c) => c.model)).toEqual(['claude-cli']);
    expect(saved[0]!.claudeApiKey).toBeNull();
    expect(out).toMatch(/Logged in to Claude/);
    expect(fake.records().map((r) => r.kind)).toEqual(['status']);
  });

  it('option 4, not logged in, answer "y": runs the CLI login, then re-checks', async () => {
    fake = makeFakeCli('claude', { status: { stdout: loggedOut }, login: { stdout: '', thenStatus: { stdout: loggedIn } } });
    const out = await runSession(['setup', '4', 'y', 'exit']);
    expect(fake.records().map((r) => r.kind)).toEqual(['status', 'login', 'status']);
    expect(out).toMatch(/Logged in to Claude/);
  });

  it('option 4, not logged in, answer "n" or blank: no login is started', async () => {
    fake = makeFakeCli('claude', { status: { stdout: loggedOut } });
    await runSession(['setup', '4', 'n', 'exit']);
    await runSession(['setup', '4', '', 'exit']);
    expect(fake.records().map((r) => r.kind)).toEqual(['status', 'status']);
  });

  it('closed input never starts a login on its own', async () => {
    fake = makeFakeCli('claude', { status: { stdout: loggedOut } });
    await runSession(['setup', '4']);
    expect(fake.records().filter((r) => r.kind === 'login')).toEqual([]);
  });

  it('option 5 (Codex) with codexEnabled false: says it is switched off and never runs the codex CLI', async () => {
    cfg = { codexEnabled: false };
    fake = makeFakeCli('codex', { status: { exitCode: 0 } });
    const out = await runSession(['setup', '5', 'exit']);
    expect(out).toMatch(/switched off/);
    expect(out).toContain('codexEnabled');
    expect(fake.records()).toEqual([]);
  });

  it('option 5 (Codex) is enabled by default and checks the Codex login status', async () => {
    fake = makeFakeCli('codex', { status: { exitCode: 0 } });
    const out = await runSession(['setup', '5', 'exit']);
    expect(out).toMatch(/Logged in to Codex/);
    expect(fake.records().map((r) => r.kind)).toEqual(['status']);
  });

  it('a missing CLI is reported without offering a login', async () => {
    cfg = { cliCommand: path.join(fs.realpathSync.native(require('os').tmpdir()), 'no-such-dir', process.platform === 'win32' ? 'claude.exe' : 'claude') };
    const out = await runSession(['setup', '4', 'exit']);
    expect(out).toMatch(/no such file|not found/i);
  });
});

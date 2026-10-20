import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import inquirer from 'inquirer';
import { buildProgram } from '../src/cli/Commands';
import { Onboarding } from '../src/cli/Onboarding';
import { ConfigManager } from '../src/config/ConfigManager';
import { Orchestrator } from '../src/core/Orchestrator';
import type { AnalyzeOptions } from '../src/core/Orchestrator';
import type { AppConfig, ScanReport } from '../src/types';

const stack = { stack: 'express' as const, language: 'javascript' as const, evidence: [] };
const emptyReport: ScanReport = {
  target: '.',
  startedAt: '',
  finishedAt: '',
  version: '0',
  stack,
  graph: { root: '.', stack, entryPoints: [], modules: [], routes: [], fileCount: 0 },
  findings: [],
  score: 100,
  summary: { critical: 0, warning: 0, info: 0, total: 0 },
};

async function optionsFor(...args: string[]): Promise<AnalyzeOptions> {
  const spy = jest.spyOn(Orchestrator, 'analyze').mockResolvedValue(emptyReport);
  try {
    await buildProgram().parseAsync(['node', 'deployready', 'analyze', '.', ...args]);
    expect(spy).toHaveBeenCalledTimes(1);
    return spy.mock.calls[0]![1] as AnalyzeOptions;
  } finally {
    spy.mockRestore();
  }
}

afterEach(() => {
  jest.restoreAllMocks();
  process.exitCode = 0;
});

describe('analyze command: --probe-common-paths is a tri-state', () => {
  it('not on the command line -> undefined (so the config key can apply in interactive runs only)', async () => {
    expect((await optionsFor()).probeCommonPaths).toBeUndefined();
    expect((await optionsFor('--yes')).probeCommonPaths).toBeUndefined();
    expect((await optionsFor('--json')).probeCommonPaths).toBeUndefined();
  });

  it('--probe-common-paths -> true', async () => {
    expect((await optionsFor('--probe-common-paths')).probeCommonPaths).toBe(true);
    expect((await optionsFor('--yes', '--probe-common-paths')).probeCommonPaths).toBe(true);
  });

  it('--no-probe-common-paths -> false', async () => {
    expect((await optionsFor('--no-probe-common-paths')).probeCommonPaths).toBe(false);
  });

  it('the other defaults are untouched', async () => {
    const o = await optionsFor();
    expect(o).toMatchObject({ yes: false, noDynamic: false, noAi: false, aggressive: false });
  });
});

describe('config key', () => {
  function managerWithHome(file?: object): typeof ConfigManager {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-cfg-'));
    if (file) {
      fs.mkdirSync(path.join(home, '.deployready'));
      fs.writeFileSync(path.join(home, '.deployready', 'config.json'), JSON.stringify(file));
    }
    jest.spyOn(require('os') as typeof os, 'homedir').mockReturnValue(home);
    let mod!: typeof import('../src/config/ConfigManager');
    jest.isolateModules(() => {
      mod = require('../src/config/ConfigManager');
    });
    return mod.ConfigManager;
  }

  it('defaults to false when there is no config file', async () => {
    expect((await managerWithHome().load()).probeCommonPaths).toBe(false);
  });

  it('defaults to false when an existing config file does not mention it', async () => {
    expect((await managerWithHome({ model: 'ollama' }).load()).probeCommonPaths).toBe(false);
  });

  it('reads true from the file', async () => {
    expect((await managerWithHome({ probeCommonPaths: true }).load()).probeCommonPaths).toBe(true);
  });

  it('codexEnabled defaults to true and is switched off only by false', async () => {
    expect((await managerWithHome().load()).codexEnabled).toBe(true);
    expect((await managerWithHome({ model: 'ollama' }).load()).codexEnabled).toBe(true);
    expect((await managerWithHome({ codexEnabled: false }).load()).codexEnabled).toBe(false);
    expect((await managerWithHome({ codexEnabled: 'false' }).load()).codexEnabled).toBe(false);
  });

  it('docs/sample-config.json documents the key as false', () => {
    const sample = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'docs', 'sample-config.json'), 'utf8'));
    expect(sample.probeCommonPaths).toBe(false);
  });

  it('init / onboarding never writes true', async () => {
    const saved: AppConfig[] = [];
    jest.spyOn(inquirer, 'prompt').mockResolvedValue({ model: 'claude' } as never);
    jest.spyOn(ConfigManager, 'save').mockImplementation(async (c: AppConfig) => void saved.push(c));
    const oldKey = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = 'not-a-real-key';
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      await Onboarding.run();
    } finally {
      if (oldKey === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = oldKey;
    }
    expect(saved).toHaveLength(1);
    expect(saved[0]!.probeCommonPaths).toBe(false);
  });
});

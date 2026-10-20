/** First-run wizard with the CLI providers, against a FAKE CLI (verified with fakes only). */
import * as path from 'path';
import { ConfigManager } from '../src/config/ConfigManager';
import { logger } from '../src/utils/logger';
import { makeFakeCli } from './helpers/fakeCli';
import type { FakeCli } from './helpers/fakeCli';

jest.mock('../src/config/ConfigManager');
jest.mock('inquirer', () => ({ __esModule: true, default: { prompt: jest.fn() } }));
jest.setTimeout(60_000);

// eslint-disable-next-line @typescript-eslint/no-var-requires
const prompt = require('inquirer').default.prompt as jest.Mock;
import { Onboarding } from '../src/cli/Onboarding';

let fake: FakeCli | undefined;

beforeEach(() => {
  prompt.mockReset();
  (ConfigManager.save as jest.Mock).mockReset().mockResolvedValue(undefined);
  (ConfigManager.configPath as jest.Mock).mockReturnValue('<mock>');
  jest.spyOn(logger, 'info').mockImplementation(() => undefined);
  jest.spyOn(logger, 'success').mockImplementation(() => undefined);
});
afterEach(() => {
  fake?.cleanup();
  fake = undefined;
  jest.restoreAllMocks();
});

describe('Onboarding with the CLI providers', () => {
  it('codex-cli: saves the choice and checks only the codex login status', async () => {
    fake = makeFakeCli('codex', { status: { exitCode: 0 } });
    const prev = process.env.PATH;
    process.env.PATH = `${fake.dir}${path.delimiter}${prev ?? ''}`;
    try {
      prompt.mockResolvedValueOnce({ model: 'codex-cli' });
      const cfg = await Onboarding.run();
      expect(cfg.model).toBe('codex-cli');
      expect(cfg.codexEnabled).not.toBe(false);
      expect(cfg.claudeApiKey).toBeNull();
      expect(cfg.openaiApiKey).toBeNull();
      expect(prompt).toHaveBeenCalledTimes(1); // already logged in: no login offered
      expect(fake.records().map((r) => r.kind)).toEqual(['status']);
    } finally {
      process.env.PATH = prev;
    }
  });

  it('claude-cli with the CLI missing from PATH: warns, offers no login and stores no key', async () => {
    const warn = jest.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const prev = process.env.PATH;
    process.env.PATH = path.join(__dirname, 'sample-app');
    try {
      prompt.mockResolvedValueOnce({ model: 'claude-cli' });
      const cfg = await Onboarding.run();
      expect(cfg.model).toBe('claude-cli');
      expect(cfg.claudeApiKey).toBeNull();
      expect(warn).toHaveBeenCalledWith(expect.stringMatching(/not found/));
      expect(prompt).toHaveBeenCalledTimes(1);
    } finally {
      process.env.PATH = prev;
    }
  });
});

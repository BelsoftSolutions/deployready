import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// ---- fakes (jest hoists these; names must start with `mock`) -----------------
const mockSpinner: Record<string, jest.Mock> = {};
jest.mock('ora', () => ({
  __esModule: true,
  default: jest.fn(() => mockSpinner),
}));

const mockPrompt = jest.fn();
jest.mock('inquirer', () => ({ __esModule: true, default: { prompt: (...a: unknown[]) => mockPrompt(...a) } }));

const mockConfig = {
  load: jest.fn(),
  exists: jest.fn(),
};
jest.mock('../src/config/ConfigManager', () => ({ ConfigManager: mockConfig }));

const mockParse = jest.fn();
jest.mock('../src/parser/CodeParser', () => ({ CodeParser: { analyze: (...a: unknown[]) => mockParse(...a) } }));

const mockScan = jest.fn();
jest.mock('../src/analysis/VulnerabilityDetector', () => ({ VulnerabilityDetector: { scan: (...a: unknown[]) => mockScan(...a) } }));

const mockFind = jest.fn();
jest.mock('../src/dynamic/LocalhostDetector', () => ({ LocalhostDetector: { find: (...a: unknown[]) => mockFind(...a) } }));

const mockDynRun = jest.fn();
jest.mock('../src/dynamic/DynamicTester', () => ({
  ...jest.requireActual('../src/dynamic/DynamicTester'),
  DynamicTester: { run: (...a: unknown[]) => mockDynRun(...a) },
}));

const mockActiveRun = jest.fn();
jest.mock('../src/active/runner', () => ({ runActiveScan: (...a: unknown[]) => mockActiveRun(...a) }));

const mockRouter = {
  sendsExternally: true,
  configured: true,
  ready: { state: 'ready', message: 'ok' },
  analyze: jest.fn(),
  constructed: 0,
};
jest.mock('../src/ai/ModelRouter', () => ({
  ModelRouter: class {
    constructor() {
      mockRouter.constructed++;
    }
    get sendsExternally(): boolean {
      return mockRouter.sendsExternally;
    }
    isConfigured(): boolean {
      return mockRouter.configured;
    }
    checkReady(): Promise<{ state: string; message: string }> {
      return Promise.resolve(mockRouter.ready);
    }
    consentNotice(): string {
      return 'This will send a STRUCTURED findings report (no source code, secrets redacted) to the claude API.';
    }
    analyze(...a: unknown[]): Promise<unknown> {
      return mockRouter.analyze(...a);
    }
  },
}));

const mockOpen = jest.fn();
jest.mock('../src/utils/openBrowser', () => ({ openInBrowser: (...a: unknown[]) => mockOpen(...a) }));

const mockDisplay = jest.fn();
jest.mock('../src/ui/IssuePresenter', () => ({ IssuePresenter: { display: (...a: unknown[]) => mockDisplay(...a) } }));

const mockLog = { info: jest.fn(), success: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
jest.mock('../src/utils/logger', () => ({ logger: mockLog }));

import { Orchestrator } from '../src/core/Orchestrator';
import { makeFinding } from '../src/utils/finding';
import type { CodeGraph, Finding } from '../src/types';

// ---- helpers -----------------------------------------------------------------
const stack = { stack: 'express' as const, language: 'javascript' as const, evidence: [] };

function graph(over: Partial<CodeGraph> = {}): CodeGraph {
  return {
    root: '/x', stack, entryPoints: [], modules: [], fileCount: 2,
    routes: [{ method: 'GET', path: '/users/:id', file: 'app.js', guarded: false }],
    ...over,
  };
}

function fnd(over: Partial<Finding> = {}): Finding {
  return makeFinding({
    rule: 'eval-use', title: 'eval', severity: 'critical', category: 'security', source: 'static',
    description: 'd', recommendation: 'r', file: 'app.js', line: 1, ...over,
  });
}

/** Clearly fake, unsigned JWT: {"alg":"none"}.{"sub":"user-1"}. */
function fakeJwt(claims: object = { sub: 'user-1' }): string {
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${enc({ alg: 'none', typ: 'JWT' })}.${enc(claims)}.`;
}

let dir: string;
const base = { noAi: true as const, json: true as const };

beforeEach(() => {
  jest.clearAllMocks();
  mockPrompt.mockReset();
  mockConfig.load.mockReset().mockResolvedValue({
    model: 'claude', claudeApiKey: null, openaiApiKey: null, ollamaPort: 1, ollamaModel: 'm',
    warnBeforeExternalSend: true, defaultPorts: [3000],
  });
  mockConfig.exists.mockReset().mockResolvedValue(true);
  mockParse.mockReset().mockResolvedValue(graph());
  mockScan.mockReset().mockResolvedValue([fnd()]);
  mockFind.mockReset().mockResolvedValue(null);
  mockDynRun.mockReset();
  mockActiveRun.mockReset();
  mockRouter.sendsExternally = true;
  mockRouter.configured = true;
  mockRouter.ready = { state: 'ready', message: 'ok' };
  mockRouter.constructed = 0;
  mockRouter.analyze.mockReset();
  for (const k of ['start', 'succeed', 'fail', 'info', 'warn']) mockSpinner[k] = jest.fn(() => mockSpinner);
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-orch-flow-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('Orchestrator: input validation', () => {
  it('rejects a missing target before running any analysis', async () => {
    await expect(Orchestrator.analyze(path.join(dir, 'nope'), base)).rejects.toThrow(/Path not found/);
    expect(mockParse).not.toHaveBeenCalled();
    expect(mockScan).not.toHaveBeenCalled();
  });

  it('rejects a file target', async () => {
    const f = path.join(dir, 'a.txt');
    fs.writeFileSync(f, 'x');
    await expect(Orchestrator.analyze(f, base)).rejects.toThrow(/Not a directory/);
  });
});

describe('Orchestrator: report assembly', () => {
  it('builds the report from static results and resolves the target to an absolute path', async () => {
    const r = await Orchestrator.analyze(dir, { ...base, noDynamic: true });
    expect(r.target).toBe(path.resolve(dir));
    expect(r.findings).toHaveLength(1);
    expect(r.summary).toMatchObject({ critical: 1, total: 1 });
    expect(r.score).toBeLessThan(100);
    expect(r.dynamic).toBeUndefined();
    expect(r.aiSummary).toBeUndefined();
    expect(Date.parse(r.finishedAt)).toBeGreaterThanOrEqual(Date.parse(r.startedAt));
    expect(mockFind).not.toHaveBeenCalled();
  });

  it('handles a project with zero findings', async () => {
    mockScan.mockResolvedValue([]);
    const r = await Orchestrator.analyze(dir, { ...base, noDynamic: true });
    expect(r.findings).toEqual([]);
    expect(r.score).toBe(100);
    expect(r.summary.total).toBe(0);
  });

  it('mentions .gitignore-skipped paths in human mode only', async () => {
    mockParse.mockResolvedValue(graph({ gitignoreSkipped: 4 }));
    await Orchestrator.analyze(dir, { noAi: true, noDynamic: true });
    expect(mockLog.info).toHaveBeenCalledWith('Skipped 4 path(s) listed in .gitignore.');
    mockLog.info.mockClear();
    await Orchestrator.analyze(dir, { ...base, noDynamic: true });
    expect(mockLog.info).not.toHaveBeenCalled();
  });

  it('prints the terminal report unless json mode is on', async () => {
    await Orchestrator.analyze(dir, { noAi: true, noDynamic: true });
    expect(mockDisplay).toHaveBeenCalledTimes(1);
    mockDisplay.mockClear();
    await Orchestrator.analyze(dir, { ...base, noDynamic: true });
    expect(mockDisplay).not.toHaveBeenCalled();
  });
});

describe('Orchestrator: dynamic testing consent gates', () => {
  const app = { port: 3000, baseUrl: 'http://localhost:3000' };
  const dynResult = { baseUrl: app.baseUrl, reachable: true, endpoints: [], findings: [fnd({ rule: 'cors-wildcard', source: 'dynamic', file: undefined, endpoint: '/x', severity: 'warning' })] };

  it('skips quietly when no app is running', async () => {
    const r = await Orchestrator.analyze(dir, base);
    expect(r.dynamic).toBeUndefined();
    expect(mockDynRun).not.toHaveBeenCalled();
    expect(mockPrompt).not.toHaveBeenCalled();
    expect(mockSpinner.info).toHaveBeenCalled();
  });

  it('--yes runs non-aggressively without prompting and merges dynamic findings into the score', async () => {
    mockFind.mockResolvedValue(app);
    mockDynRun.mockResolvedValue(dynResult);
    const r = await Orchestrator.analyze(dir, { ...base, yes: true });
    expect(mockPrompt).not.toHaveBeenCalled();
    expect(mockDynRun).toHaveBeenCalledWith(app.baseUrl, expect.any(Array), { aggressive: false, projectPath: path.resolve(dir) });
    expect(mockFind).toHaveBeenCalledWith([3000]);
    expect(r.dynamic).toBe(dynResult);
    expect(r.findings.map((f) => f.rule).sort()).toEqual(['cors-wildcard', 'eval-use']);
  });

  it('--yes with --aggressive passes aggressive through', async () => {
    mockFind.mockResolvedValue(app);
    mockDynRun.mockResolvedValue(dynResult);
    await Orchestrator.analyze(dir, { ...base, yes: true, aggressive: true });
    expect(mockDynRun).toHaveBeenCalledWith(app.baseUrl, expect.any(Array), { aggressive: true, projectPath: path.resolve(dir) });
  });

  it('declining the first prompt sends no requests at all', async () => {
    mockFind.mockResolvedValue(app);
    mockPrompt.mockResolvedValueOnce({ ok: false });
    const r = await Orchestrator.analyze(dir, base);
    expect(mockPrompt).toHaveBeenCalledTimes(1);
    expect(mockDynRun).not.toHaveBeenCalled();
    expect(r.dynamic).toBeUndefined();
  });

  it('asks separately before aggressive tests and honours a "no"', async () => {
    mockFind.mockResolvedValue(app);
    mockPrompt.mockResolvedValueOnce({ ok: true }).mockResolvedValueOnce({ agg: false });
    mockDynRun.mockResolvedValue(dynResult);
    await Orchestrator.analyze(dir, base);
    expect(mockPrompt).toHaveBeenCalledTimes(2);
    expect(mockDynRun).toHaveBeenCalledWith(app.baseUrl, expect.any(Array), { aggressive: false, projectPath: path.resolve(dir) });
  });

  it('enables aggressive tests only after an explicit "yes"', async () => {
    mockFind.mockResolvedValue(app);
    mockPrompt.mockResolvedValueOnce({ ok: true }).mockResolvedValueOnce({ agg: true });
    mockDynRun.mockResolvedValue(dynResult);
    await Orchestrator.analyze(dir, base);
    expect(mockDynRun).toHaveBeenCalledWith(app.baseUrl, expect.any(Array), { aggressive: true, projectPath: path.resolve(dir) });
  });

  it('--aggressive on the CLI skips the second prompt', async () => {
    mockFind.mockResolvedValue(app);
    mockPrompt.mockResolvedValueOnce({ ok: true });
    mockDynRun.mockResolvedValue(dynResult);
    await Orchestrator.analyze(dir, { ...base, aggressive: true });
    expect(mockPrompt).toHaveBeenCalledTimes(1);
  });

  it('a failing live test degrades to static-only results instead of aborting the scan', async () => {
    mockFind.mockResolvedValue(app);
    mockDynRun.mockRejectedValue(new Error('probe exploded'));
    const r = await Orchestrator.analyze(dir, { ...base, yes: true });
    expect(r.dynamic).toBeUndefined();
    expect(r.findings.map((f) => f.rule)).toEqual(['eval-use']);
    expect(mockSpinner.fail).toHaveBeenCalledWith('Live testing failed: probe exploded');
  });
});

describe('Orchestrator: active (authenticated) scan gates', () => {
  const app = { port: 3000, baseUrl: 'http://localhost:3000' };
  const activeFinding = fnd({ rule: 'idor', source: 'dynamic', file: undefined, endpoint: '/users/user-1', severity: 'critical' });
  const opts = { ...base, noDynamic: true, active: true };

  it('does nothing without a token (the CLI shows token instructions)', async () => {
    const r = await Orchestrator.analyze(dir, opts);
    expect(mockFind).not.toHaveBeenCalled();
    expect(mockActiveRun).not.toHaveBeenCalled();
    expect(r.findings.map((f) => f.rule)).toEqual(['eval-use']);
  });

  it('is not run unless --active is set, even with a token', async () => {
    await Orchestrator.analyze(dir, { ...base, noDynamic: true, token: fakeJwt(), yes: true });
    expect(mockActiveRun).not.toHaveBeenCalled();
  });

  it('rejects a token that is not a JWT, with a warning and no network', async () => {
    await Orchestrator.analyze(dir, { ...opts, token: 'not-a-jwt', yes: true });
    expect(mockLog.warn).toHaveBeenCalledWith(expect.stringContaining('not a valid JWT'));
    expect(mockFind).not.toHaveBeenCalled();
    expect(mockActiveRun).not.toHaveBeenCalled();
  });

  it('skips when no app is running', async () => {
    await Orchestrator.analyze(dir, { ...opts, token: fakeJwt(), yes: true });
    expect(mockFind).toHaveBeenCalledWith([3000]);
    expect(mockActiveRun).not.toHaveBeenCalled();
  });

  it('declining the consent prompt (default: no) sends nothing', async () => {
    mockFind.mockResolvedValue(app);
    mockPrompt.mockResolvedValueOnce({ ok: false });
    await Orchestrator.analyze(dir, { ...opts, token: fakeJwt() });
    expect(mockPrompt.mock.calls[0][0][0].default).toBe(false);
    expect(mockActiveRun).not.toHaveBeenCalled();
  });

  it('skips when no GET route can be resolved from the token claims', async () => {
    mockFind.mockResolvedValue(app);
    mockParse.mockResolvedValue(graph({ routes: [{ method: 'POST', path: '/users/:id', file: 'a.js', guarded: false }, { method: 'GET', path: '/x/:unknown', file: 'a.js', guarded: false }] }));
    await Orchestrator.analyze(dir, { ...opts, token: fakeJwt(), yes: true });
    expect(mockActiveRun).not.toHaveBeenCalled();
    expect(mockLog.info).toHaveBeenCalledWith(expect.stringContaining('no discovered route can be requested'));
  });

  it('runs the active scan with both tokens and merges its findings', async () => {
    mockFind.mockResolvedValue(app);
    mockActiveRun.mockResolvedValue([activeFinding]);
    const tokenA = fakeJwt({ sub: 'user-1' });
    const tokenB = fakeJwt({ sub: 'user-2' });
    const r = await Orchestrator.analyze(dir, { ...opts, token: tokenA, tokenB, yes: true });
    expect(mockPrompt).not.toHaveBeenCalled();
    const [cfg, adapter] = mockActiveRun.mock.calls[0];
    expect(cfg.token).toBe(tokenA);
    expect(cfg.tokenB).toBe(tokenB);
    expect(cfg.requests).toEqual([{ method: 'GET', path: '/users/user-1', pathParams: [{ index: 2, name: 'id' }] }]);
    expect(typeof adapter).toBe('function');
    expect(r.findings.map((f) => f.rule).sort()).toEqual(['eval-use', 'idor']);
  });

  it('a failing active scan degrades to the other results', async () => {
    mockFind.mockResolvedValue(app);
    mockActiveRun.mockRejectedValue(new Error('adapter down'));
    const r = await Orchestrator.analyze(dir, { ...opts, token: fakeJwt(), yes: true });
    expect(mockSpinner.fail).toHaveBeenCalledWith('Active scan failed: adapter down');
    expect(r.findings.map((f) => f.rule)).toEqual(['eval-use']);
  });
});

describe('Orchestrator: AI step gates', () => {
  const aiFinding = (file?: string) =>
    makeFinding({ rule: 'ai-x', title: 'AI', severity: 'critical', category: 'security', source: 'ai', unverified: true, description: 'dd', recommendation: 'rr', file });
  const opts = { json: true, noDynamic: true };
  const savedEnv = { a: process.env.ANTHROPIC_API_KEY, o: process.env.OPENAI_API_KEY };

  beforeEach(() => {
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OPENAI_API_KEY;
    mockRouter.analyze.mockResolvedValue({ summary: 'AI says hi', findings: [aiFinding()] });
  });
  afterEach(() => {
    if (savedEnv.a !== undefined) process.env.ANTHROPIC_API_KEY = savedEnv.a;
    if (savedEnv.o !== undefined) process.env.OPENAI_API_KEY = savedEnv.o;
  });

  it('with no config file and no API-key env vars, AI is skipped and no router is built', async () => {
    mockConfig.exists.mockResolvedValue(false);
    const r = await Orchestrator.analyze(dir, opts);
    expect(mockRouter.constructed).toBe(0);
    expect(r.aiSummary).toBeUndefined();
    expect(mockLog.info).toHaveBeenCalledWith(expect.stringContaining('No AI model configured'));
  });

  it('an env API key alone is enough to attempt AI without a config file', async () => {
    mockConfig.exists.mockResolvedValue(false);
    process.env.ANTHROPIC_API_KEY = 'fake-test-key-not-real';
    await Orchestrator.analyze(dir, { ...opts, yes: true });
    expect(mockRouter.constructed).toBe(1);
  });

  it('skips with a warning when the selected model is missing its key', async () => {
    mockRouter.configured = false;
    const r = await Orchestrator.analyze(dir, opts);
    expect(mockLog.warn).toHaveBeenCalledWith(expect.stringContaining('not fully configured'));
    expect(mockRouter.analyze).not.toHaveBeenCalled();
    expect(r.aiSummary).toBeUndefined();
  });

  it.each(['disabled', 'not_logged_in', 'missing'])('skips AI without prompting or sending when the provider is %s', async (state) => {
    mockRouter.ready = { state, message: `provider is ${state}` };
    const r = await Orchestrator.analyze(dir, opts);
    expect(mockLog.warn).toHaveBeenCalledWith(expect.stringContaining(`provider is ${state}`));
    expect(mockPrompt).not.toHaveBeenCalled();
    expect(mockRouter.analyze).not.toHaveBeenCalled();
    expect(r.aiSummary).toBeUndefined();
  });

  it('asks before an external send and honours "no" (nothing is sent)', async () => {
    mockPrompt.mockResolvedValueOnce({ ok: false });
    const r = await Orchestrator.analyze(dir, opts);
    expect(mockPrompt).toHaveBeenCalledTimes(1);
    expect(mockRouter.analyze).not.toHaveBeenCalled();
    expect(r.aiSummary).toBeUndefined();
    expect(r.findings.some((f) => f.source === 'ai')).toBe(false);
  });

  it('proceeds after an explicit "yes" and shows the privacy warning first', async () => {
    mockPrompt.mockResolvedValueOnce({ ok: true });
    mockLog.warn.mockClear();
    const r = await Orchestrator.analyze(dir, opts);
    expect(mockLog.warn).toHaveBeenCalledWith(expect.stringContaining('STRUCTURED findings report'));
    expect(mockRouter.analyze).toHaveBeenCalledTimes(1);
    expect(r.aiSummary).toBe('AI says hi');
  });

  it('--yes bypasses the prompt', async () => {
    await Orchestrator.analyze(dir, { ...opts, yes: true });
    expect(mockPrompt).not.toHaveBeenCalled();
    expect(mockRouter.analyze).toHaveBeenCalledTimes(1);
  });

  it('does not prompt when the user disabled the warning in config', async () => {
    mockConfig.load.mockResolvedValue({ model: 'claude', warnBeforeExternalSend: false, defaultPorts: [] });
    await Orchestrator.analyze(dir, opts);
    expect(mockPrompt).not.toHaveBeenCalled();
    expect(mockRouter.analyze).toHaveBeenCalledTimes(1);
  });

  it('does not prompt for a local (non-external) model', async () => {
    mockRouter.sendsExternally = false;
    await Orchestrator.analyze(dir, opts);
    expect(mockPrompt).not.toHaveBeenCalled();
    expect(mockRouter.analyze).toHaveBeenCalledTimes(1);
  });

  it('a model failure keeps the local results and the original score', async () => {
    mockRouter.analyze.mockRejectedValue(new Error('Claude API request failed: rate limited (too many requests)'));
    const without = await Orchestrator.analyze(dir, { ...opts, noAi: true });
    const r = await Orchestrator.analyze(dir, { ...opts, yes: true });
    expect(mockSpinner.fail).toHaveBeenCalledWith('AI analysis failed: Claude API request failed: rate limited (too many requests)');
    expect(r.score).toBe(without.score);
    expect(r.findings).toEqual(without.findings);
    expect(r.aiSummary).toBeUndefined();
  });

  it('an empty model reply leaves aiSummary unset', async () => {
    mockRouter.analyze.mockResolvedValue({ summary: '', findings: [] });
    const r = await Orchestrator.analyze(dir, { ...opts, yes: true });
    expect(r.aiSummary).toBeUndefined();
    expect(r.findings.map((f) => f.rule)).toEqual(['eval-use']);
  });

  it('uses only the dropped-findings note as the summary when the model gave none', async () => {
    mockRouter.analyze.mockResolvedValue({ summary: '', findings: [aiFinding('ghost.js')] });
    const r = await Orchestrator.analyze(dir, { ...opts, yes: true });
    expect(r.aiSummary).toBe('1 AI finding(s) dropped: referenced file not found');
    expect(mockLog.warn).toHaveBeenCalledWith('1 AI finding(s) dropped: referenced file not found');
    expect(r.findings.some((f) => f.source === 'ai')).toBe(false);
  });

  it('keeps an AI finding that points at a real file, demoted and unscored', async () => {
    fs.writeFileSync(path.join(dir, 'app.js'), 'x');
    mockRouter.analyze.mockResolvedValue({ summary: 'S', findings: [aiFinding('app.js')] });
    const without = await Orchestrator.analyze(dir, { ...opts, noAi: true });
    const r = await Orchestrator.analyze(dir, { ...opts, yes: true });
    const ai = r.findings.find((f) => f.source === 'ai');
    expect(ai).toMatchObject({ severity: 'info', unverified: true, file: 'app.js' });
    expect(r.score).toBe(without.score);
    expect(r.summary.unverified).toBe(1);
  });
});

describe('Orchestrator: export', () => {
  const opts = { ...base, noDynamic: true };

  it('writes nothing by default', async () => {
    await Orchestrator.analyze(dir, opts);
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it('--export writes the markdown report into the project root', async () => {
    const r = await Orchestrator.analyze(dir, { ...opts, export: true });
    const file = path.join(path.resolve(dir), 'deployready-report.md');
    expect(fs.readFileSync(file, 'utf8')).toContain(`**Score:** ${r.score}/100`);
    expect(fs.existsSync(path.join(dir, 'deployready-report.html'))).toBe(false);
    expect(mockLog.success).toHaveBeenCalledWith(`Markdown report saved to ${file}`);
  });

  it('--html writes the dashboard and does not open a browser', async () => {
    await Orchestrator.analyze(dir, { ...opts, html: true });
    expect(fs.readFileSync(path.join(dir, 'deployready-report.html'), 'utf8')).toMatch(/^<!DOCTYPE html>/);
    expect(mockOpen).not.toHaveBeenCalled();
  });

  it('--open implies the HTML report; opens it in human mode only', async () => {
    await Orchestrator.analyze(dir, { noAi: true, noDynamic: true, open: true });
    const file = path.join(path.resolve(dir), 'deployready-report.html');
    expect(fs.existsSync(file)).toBe(true);
    expect(mockOpen).toHaveBeenCalledWith(file);
  });

  it('--open in json/CI mode writes the report but never launches a browser', async () => {
    await Orchestrator.analyze(dir, { ...opts, open: true });
    expect(fs.existsSync(path.join(dir, 'deployready-report.html'))).toBe(true);
    expect(mockOpen).not.toHaveBeenCalled();
  });

  it('propagates a write failure instead of silently dropping the report', async () => {
    const ro = path.join(dir, 'deployready-report.md');
    fs.mkdirSync(ro); // a directory where the file should go -> EISDIR
    await expect(Orchestrator.analyze(dir, { ...opts, export: true })).rejects.toThrow();
  });
});

import type { IncomingMessage, ServerResponse } from 'http';
import { setVerbose } from '../src/utils/logger';
import { PROBE_PATHS } from '../src/dynamic/commonPaths/signatures';
import { CONTROL_PATH, expressProject, send, withApp, writeProject } from './helpers/dummyApp';
import type { DummyApp, Handler } from './helpers/dummyApp';

let mockPorts: number[] = [];
let mockConfigProbe: boolean | undefined;
const mockPrompt = jest.fn();

jest.mock('../src/config/ConfigManager', () => ({
  ConfigManager: {
    exists: async () => true,
    load: async () => ({ defaultPorts: mockPorts, model: 'none', probeCommonPaths: mockConfigProbe }),
  },
}));
jest.mock('inquirer', () => ({ prompt: (...a: unknown[]) => mockPrompt(...a) }));

import { Orchestrator } from '../src/core/Orchestrator';
import type { AnalyzeOptions } from '../src/core/Orchestrator';

jest.setTimeout(30000);

const handlerLine = '(req, res) => res.send("ok")';
const ROUTES = ['/ping', '/home'];
const PROBE_PATH_LIST = PROBE_PATHS.map((p) => p.path);
const FAKE_SECRET = ['zz', 'Q9', 'notarealvalue', '42'].join('-');
const LEAKS: Record<string, string> = {
  '/.env': `APP_SECRET=${FAKE_SECRET}\nPORT=3000\n`,
  '/.git/config': '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = ssh://example.invalid/r.git\n',
  '/phpinfo.php': '<html><head><title>phpinfo()</title></head><body>PHP Version 8.2</body></html>',
  '/admin': '<html><head><title>Admin dashboard</title></head><body><h1>Admin</h1></body></html>',
};

/** Open on `open`, leaks content on every "guessable" path, 404 elsewhere. */
function leakyApp(open: string[]): Handler {
  return (req: IncomingMessage, res: ServerResponse) => {
    const p = (req.url ?? '/').split('?')[0] ?? '/';
    if (open.includes(p)) return send(res, 200, `<h1>page ${p}</h1>`);
    const leak = LEAKS[p];
    if (leak) return send(res, 200, leak, p.endsWith('.php') || p === '/admin' ? 'text/html' : 'text/plain');
    send(res, 404, 'not found', 'text/plain');
  };
}

const project = () => expressProject(ROUTES.map((r) => `app.get("${r}", ${handlerLine});`));

const stdout: string[] = [];
const stderr: string[] = [];
const prompts: Array<{ message: string; default: unknown }> = [];
let probeAnswer = false;
const savedCi = process.env.CI;

beforeEach(() => {
  mockPrompt.mockReset();
  prompts.length = 0;
  stdout.length = 0;
  stderr.length = 0;
  probeAnswer = false;
  mockPorts = [];
  mockConfigProbe = undefined;
  delete process.env.CI;
  mockPrompt.mockImplementation(async ([q]: Array<{ name: string; message: string; default?: unknown }>) => {
    prompts.push({ message: q.message, default: q.default });
    if (/guessed-path/.test(q.message)) return { ok: probeAnswer };
    if (q.name === 'agg') return { agg: false };
    return { ok: true };
  });
  jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void stdout.push(a.join(' ')));
  jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => void stderr.push(a.join(' ')));
});

afterEach(() => {
  jest.restoreAllMocks();
  setVerbose(false);
  if (savedCi === undefined) delete process.env.CI;
  else process.env.CI = savedCi;
});

const probePrompts = () => prompts.filter((p) => /guessed-path/.test(p.message));
const probeRequests = (app: DummyApp) => app.paths().filter((p) => PROBE_PATH_LIST.includes(p) || CONTROL_PATH.test(p));
const run = (dir: string, opts: AnalyzeOptions) => Orchestrator.analyze(dir, { noAi: true, commonPathDelayMs: 0, ...opts });

function expectDefaultRequestsOnly(app: DummyApp): void {
  const paths = app.paths();
  expect(paths.length).toBeGreaterThan(0);
  expect(paths.filter((p) => !CONTROL_PATH.test(p)).every((p) => ROUTES.includes(p))).toBe(true);
  expect(paths.filter((p) => CONTROL_PATH.test(p)).length).toBeLessThanOrEqual(1);
  for (const guessed of PROBE_PATH_LIST) expect(paths).not.toContain(guessed);
}

describe('default is unchanged: without the opt-in no probe path is ever requested', () => {
  const NEVER_ON: Array<[string, AnalyzeOptions, { ci?: boolean; config?: boolean }]> = [
    ['--yes', { yes: true }, {}],
    ['--json', { json: true, yes: true }, {}],
    ['--yes with env CI=1', { yes: true }, { ci: true }],
    ['env CI=1 alone', {}, { ci: true }],
    ['the config key set to true, --yes', { yes: true }, { config: true }],
    ['the config key set to true, --json', { json: true, yes: true }, { config: true }],
    ['the config key set to true, env CI=1', {}, { ci: true, config: true }],
    ['--no-probe-common-paths with the config key true (interactive)', { probeCommonPaths: false }, { config: true }],
    ['--no-probe-common-paths with --yes', { yes: true, probeCommonPaths: false }, {}],
    ['interactive, config key false', {}, { config: false }],
    ['interactive, config key absent', {}, {}],
  ];

  for (const [name, opts, env] of NEVER_ON) {
    it(`${name}: only discovered routes (plus at most the lazy control) are requested`, async () => {
      if (env.ci) process.env.CI = '1';
      mockConfigProbe = env.config;
      await withApp(leakyApp(ROUTES), async (app) => {
        mockPorts = [app.port];
        const r = await run(project(), opts);
        expectDefaultRequestsOnly(app);
        expect(r.dynamic?.commonPaths).toBeUndefined();
        expect(r.findings.filter((f) => f.rule === 'common-path-exposure')).toEqual([]);
        expect(probePrompts()).toEqual([]);
        expect(stdout.join('\n')).not.toMatch(/Common-path probe/);
      });
    });
  }

  it('--yes, --json and CI runs never print the opt-in hint', async () => {
    await withApp(leakyApp(ROUTES), async (app) => {
      mockPorts = [app.port];
      await run(project(), { yes: true });
      await run(project(), { yes: true, json: true });
      process.env.CI = '1';
      await run(project(), {});
      expect([...stdout, ...stderr].join('\n')).not.toMatch(/--probe-common-paths/);
    });
  });

  it('an interactive run with the probe off prints the one-line hint, and nothing is guessed', async () => {
    await withApp(leakyApp(ROUTES), async (app) => {
      mockPorts = [app.port];
      await run(project(), {});
      const hints = stdout.filter((l) => /--probe-common-paths/.test(l));
      expect(hints).toHaveLength(1);
      expect(hints[0]).toMatch(/off/);
      expectDefaultRequestsOnly(app);
    });
  });

  it('--no-dynamic means no request at all, even with the flag and --yes', async () => {
    await withApp(leakyApp(ROUTES), async (app) => {
      mockPorts = [app.port];
      mockConfigProbe = true;
      const r = await run(project(), { yes: true, noDynamic: true, probeCommonPaths: true });
      expect(app.requests).toEqual([]);
      expect(r.dynamic).toBeUndefined();
      expect(probePrompts()).toEqual([]);
    });
  });

  it('--no-dynamic interactive with config true: still nothing, no probe prompt, no hint', async () => {
    await withApp(leakyApp(ROUTES), async (app) => {
      mockPorts = [app.port];
      mockConfigProbe = true;
      await run(project(), { noDynamic: true });
      expect(app.requests).toEqual([]);
      expect(prompts).toEqual([]);
      expect(stdout.join('\n')).not.toMatch(/--probe-common-paths/);
    });
  });
});

describe('with the opt-in', () => {
  it('interactive, flag given, confirm answered No (default is No): zero probe requests', async () => {
    probeAnswer = false;
    await withApp(leakyApp(ROUTES), async (app) => {
      mockPorts = [app.port];
      const r = await run(project(), { probeCommonPaths: true });
      expect(probePrompts()).toHaveLength(1);
      expect(probePrompts()[0]?.default).toBe(false);
      expectDefaultRequestsOnly(app);
      expect(r.dynamic?.commonPaths).toBeUndefined();
      expect(r.findings.filter((f) => f.rule === 'common-path-exposure')).toEqual([]);
      expect(stdout.join('\n')).toMatch(/Skipping the common-path probe/);
    });
  });

  it('interactive, config key true, no flag: prompts, default No, and No sends nothing', async () => {
    mockConfigProbe = true;
    probeAnswer = false;
    await withApp(leakyApp(ROUTES), async (app) => {
      mockPorts = [app.port];
      await run(project(), {});
      expect(probePrompts()).toHaveLength(1);
      expect(probePrompts()[0]?.default).toBe(false);
      expectDefaultRequestsOnly(app);
    });
  });

  it('interactive, config key true, confirm answered Yes: the probe runs', async () => {
    mockConfigProbe = true;
    probeAnswer = true;
    await withApp(leakyApp(ROUTES), async (app) => {
      mockPorts = [app.port];
      const r = await run(project(), {});
      expect(probePrompts()).toHaveLength(1);
      expect(r.dynamic?.commonPaths?.probed.map((p) => p.path)).toEqual(PROBE_PATH_LIST);
      expect(probeRequests(app).length).toBeGreaterThanOrEqual(PROBE_PATH_LIST.length + 1);
      expect(stdout.join('\n')).not.toMatch(/--probe-common-paths/);
    });
  });

  it('the flag in --yes: the exact list and the cap are printed first, then probed, without a prompt', async () => {
    let listPrintedBeforeFirstProbeRequest: boolean | undefined;
    const inner = leakyApp(ROUTES);
    const handler: Handler = (req, res) => {
      const p = (req.url ?? '/').split('?')[0] ?? '/';
      if (listPrintedBeforeFirstProbeRequest === undefined && (PROBE_PATH_LIST.includes(p) || CONTROL_PATH.test(p))) {
        const printed = stdout.join('\n');
        listPrintedBeforeFirstProbeRequest =
          PROBE_PATH_LIST.every((x) => printed.includes(`GET ${x}`)) && /at most 20 GET requests/.test(printed);
      }
      inner(req, res);
    };
    await withApp(handler, async (app) => {
      mockPorts = [app.port];
      const r = await run(project(), { yes: true, probeCommonPaths: true });

      expect(probePrompts()).toEqual([]);
      expect(listPrintedBeforeFirstProbeRequest).toBe(true);
      expect(stdout.join('\n')).toMatch(new RegExp(`Target: http://[^ ]+:${app.port}`));

      const cp = r.dynamic?.commonPaths;
      expect(cp?.cap).toBe(20);
      expect(cp?.target).toMatch(new RegExp(`^http://[^/]+:${app.port}$`));
      expect(cp?.probed.map((p) => p.path)).toEqual(PROBE_PATH_LIST);
      const sent = app.paths();
      for (const p of PROBE_PATH_LIST) expect(sent.filter((x) => x === p)).toHaveLength(1);
      expect(sent.filter((p) => CONTROL_PATH.test(p)).length).toBeGreaterThanOrEqual(1);

      const guessed = r.findings.filter((f) => f.rule === 'common-path-exposure');
      expect(guessed.map((f) => f.endpoint).sort()).toEqual(['/.env', '/.git/config', '/admin', '/phpinfo.php'].sort());
      expect(guessed.every((f) => f.guessed === true && /guessed path, lower confidence/.test(f.title))).toBe(true);
      expect(r.findings.find((f) => f.endpoint === '/.git/config')?.severity).toBe('critical');
      expect(JSON.stringify(r)).not.toContain(FAKE_SECRET);
      expect([...stdout, ...stderr].join('\n')).not.toContain(FAKE_SECRET);
    });
  });

  it('--json with the flag: the printed list never reaches stdout', async () => {
    await withApp(leakyApp(ROUTES), async (app) => {
      mockPorts = [app.port];
      const r = await run(project(), { yes: true, json: true, probeCommonPaths: true });
      expect(r.dynamic?.commonPaths?.probed).toHaveLength(PROBE_PATH_LIST.length);
      expect(stdout.join('\n')).not.toMatch(/\/\.env|Common-path probe/);
      expect(stderr.join('\n')).toMatch(/GET \/\.env/);
    });
  });

  it('paths the normal scan requested are excluded: no duplicate request, no duplicate finding', async () => {
    const dir = expressProject([`app.get("/admin", ${handlerLine});`, `app.get("/ping", ${handlerLine});`]);
    const baseline = await withApp(leakyApp(['/ping']), async (app) => {
      mockPorts = [app.port];
      await run(dir, { yes: true });
      return app.paths().filter((p) => p === '/admin').length;
    });
    expect(baseline).toBeGreaterThan(0);

    await withApp(leakyApp(['/ping']), async (app) => {
      mockPorts = [app.port];
      const r = await run(dir, { yes: true, probeCommonPaths: true });
      expect(app.paths().filter((p) => p === '/admin').length).toBe(baseline);
      expect(r.dynamic?.commonPaths?.covered).toEqual(['/admin']);
      expect(r.dynamic?.commonPaths?.probed.map((p) => p.path)).not.toContain('/admin');
      expect(r.findings.filter((f) => f.rule === 'common-path-exposure' && f.endpoint === '/admin')).toEqual([]);
      expect(stdout.join('\n')).not.toMatch(/GET \/admin\b/);
    });
  });

  it('zero discovered routes: the probe still runs and the dynamic-skipped note stays', async () => {
    const dir = writeProject({ 'index.html': '<h1>hi</h1>' });
    await withApp(leakyApp(['/']), async (app) => {
      mockPorts = [app.port];
      const r = await run(dir, { yes: true, probeCommonPaths: true });
      expect(r.graph.routes).toEqual([]);
      expect(r.findings.some((f) => f.note === true && /No routes discovered; dynamic checks skipped/.test(f.title))).toBe(true);
      expect(r.dynamic?.commonPaths?.probed.map((p) => p.path)).toEqual(PROBE_PATH_LIST);
      expect(app.paths().filter((p) => !CONTROL_PATH.test(p)).sort()).toEqual([...PROBE_PATH_LIST].sort());
      expect(r.findings.some((f) => f.rule === 'common-path-exposure' && f.endpoint === '/.git/config')).toBe(true);
    });
  });

  it('zero discovered routes, interactive, confirm No: nothing is requested', async () => {
    const dir = writeProject({ 'index.html': '<h1>hi</h1>' });
    mockConfigProbe = true;
    probeAnswer = false;
    await withApp(leakyApp(['/']), async (app) => {
      mockPorts = [app.port];
      const r = await run(dir, {});
      expect(probePrompts()).toHaveLength(1);
      expect(app.requests).toEqual([]);
      expect(r.findings.some((f) => f.note === true && /No routes discovered/.test(f.title))).toBe(true);
      expect(r.dynamic?.commonPaths).toBeUndefined();
    });
  });

  it('zero discovered routes without the opt-in: still nothing is requested', async () => {
    const dir = writeProject({ 'index.html': '<h1>hi</h1>' });
    await withApp(leakyApp(['/']), async (app) => {
      mockPorts = [app.port];
      mockConfigProbe = true;
      await run(dir, { yes: true });
      expect(app.requests).toEqual([]);
    });
  });

  it('no local server found: the probe is skipped quietly', async () => {
    mockPorts = [];
    const r = await run(project(), { yes: true, probeCommonPaths: true });
    expect(r.dynamic).toBeUndefined();
  });
});

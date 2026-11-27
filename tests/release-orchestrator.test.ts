/**
 * Audit reproductions + end-to-end release state:
 *  (a) an unverified AI critical used to coexist with score 100/100 and a passing --fail-on critical
 *      gate with nothing else in the report saying so;
 *  (b) a scanner step that threw (dynamic / active / supabase / firebase / AI) used to leave the
 *      report identical to "that check ran and found nothing".
 * The score and --fail-on keep their old behaviour; the release state and coverage now tell the truth.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const mockState = {
  aiText: '',
  aiThrows: false,
  dynThrows: false,
  activeThrows: false,
  supabaseThrows: false,
  firebaseThrows: false,
  server: true,
  releasePolicy: undefined as unknown,
};

jest.mock('../src/config/ConfigManager', () => ({
  ConfigManager: {
    exists: async () => true,
    load: async () => ({
      model: 'ollama',
      ollamaPort: 11434,
      ollamaModel: 'x',
      warnBeforeExternalSend: false,
      defaultPorts: [3000],
      releasePolicy: mockState.releasePolicy,
    }),
  },
}));
jest.mock('../src/ai/ModelRouter', () => {
  const { parseAiResponse } = jest.requireActual('../src/ai/parseAiResponse');
  return {
    ModelRouter: class {
      sendsExternally = false;
      isConfigured(): boolean {
        return true;
      }
      async checkReady(): Promise<unknown> {
        return { state: 'ready', provider: 'x', message: 'ok' };
      }
      consentNotice(): string {
        return '';
      }
      async analyze(): Promise<unknown> {
        if (mockState.aiThrows) throw new Error('provider down');
        return parseAiResponse(mockState.aiText);
      }
    },
  };
});
jest.mock('../src/dynamic/LocalhostDetector', () => ({
  LocalhostDetector: { find: async () => (mockState.server ? { port: 3000, baseUrl: 'http://localhost:3000' } : null) },
}));
jest.mock('../src/dynamic/DynamicTester', () => ({
  ...jest.requireActual('../src/dynamic/DynamicTester'),
  DynamicTester: {
    run: async (baseUrl: string) => {
      if (mockState.dynThrows) throw new Error('socket hang up');
      return { baseUrl, reachable: true, endpoints: [], probed: [{ method: 'GET', path: '/health', why: ['route'] }], skipped: [], findings: [] };
    },
  },
}));
jest.mock('../src/active/runner', () => ({
  ...jest.requireActual('../src/active/runner'),
  runActiveScan: async () => {
    if (mockState.activeThrows) throw new Error('active boom');
    return [];
  },
}));
jest.mock('../src/supabase/static', () => {
  const actual = jest.requireActual('../src/supabase/static');
  return {
    ...actual,
    scanSupabaseStatic: async (...a: unknown[]) => {
      if (mockState.supabaseThrows) throw new Error('supabase parser crashed');
      return actual.scanSupabaseStatic(...a);
    },
  };
});
jest.mock('../src/firebase/static', () => {
  const actual = jest.requireActual('../src/firebase/static');
  return {
    ...actual,
    scanFirebaseStatic: async (...a: unknown[]) => {
      if (mockState.firebaseThrows) throw new Error('firebase parser crashed');
      return actual.scanFirebaseStatic(...a);
    },
  };
});

import { Orchestrator } from '../src/core/Orchestrator';
import { shouldFail } from '../src/core/CiGate';
import { buildProgram } from '../src/cli/Commands';
import { SCORE_DISCLAIMER } from '../src/core/releaseState';
import { dummyJwt } from './helpers/dummyApp';
import type { CoverageArea, ScanReport } from '../src/types';

function cleanProject(extra: Record<string, string> = {}): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-release-'));
  fs.writeFileSync(
    path.join(dir, 'app.js'),
    "const express = require('express');\nconst app = express();\napp.get('/health', (req, res) => res.send('ok'));\n",
  );
  for (const [f, body] of Object.entries(extra)) {
    fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    fs.writeFileSync(path.join(dir, f), body);
  }
  return dir;
}

const aiCritical = JSON.stringify({
  summary: 's',
  findings: [{ rule: 'ai-sqli', title: 'SQL injection', severity: 'critical', category: 'security', description: 'd', recommendation: 'r', file: 'app.js' }],
});

const areaOf = (r: ScanReport, kind: string): CoverageArea | undefined => r.coverage?.find((a) => a.kind === kind);

beforeEach(() => {
  Object.assign(mockState, {
    aiText: JSON.stringify({ summary: '', findings: [] }),
    aiThrows: false,
    dynThrows: false,
    activeThrows: false,
    supabaseThrows: false,
    firebaseThrows: false,
    server: true,
    releasePolicy: undefined,
  });
});

afterEach(() => {
  jest.restoreAllMocks();
  process.exitCode = 0;
});

describe('reproduction (a): unverified AI critical vs. score 100', () => {
  it('score stays 100 and --fail-on critical still passes (backward compatible), but the release is review-required, never ready', async () => {
    mockState.aiText = aiCritical;
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true });
    // The audit finding, still true for the score/--fail-on by design:
    expect(r.score).toBe(100);
    expect(r.summary.critical).toBe(0);
    expect(r.summary.unverified).toBe(1);
    expect(shouldFail(r.summary, 'critical')).toBe(false);
    // ...but it is no longer hidden:
    expect(r.release?.state).toBe('review-required');
    expect(r.release?.confidence).toMatchObject({ confirmed: 0, unverified: 1, ai: 1, unconfirmedBlocking: 1 });
    expect(r.release?.line).toMatch(/^Release: REVIEW REQUIRED — 1 unverified\/AI critical to review/);
    expect(r.findings.find((f) => f.source === 'ai')?.suggestedSeverity).toBe('critical');
  });

  it('treatUnverifiedCriticalAs: "not-ready" from config makes it block', async () => {
    mockState.aiText = aiCritical;
    mockState.releasePolicy = { treatUnverifiedCriticalAs: 'not-ready' };
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true });
    expect(r.release?.state).toBe('not-ready');
    expect(r.release?.policy.treatUnverifiedCriticalAs).toBe('not-ready');
  });

  it('an invalid treatUnverifiedCriticalAs ("ready") is refused with a warning; the default applies', async () => {
    mockState.aiText = aiCritical;
    mockState.releasePolicy = { treatUnverifiedCriticalAs: 'ready' };
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true });
    expect(r.release?.state).toBe('review-required');
    expect(r.release?.policyWarnings?.[0]).toMatch(/never hidden/);
  });
});

describe('reproduction (b): a scanner step that errors is never a pass', () => {
  it('dynamic step throws: same score as --no-dynamic, but coverage says failed and the release is insufficient-evidence', async () => {
    mockState.dynThrows = true;
    const dir = cleanProject();
    const r = await Orchestrator.analyze(dir, { yes: true, json: true, noAi: true });
    const off = await Orchestrator.analyze(dir, { yes: true, json: true, noAi: true, noDynamic: true });
    expect(r.score).toBe(off.score);
    expect(r.dynamic).toBeUndefined();
    expect(areaOf(r, 'dynamic')).toMatchObject({ state: 'failed', requested: true, mandatory: true });
    expect(areaOf(r, 'dynamic')?.reason).toContain('socket hang up');
    expect(r.release?.state).toBe('insufficient-evidence');
    expect(r.release?.line).toContain('live check failed (scanner error is not a pass)');
    // Disabled on purpose is not the same thing: untested, not mandatory, ready under limited coverage.
    expect(areaOf(off, 'dynamic')).toMatchObject({ state: 'untested', mandatory: false });
    expect(off.release?.state).toBe('ready');
    expect(off.release?.limitedCoverage).toBe(true);
    expect(off.release?.line).toMatch(/^Release: READY under limited coverage — no confirmed findings · Coverage: static \(JS\/TS\) ✓ · secrets ✓ · dependencies – untested · live – untested/);
  });

  it('dynamic step that ran gives a passed live area and full (not limited) coverage', async () => {
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true, noAi: true });
    expect(areaOf(r, 'dynamic')?.state).toBe('passed');
    expect(r.release?.state).toBe('ready');
    expect(r.release?.limitedCoverage).toBe(false);
  });

  it('no local server: dynamic untested (not failed), release not blocked', async () => {
    mockState.server = false;
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true, noAi: true });
    expect(areaOf(r, 'dynamic')).toMatchObject({ state: 'untested' });
    expect(r.release?.state).toBe('ready');
  });

  it('active step throws: active area failed, insufficient-evidence', async () => {
    mockState.activeThrows = true;
    const token = dummyJwt({ sub: 'u1' });
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true, noAi: true, active: true, token });
    expect(areaOf(r, 'active')).toMatchObject({ state: 'failed', requested: true });
    expect(r.release?.state).toBe('insufficient-evidence');
  });

  it('--active asked for without a token: active requested but untested, insufficient-evidence', async () => {
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true, noAi: true, noDynamic: true, activeRequested: true });
    expect(areaOf(r, 'active')).toMatchObject({ state: 'untested', requested: true, mandatory: true });
    expect(r.release?.state).toBe('insufficient-evidence');
  });

  it('active scan that ran is passed', async () => {
    const token = dummyJwt({ sub: 'u1' });
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true, noAi: true, active: true, token });
    expect(areaOf(r, 'active')?.state).toBe('passed');
  });

  it('supabase step throws: static area failed -> review-required; with --supabase the live area is failed -> insufficient-evidence', async () => {
    mockState.supabaseThrows = true;
    const dir = cleanProject();
    const r = await Orchestrator.analyze(dir, { yes: true, json: true, noAi: true, noDynamic: true });
    expect(areaOf(r, 'supabase-static')?.state).toBe('failed');
    expect(r.release?.state).toBe('review-required');
    const live = await Orchestrator.analyze(dir, { yes: true, json: true, noAi: true, noDynamic: true, supabase: { live: true } });
    expect(areaOf(live, 'supabase-live')).toMatchObject({ state: 'failed', requested: true });
    expect(live.release?.state).toBe('insufficient-evidence');
  });

  it('--supabase without a project URL: live requested but untested -> insufficient-evidence; no project = not-applicable', async () => {
    const dir = cleanProject();
    const plain = await Orchestrator.analyze(dir, { yes: true, json: true, noAi: true, noDynamic: true });
    expect(areaOf(plain, 'supabase-static')?.state).toBe('not-applicable');
    expect(areaOf(plain, 'supabase-live')?.state).toBe('not-applicable');
    const prev = process.env.SUPABASE_URL;
    delete process.env.SUPABASE_URL;
    try {
      const r = await Orchestrator.analyze(dir, { yes: true, json: true, noAi: true, noDynamic: true, supabase: { live: true } });
      expect(areaOf(r, 'supabase-live')).toMatchObject({ state: 'untested', requested: true });
      expect(areaOf(r, 'supabase-live')?.reason).toMatch(/no project URL/);
      expect(r.release?.state).toBe('insufficient-evidence');
    } finally {
      if (prev !== undefined) process.env.SUPABASE_URL = prev;
    }
  });

  it('firebase step throws: firebase area failed -> review-required', async () => {
    mockState.firebaseThrows = true;
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true, noAi: true, noDynamic: true });
    expect(areaOf(r, 'firebase')?.state).toBe('failed');
    expect(r.release?.state).toBe('review-required');
  });

  it('AI step throws: ai area failed -> review-required (optional area, still never "ready")', async () => {
    mockState.aiThrows = true;
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true, noDynamic: true });
    expect(areaOf(r, 'ai')).toMatchObject({ state: 'failed' });
    expect(r.release?.state).toBe('review-required');
  });

  it('requireAreas from config: a required area that did not run is insufficient-evidence', async () => {
    mockState.releasePolicy = { requireAreas: ['static', 'secrets', 'dynamic'] };
    const r = await Orchestrator.analyze(cleanProject(), { yes: true, json: true, noAi: true, noDynamic: true });
    expect(areaOf(r, 'dynamic')).toMatchObject({ state: 'untested', mandatory: true });
    expect(r.release?.state).toBe('insufficient-evidence');
  });

  it('a project with no supported source files is not "ready": static is untested', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-release-empty-'));
    fs.writeFileSync(path.join(dir, 'main.go'), 'package main\n');
    const r = await Orchestrator.analyze(dir, { yes: true, json: true, noAi: true, noDynamic: true });
    expect(r.score).toBe(100);
    expect(areaOf(r, 'static')?.state).toBe('untested');
    expect(r.release?.state).toBe('insufficient-evidence');
  });
});

describe('analyze CLI: --fail-on-release-state and exit codes', () => {
  async function run(dir: string, ...args: string[]): Promise<{ json: any; code: number }> {
    const chunks: string[] = [];
    jest.spyOn(process.stdout, 'write').mockImplementation(((s: string) => (chunks.push(String(s)), true)) as never);
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
    process.exitCode = 0;
    await buildProgram().parseAsync(['node', 'deployready', 'analyze', dir, '--json', ...args]);
    let json: any;
    try {
      json = JSON.parse(chunks.join(''));
    } catch {
      json = undefined;
    }
    return { json, code: Number(process.exitCode ?? 0) };
  }

  it('JSON carries release, coverage and the score note', async () => {
    const { json, code } = await run(cleanProject(), '--no-ai', '--no-dynamic');
    expect(code).toBe(0);
    expect(json.release.state).toBe('ready');
    expect(json.scoreNote).toBe(SCORE_DISCLAIMER);
    expect(json.coverage.map((a: CoverageArea) => a.kind)).toEqual(
      expect.arrayContaining(['static', 'secrets', 'dependencies', 'dynamic', 'active', 'ai']),
    );
  });

  it('without the new flag, an unverified AI critical keeps exit 0 under --fail-on critical (backward compatible)', async () => {
    mockState.aiText = aiCritical;
    const { json, code } = await run(cleanProject(), '--no-dynamic', '--fail-on', 'critical');
    expect(code).toBe(0);
    expect(json.passed).toBe(true);
    expect(json.release.state).toBe('review-required');
    expect(json.findings.find((f: any) => f.unverified).suggestedSeverity).toBe('critical');
  });

  it('--fail-on-release-state review-required exits 2 on an unverified AI critical', async () => {
    mockState.aiText = aiCritical;
    const { json, code } = await run(cleanProject(), '--no-dynamic', '--fail-on-release-state', 'review-required');
    expect(code).toBe(2);
    expect(json.releaseGatePassed).toBe(false);
  });

  it('--fail-on-release-state not-ready passes review-required (exit 0)', async () => {
    mockState.aiText = aiCritical;
    const { code } = await run(cleanProject(), '--no-dynamic', '--fail-on-release-state', 'not-ready');
    expect(code).toBe(0);
  });

  it('exit 3 when the release state is insufficient-evidence and the flag is given; exit 0 without the flag', async () => {
    mockState.dynThrows = true;
    const dir = cleanProject();
    expect((await run(dir, '--no-ai', '--fail-on-release-state', 'not-ready')).code).toBe(3);
    expect((await run(dir, '--no-ai')).code).toBe(0);
    expect((await run(dir, '--no-ai', '--fail-on', 'critical')).code).toBe(0);
  });

  it('confirmed critical: not-ready, --fail-on critical exits 2 as before', async () => {
    const dir = cleanProject({ 'run.js': 'const r = eval(input);\n' });
    const { json, code } = await run(dir, '--no-ai', '--no-dynamic', '--fail-on', 'critical');
    expect(json.release.state).toBe('not-ready');
    expect(json.release.line).toMatch(/^Release: NOT READY — 1 confirmed critical/);
    expect(code).toBe(2);
    expect((await run(dir, '--no-ai', '--no-dynamic', '--fail-on-release-state', 'not-ready')).code).toBe(2);
  });

  it('accepted baseline risks: ready-with-accepted-risks, and that state passes --fail-on-release-state review-required', async () => {
    const dir = cleanProject({ 'run.js': 'const r = eval(input);\n' });
    const baseline = path.join(dir, 'baseline.json');
    await run(dir, '--no-ai', '--no-dynamic', '--write-baseline', baseline);
    const { json, code } = await run(dir, '--no-ai', '--no-dynamic', '--baseline', baseline, '--fail-on', 'critical', '--fail-on-release-state', 'review-required');
    expect(json.release.state).toBe('ready-with-accepted-risks');
    expect(json.release.accepted).toBeGreaterThan(0);
    expect(code).toBe(0);
    expect((await run(dir, '--no-ai', '--no-dynamic', '--baseline', baseline, '--fail-on-release-state', 'ready-with-accepted-risks')).code).toBe(2);
  });

  it('rejects an invalid --fail-on-release-state (tool error, exit 1)', async () => {
    const { code } = await run(cleanProject(), '--no-ai', '--no-dynamic', '--fail-on-release-state', 'ready');
    expect(code).toBe(1);
  });
});

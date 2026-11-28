/* eslint-disable @typescript-eslint/no-var-requires */
import {
  assessRelease,
  parseReleasePolicy,
  parseReleaseStateThreshold,
  releaseAtOrWorse,
  withRelease,
  suggestedSeverity,
  DEFAULT_RELEASE_POLICY,
  RELEASE_STATES,
  SCORE_DISCLAIMER,
} from '../src/core/releaseState';
import { CoverageRecorder, buildCoverage, coverageSummary } from '../src/core/coverage';
import { EXIT, releaseExitCode, toCiJson } from '../src/core/CiGate';
import { ScoreCalculator } from '../src/analysis/ScoreCalculator';
import { makeFinding } from '../src/utils/finding';
import { HtmlReporter } from '../src/ui/HtmlReporter';
import { ExportManager } from '../src/ui/ExportManager';
import { IssuePresenter } from '../src/ui/IssuePresenter';
import type { CoverageArea, Finding, ScanReport } from '../src/types';

const { buildSummary } = require('../action/summary');

const f = (over: Partial<Finding> = {}): Finding =>
  makeFinding({
    rule: 'r',
    title: 't',
    severity: 'critical',
    category: 'security',
    source: 'static',
    description: 'd',
    recommendation: 'x',
    file: 'a.js',
    line: 1,
    ...over,
  } as Finding);

const graph = (files: string[] = ['app.js']) => ({
  root: '/x',
  stack: { stack: 'express' as const, language: 'javascript' as const, evidence: [] },
  entryPoints: [],
  modules: files.map((file) => ({ file, imports: [], exports: [], isRoute: false })),
  routes: [],
  fileCount: files.length,
});

function cov(set: (r: CoverageRecorder) => void = () => undefined, files?: string[]): CoverageArea[] {
  const r = new CoverageRecorder();
  set(r);
  return buildCoverage({ graph: graph(files) } as Pick<ScanReport, 'graph'>, r);
}

const live = (r: CoverageRecorder) => r.set('dynamic', 'passed', 'ran');

describe('assessRelease: every state', () => {
  it('ready: no findings, live coverage', () => {
    const r = assessRelease({ findings: [], coverage: cov(live) });
    expect(r.state).toBe('ready');
    expect(r.limitedCoverage).toBe(false);
    expect(r.line).toMatch(/^Release: READY — no confirmed findings · Coverage: static \(JS\/TS\) ✓ · secrets ✓ · dependencies – untested · live ✓/);
  });

  it('ready under limited coverage: only static evidence', () => {
    const r = assessRelease({ findings: [f({ severity: 'warning' })], coverage: cov() });
    expect(r.state).toBe('ready');
    expect(r.limitedCoverage).toBe(true);
    expect(r.line).toContain('READY under limited coverage');
    expect(r.line).toContain('1 lower-severity open');
  });

  it('ready-with-accepted-risks: a confirmed critical accepted in the baseline', () => {
    const crit = f();
    const r = assessRelease({ findings: [crit], coverage: cov(live) }, { accepted: [crit] });
    expect(r.state).toBe('ready-with-accepted-risks');
    expect(r.accepted).toBe(1);
    expect(r.findings.critical).toBe(0);
    expect(r.line).toContain('READY WITH ACCEPTED RISKS — 1 accepted risk(s) in the baseline');
  });

  it('review-required: unverified AI critical (severity demoted to info, suggestion kept)', () => {
    const ai = f({ source: 'ai', unverified: true, severity: 'info', suggestedSeverity: 'critical' });
    const r = assessRelease({ findings: [ai], coverage: cov(live) });
    expect(r.state).toBe('review-required');
    expect(r.confidence).toMatchObject({ confirmed: 0, unverified: 1, ai: 1, unconfirmedBlocking: 1 });
  });

  it('review-required: suspected (guessed-path) critical', () => {
    const r = assessRelease({ findings: [f({ guessed: true, source: 'dynamic' })], coverage: cov(live) });
    expect(r.state).toBe('review-required');
    expect(r.confidence.suspected).toBe(1);
    expect(r.findings.critical).toBe(0);
  });

  it('review-required: a non-mandatory area errored', () => {
    const r = assessRelease({ findings: [], coverage: cov((x) => x.set('firebase', 'failed', 'boom')) });
    expect(r.state).toBe('review-required');
    expect(r.reasons[0]).toContain('firebase check failed');
  });

  it('not-ready: confirmed critical; wins over insufficient evidence', () => {
    const r = assessRelease({
      findings: [f(), f({ rule: 'r2', line: 2 })],
      coverage: cov((x) => x.set('dynamic', 'failed', 'boom', { requested: true })),
    });
    expect(r.state).toBe('not-ready');
    expect(r.line).toMatch(/^Release: NOT READY — 2 confirmed critical; live check failed/);
    expect(r.findings.critical).toBe(2);
  });

  it('insufficient-evidence: a mandatory area errored (scanner failure is never a pass)', () => {
    const r = assessRelease({ findings: [], coverage: cov((x) => x.set('static', 'failed', 'parser crashed')) });
    expect(r.state).toBe('insufficient-evidence');
    expect(r.reasons).toEqual(expect.arrayContaining(['static check failed (scanner error is not a pass)']));
  });

  it('insufficient-evidence beats review-required (unverified critical + failed required area)', () => {
    const ai = f({ source: 'ai', unverified: true, severity: 'info', suggestedSeverity: 'critical' });
    const r = assessRelease({ findings: [ai], coverage: cov((x) => x.set('active', 'failed', 'x', { requested: true })) });
    expect(r.state).toBe('insufficient-evidence');
  });

  it('covers every release state value', () => {
    expect(RELEASE_STATES).toEqual(['ready', 'ready-with-accepted-risks', 'review-required', 'not-ready', 'insufficient-evidence']);
  });
});

describe('score is unchanged and separate', () => {
  it('same formula for confirmed findings; unverified/notes never scored', () => {
    const findings = [f(), f({ severity: 'warning', rule: 'w' }), f({ source: 'ai', unverified: true, severity: 'info', rule: 'a' })];
    const s = ScoreCalculator.summarize(findings);
    expect(ScoreCalculator.calculate(s)).toBe(Math.max(1, Math.round((100 * 30) / (30 + 13))));
  });
});

describe('policy', () => {
  it('defaults', () => {
    expect(parseReleasePolicy(undefined)).toEqual({ policy: DEFAULT_RELEASE_POLICY, warnings: [] });
  });

  it('blockOn: warning makes a confirmed warning not-ready', () => {
    const { policy } = parseReleasePolicy({ blockOn: ['critical', 'warning'] });
    const r = assessRelease({ findings: [f({ severity: 'warning' })], coverage: cov(live) }, { policy });
    expect(r.state).toBe('not-ready');
    expect(r.line).toContain('1 confirmed warning');
  });

  it('blockOn: [] never blocks on findings (coverage still matters)', () => {
    const { policy } = parseReleasePolicy({ blockOn: [] });
    expect(assessRelease({ findings: [f()], coverage: cov(live) }, { policy }).state).toBe('ready');
    expect(assessRelease({ findings: [f()], coverage: cov((x) => x.set('static', 'failed', 'x')) }, { policy }).state).toBe(
      'insufficient-evidence',
    );
  });

  it('requireAreas by kind or id', () => {
    const { policy } = parseReleasePolicy({ requireAreas: ['static-python'] });
    expect(assessRelease({ findings: [], coverage: cov(live) }, { policy }).state).toBe('ready'); // no python area at all
    const py = cov(live, ['app.py']);
    expect(py.find((a) => a.id === 'static-python')?.state).toBe('passed');
    expect(assessRelease({ findings: [], coverage: cov(() => undefined, ['a.js']) }, { policy: parseReleasePolicy({ requireAreas: ['dependencies'] }).policy }).state).toBe(
      'insufficient-evidence',
    );
  });

  it('treatUnverifiedCriticalAs: not-ready', () => {
    const { policy } = parseReleasePolicy({ treatUnverifiedCriticalAs: 'not-ready' });
    const ai = f({ source: 'ai', unverified: true, severity: 'info', suggestedSeverity: 'critical' });
    expect(assessRelease({ findings: [ai], coverage: cov(live) }, { policy }).state).toBe('not-ready');
  });

  it('invalid values are dropped with warnings, never fatal', () => {
    const { policy, warnings } = parseReleasePolicy({ blockOn: ['critical', 'high'], requireAreas: ['static', 'nope'], treatUnverifiedCriticalAs: 'ready' });
    expect(policy).toEqual({ blockOn: ['critical'], requireAreas: ['static'], treatUnverifiedCriticalAs: 'review-required' });
    expect(warnings).toHaveLength(3);
    expect(parseReleasePolicy('x').warnings[0]).toMatch(/must be an object/);
  });

  it('suggestedSeverity falls back to the "AI-suggested severity:" description prefix', () => {
    expect(suggestedSeverity(f({ severity: 'info', description: 'AI-suggested severity: critical. bad' }))).toBe('critical');
    expect(suggestedSeverity(f({ severity: 'warning' }))).toBe('warning');
  });
});

describe('gate helpers and exit codes', () => {
  it('parseReleaseStateThreshold', () => {
    expect(parseReleaseStateThreshold('NOT-READY')).toBe('not-ready');
    expect(() => parseReleaseStateThreshold('ready')).toThrow(/Invalid --fail-on-release-state/);
    expect(() => parseReleaseStateThreshold('meh')).toThrow(/Invalid/);
  });

  it('releaseAtOrWorse ordering: insufficient-evidence is worst', () => {
    expect(releaseAtOrWorse('not-ready', 'review-required')).toBe(true);
    expect(releaseAtOrWorse('review-required', 'not-ready')).toBe(false);
    expect(releaseAtOrWorse('insufficient-evidence', 'not-ready')).toBe(true);
    expect(releaseAtOrWorse('ready-with-accepted-risks', 'review-required')).toBe(false);
  });

  it('releaseExitCode: 0 without the flag, 2 gate, 3 insufficient evidence', () => {
    const ready = assessRelease({ findings: [], coverage: cov(live) });
    const notReady = assessRelease({ findings: [f()], coverage: cov(live) });
    const ie = assessRelease({ findings: [], coverage: cov((x) => x.set('static', 'failed', 'x')) });
    expect(releaseExitCode(ie, undefined)).toBe(EXIT.OK);
    expect(releaseExitCode(ready, 'review-required')).toBe(EXIT.OK);
    expect(releaseExitCode(notReady, 'review-required')).toBe(EXIT.GATE);
    expect(releaseExitCode(ie, 'review-required')).toBe(EXIT.INSUFFICIENT_EVIDENCE);
    expect(releaseExitCode(ie, 'insufficient-evidence')).toBe(EXIT.INSUFFICIENT_EVIDENCE);
    expect(releaseExitCode(notReady, 'insufficient-evidence')).toBe(EXIT.OK);
  });
});

describe('coverage', () => {
  it('unrecorded areas default to untested (dependencies are never claimed as tested)', () => {
    const areas = cov();
    expect(areas.find((a) => a.kind === 'dependencies')?.state).toBe('untested');
    expect(areas.find((a) => a.kind === 'dynamic')?.state).toBe('untested');
    expect(areas.find((a) => a.kind === 'secrets')?.state).toBe('passed');
  });

  it('a failed static step also fails secrets; degrade never upgrades', () => {
    const areas = cov((r) => r.set('static', 'failed', 'boom'));
    expect(areas.find((a) => a.kind === 'secrets')?.state).toBe('failed');
    const r = new CoverageRecorder();
    r.set('dynamic', 'failed', 'x');
    r.degrade('dynamic', 'inconclusive', 'y');
    expect(r.get('dynamic')?.state).toBe('failed');
  });

  it('reasons are redacted', () => {
    const r = new CoverageRecorder();
    r.set('dynamic', 'failed', 'error with ghp_abcdefghijklmnopqrstuvwxyz0123456789 inside');
    expect(r.get('dynamic')?.reason).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz0123456789');
  });

  it('summary collapses static, hides n/a', () => {
    const areas = cov((r) => r.set('firebase', 'not-applicable', 'none'), ['a.js', 'b.py']);
    const s = coverageSummary(areas);
    expect(s.startsWith('static (JS/TS, Python) ✓ · secrets ✓ · dependencies – untested')).toBe(true);
    expect(s).not.toContain('firebase');
  });
});

describe('outputs carry the release line and the score disclaimer', () => {
  const report = (): ScanReport =>
    withRelease({
      target: '/x',
      startedAt: 'now',
      finishedAt: 'now',
      version: '0.0.0',
      stack: graph().stack,
      graph: graph(),
      findings: [f()],
      score: 75,
      summary: { critical: 1, warning: 0, info: 0, total: 1 },
      coverage: cov(),
    });

  it('JSON (CI)', () => {
    const body = toCiJson(report(), 'critical', undefined, { failOnReleaseState: 'not-ready' });
    expect((body.release as any).state).toBe('not-ready');
    expect(body.scoreNote).toBe(SCORE_DISCLAIMER);
    expect(body.releaseGatePassed).toBe(false);
  });

  it('HTML', () => {
    const html = HtmlReporter.render(report());
    expect(html).toContain('Release: NOT READY — 1 confirmed critical');
    expect(html).toContain(SCORE_DISCLAIMER);
    expect(html).toContain('<h2>Coverage</h2>');
  });

  it('markdown', () => {
    const md = ExportManager.toMarkdown(report());
    expect(md).toContain('- **Release:** NOT READY — 1 confirmed critical');
    expect(md).toContain(SCORE_DISCLAIMER);
    expect(md).toContain('| dependencies | untested |');
  });

  it('terminal', () => {
    const out: string[] = [];
    jest.spyOn(console, 'log').mockImplementation((s?: unknown) => void out.push(String(s ?? '')));
    try {
      IssuePresenter.display(report());
    } finally {
      jest.restoreAllMocks();
    }
    const text = out.join('\n').replace(/\x1b\[[0-9;]*m/g, '');
    expect(text).toContain('Release: NOT READY — 1 confirmed critical · Coverage: static (JS/TS) ✓ · secrets ✓ · dependencies – untested · live – untested');
    expect(text).toContain(SCORE_DISCLAIMER);
    expect(text).not.toContain('Coverage gaps'); // optional untested areas are only in the line
    out.length = 0;
    jest.spyOn(console, 'log').mockImplementation((s?: unknown) => void out.push(String(s ?? '')));
    try {
      IssuePresenter.display(withRelease({ ...report(), coverage: cov((r) => r.set('dynamic', 'failed', 'socket hang up', { requested: true })) }));
    } finally {
      jest.restoreAllMocks();
    }
    const failed = out.join('\n').replace(/\x1b\[[0-9;]*m/g, '');
    expect(failed).toContain('Coverage gaps');
    expect(failed).toContain('live ✗ failed (required): socket hang up');
  });

  it('GitHub Action summary', () => {
    const json = toCiJson(report(), 'critical');
    const md = buildSummary(JSON.parse(JSON.stringify(json)), { exitCode: 2, failOn: 'critical' });
    expect(md).toContain('**Release: NOT READY — 1 confirmed critical');
    expect(md).toContain(SCORE_DISCLAIMER);
    expect(buildSummary({ ...json, release: { ...(json.release as object), state: 'insufficient-evidence' } }, { exitCode: 3 })).toContain(
      'insufficient evidence',
    );
    const aiOnly = buildSummary(
      { score: 100, summary: { critical: 0, warning: 0, info: 0, total: 0 }, findings: [{ rule: 'a', unverified: true, severity: 'info' }] },
      { exitCode: 0 },
    );
    expect(aiOnly).toContain('1 unverified AI suggestion(s) not counted above');
    expect(aiOnly).toContain('No confirmed findings in the areas tested.');
  });
});

describe('engine coverage (dependencies / engines areas from report.engineRuns)', () => {
  const { recordEngineCoverage } = require('../src/core/coverage');
  const run = (id: string, status: string, extra: Record<string, unknown> = {}) => ({
    id, status, findings: 0, durationMs: 1, coverage: { checked: [], skipped: [], errors: [] }, ...extra,
  });
  const areaFor = (runs: unknown[], o: Record<string, unknown> = {}) => {
    const r = new CoverageRecorder();
    recordEngineCoverage(r, runs, o);
    return { dep: r.get('dependencies'), eng: r.get('engines') };
  };

  it('passed when a dependency engine ran clean', () => {
    expect(areaFor([run('npm-audit', 'ran', { version: '10.0.0', findings: 2 })]).dep).toMatchObject({ state: 'passed' });
  });
  it('failed when one errored (even if another ran)', () => {
    const { dep } = areaFor([run('npm-audit', 'ran'), run('osv-scanner', 'error', { reason: 'osv-scanner failed: timeout' })]);
    expect(dep).toMatchObject({ state: 'failed', reason: 'osv-scanner failed: timeout' });
  });
  it('untested with reasons when skipped (--offline) or nothing applied, and --no-deps says so', () => {
    expect(areaFor([run('npm-audit', 'skipped', { reason: 'skipped: --offline' })]).dep).toMatchObject({ state: 'untested', reason: 'npm-audit: skipped: --offline' });
    expect(areaFor([]).dep?.state).toBe('untested');
    expect(areaFor([], { noDeps: true }).dep?.reason).toBe('Skipped (--no-deps).');
  });
  it('an engine named in --engines is requested, so its miss matters; unknown engines fail the engines area', () => {
    const { eng } = areaFor([run('semgrep', 'error', { reason: 'semgrep is not installed' })], { engines: 'semgrep' });
    expect(eng).toMatchObject({ state: 'failed', requested: true });
    expect(areaFor([run('nope', 'error', { reason: 'unknown engine "nope"' })], { engines: 'nope' }).eng?.state).toBe('failed');
    const areas = buildCoverage({ graph: graph() } as Pick<ScanReport, 'graph'>, (() => {
      const r = new CoverageRecorder();
      recordEngineCoverage(r, [run('semgrep', 'error', { reason: 'x' })], { engines: 'semgrep' });
      return r;
    })());
    expect(assessRelease({ findings: [], coverage: areas }).state).toBe('insufficient-evidence');
  });
});

describe('static scan issues are surfaced, not swallowed', () => {
  it('unreadable files and a failed route discovery are collected', async () => {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const { VulnerabilityDetector } = require('../src/analysis/VulnerabilityDetector');
    const { FileWalker } = require('../src/utils/FileWalker');
    const { CodeParser } = require('../src/parser/CodeParser');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-static-issues-'));
    fs.writeFileSync(path.join(dir, 'a.js'), 'const x = 1;\n');
    fs.writeFileSync(path.join(dir, 'b.js'), 'const y = 2;\n');
    const realRead = FileWalker.read.bind(FileWalker);
    jest.spyOn(FileWalker, 'read').mockImplementation(((f: { relPath: string }) =>
      f.relPath === 'b.js' ? Promise.reject(new Error('EACCES')) : realRead(f)) as never);
    jest.spyOn(CodeParser, 'analyze').mockRejectedValue(new Error('parser exploded'));
    try {
      const issues = { unreadable: [] as string[] };
      await VulnerabilityDetector.scan(dir, issues);
      expect(issues.unreadable).toEqual(['b.js']);
      expect((issues as { routeAuthError?: string }).routeAuthError).toBe('parser exploded');
    } finally {
      jest.restoreAllMocks();
    }
  });

  it('an inconclusive static entry keeps per-language areas and makes the release review-required', () => {
    const areas = cov((r) => r.set('static', 'inconclusive', 'Static scan partial: 1 file(s) could not be read (b.js).'));
    expect(areas.find((a) => a.id === 'static-javascript')).toMatchObject({ state: 'inconclusive' });
    expect(assessRelease({ findings: [], coverage: areas }).state).toBe('review-required');
  });
});

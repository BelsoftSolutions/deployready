import { IssueAggregator } from '../src/analysis/IssueAggregator';
import { ScoreCalculator } from '../src/analysis/ScoreCalculator';
import { newFindings, serializeBaseline, readBaseline, shouldFail, summarize, toCiJson } from '../src/core/CiGate';
import { runCommonPathProbe } from '../src/dynamic/commonPaths/prober';
import { PROBE_PATHS } from '../src/dynamic/commonPaths/signatures';
import { ExportManager } from '../src/ui/ExportManager';
import { HtmlReporter } from '../src/ui/HtmlReporter';
import { IssuePresenter } from '../src/ui/IssuePresenter';
import { COMMON_PATH_TITLE } from '../src/ui/commonPathSection';
import type { Finding, ScanReport } from '../src/types';
import { PLAIN_404, html, send, text, withServer } from './helpers/probeServer';
import type { RouteMap } from './helpers/probeServer';

const FAKE_ENV_VALUE = ['zz', 'envvalue', 'not-real', '77'].join('-');
const FAKE_NPM_VALUE = ['zz', 'npmvalue', 'not-real', '88'].join('-');
const PATHS = PROBE_PATHS.map((p) => p.path);

const ROUTES: RouteMap = {
  '/.env': text(`DATABASE_URL=postgres://user:${FAKE_ENV_VALUE}@db.example.invalid/app\nAPP_SECRET=${FAKE_ENV_VALUE}\n`),
  '/.git/config': text('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.invalid/r.git\n'),
  '/.npmrc': text(`//registry.example.invalid/:_authToken=${FAKE_NPM_VALUE}\n`),
  '/phpinfo.php': html('<html><head><title>phpinfo()</title></head><body>PHP Version 8.2</body></html>'),
};

async function buildReport(routes: RouteMap): Promise<ScanReport> {
  const probe = await withServer(
    (req, res) => send(res, routes[req.url ?? ''] ?? PLAIN_404),
    (baseUrl) => runCommonPathProbe(baseUrl, { exclude: [], delayMs: 0 }),
  );
  const agg = IssueAggregator.process([], probe.findings);
  const stack = { stack: 'express' as const, language: 'javascript' as const, evidence: [] };
  return {
    target: '/tmp/app',
    startedAt: '2026-01-01T00:00:00.000Z',
    finishedAt: '2026-01-01T00:00:01.000Z',
    version: '0.0.0-test',
    stack,
    graph: { root: '/tmp/app', stack, entryPoints: [], modules: [], routes: [], fileCount: 1 },
    dynamic: { baseUrl: probe.report.target, reachable: true, endpoints: [], probed: [], skipped: [], findings: probe.findings, commonPaths: probe.report },
    findings: agg.findings,
    score: agg.score,
    summary: agg.summary,
  };
}

const ANSI = /\[[0-9;]*m/g;
function terminal(report: ScanReport): string {
  const lines: string[] = [];
  const spy = jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void lines.push(a.join(' ')));
  try {
    IssuePresenter.display(report);
  } finally {
    spy.mockRestore();
  }
  return lines.join('\n').replace(ANSI, '');
}

const count = (haystack: string, needle: string): number => haystack.split(needle).length - 1;
const guessedTitles = (r: ScanReport): string[] => r.findings.filter((f) => f.guessed).map((f) => f.title);

let report: ScanReport;
beforeAll(async () => {
  report = await buildReport(ROUTES);
});

describe('the four outputs render the opt-in probe section', () => {
  it('the fixture produced guessed findings, with the label in the title', () => {
    const titles = guessedTitles(report);
    expect(titles.length).toBeGreaterThanOrEqual(4);
    for (const t of titles) expect(t).toMatch(/\(guessed path, lower confidence\)$/);
  });

  function expectSection(out: string): void {
    expect(out).toContain(COMMON_PATH_TITLE);
    expect(out).toContain('guessed path, lower confidence');
    for (const p of PATHS) expect(out).toContain(p);
    expect(out).toMatch(/not found/);
    expect(out).toContain(report.dynamic!.commonPaths!.control.path);
    expect(out).toMatch(/cap: 20/);
    for (const v of [FAKE_ENV_VALUE, FAKE_NPM_VALUE]) expect(out).not.toContain(v);
  }

  it('terminal: section, labelled findings once, every requested path with outcome, no secret value', () => {
    const out = terminal(report);
    expectSection(out);
    for (const t of guessedTitles(report)) expect(count(out, t)).toBe(1);
    expect(out).toMatch(/found\s+GET \/\.env -> 200/);
    expect(out).toMatch(/not found\s+GET \/\.env\.local -> 404/);
    expect(out).toMatch(/Guessed findings count in the summary/);
  });

  it('markdown: section, labelled findings once, every requested path with outcome, no secret value', () => {
    const md = ExportManager.toMarkdown(report);
    expectSection(md);
    expect(md).toContain(`## ${COMMON_PATH_TITLE}`);
    for (const t of guessedTitles(report)) expect(count(md, t)).toBe(1);
    expect(md).toMatch(/\| `\/\.env\.local` \| 404 \| not found \|/);
    expect(md).toMatch(/\| `\/\.env` \| 200 \| found \|/);
  });

  it('html: section, labelled findings once, every requested path with outcome, no secret value', () => {
    const page = HtmlReporter.render(report);
    expectSection(page);
    expect(page).toContain(`<h2>🔎 ${COMMON_PATH_TITLE}</h2>`);
    for (const t of guessedTitles(report)) expect(count(page, t)).toBe(1);
    expect(page).toMatch(/<td><code>\/\.env\.local<\/code><\/td><td>404<\/td><td>not found<\/td>/);
    expect(page).toMatch(/<td><code>\/\.env<\/code><\/td><td>200<\/td><td>found<\/td>/);
  });

  it('json: section with the guessed findings and all paths; the normal findings list does not repeat them', () => {
    const out = toCiJson(report, 'none') as {
      findings: Array<{ title: string }>;
      commonPathProbe: { title: string; cap: number; control: { path: string; status: number }; probed: Array<{ path: string; outcome: string; reason: string }>; findings: Array<{ title: string; guessed: boolean }> };
      summary: { critical: number };
    };
    const text = JSON.stringify(out);
    expect(out.commonPathProbe.title).toBe(COMMON_PATH_TITLE);
    expect(out.commonPathProbe.cap).toBe(20);
    expect(out.commonPathProbe.control.path).toBe(report.dynamic!.commonPaths!.control.path);
    expect(out.commonPathProbe.probed.map((p) => p.path)).toEqual(PATHS);
    expect(out.commonPathProbe.probed.find((p) => p.path === '/.env.local')).toMatchObject({ outcome: 'not-found' });
    expect(out.commonPathProbe.findings.map((f) => f.title).sort()).toEqual(guessedTitles(report).sort());
    expect(out.commonPathProbe.findings.every((f) => f.guessed === true)).toBe(true);
    for (const t of guessedTitles(report)) expect(out.findings.some((f) => f.title === t)).toBe(false);
    expect(out.summary.critical).toBe(report.summary.critical);
    for (const v of [FAKE_ENV_VALUE, FAKE_NPM_VALUE]) expect(text).not.toContain(v);
  });

  it('without the probe none of the four outputs mention it, and json has no probe key', () => {
    const plain: ScanReport = { ...report, dynamic: undefined, findings: [], score: 100, summary: { critical: 0, warning: 0, info: 0, total: 0 } };
    expect(terminal(plain)).not.toMatch(/Common-path probe/);
    expect(ExportManager.toMarkdown(plain)).not.toMatch(/Common-path probe/);
    expect(HtmlReporter.render(plain)).not.toMatch(/Common-path probe/);
    expect(Object.keys(toCiJson(plain, 'none'))).not.toContain('commonPathProbe');
  });

  it('a probe that found nothing still lists every requested path', async () => {
    const empty = await buildReport({});
    expect(empty.findings.filter((f) => f.guessed)).toEqual([]);
    for (const out of [terminal(empty), ExportManager.toMarkdown(empty), HtmlReporter.render(empty)]) {
      expect(out).toContain(COMMON_PATH_TITLE);
      expect(out).toMatch(/No guessed path was proven exposed/);
      for (const p of PATHS) expect(out).toContain(p);
    }
    const j = toCiJson(empty, 'none') as { commonPathProbe: { probed: unknown[]; findings: unknown[] } };
    expect(j.commonPathProbe.probed).toHaveLength(PATHS.length);
    expect(j.commonPathProbe.findings).toEqual([]);
  });
});

describe('score and gate treat guessed findings like any finding of their capped severity', () => {
  it('a conclusive critical (git config) fails --fail-on critical', async () => {
    const r = await buildReport({ '/.git/config': ROUTES['/.git/config']! });
    expect(r.summary.critical).toBe(1);
    expect(r.findings.find((f) => f.guessed)?.severity).toBe('critical');
    expect(shouldFail(r.summary, 'critical')).toBe(true);
    expect((toCiJson(r, 'critical') as { passed: boolean }).passed).toBe(false);
  });

  it('a non-conclusive warning (phpinfo) does not fail --fail-on critical but does fail --fail-on warning', async () => {
    const r = await buildReport({ '/phpinfo.php': ROUTES['/phpinfo.php']! });
    expect(r.summary).toMatchObject({ critical: 0, warning: 1, info: 0 });
    expect(r.findings.find((f) => f.guessed)?.severity).toBe('warning');
    expect(shouldFail(r.summary, 'critical')).toBe(false);
    expect((toCiJson(r, 'critical') as { passed: boolean }).passed).toBe(true);
    expect(shouldFail(r.summary, 'warning')).toBe(true);
  });

  it('a guessed finding scores exactly like an ordinary finding of the same severity', async () => {
    const r = await buildReport({ '/phpinfo.php': ROUTES['/phpinfo.php']! });
    const guessed = r.findings.find((f) => f.guessed) as Finding;
    const ordinary: Finding = { ...guessed, guessed: undefined };
    const a = IssueAggregator.process([], [guessed]);
    const b = IssueAggregator.process([], [ordinary]);
    expect(a.score).toBe(b.score);
    expect(a.summary).toEqual(b.summary);
    expect(a.score).toBe(ScoreCalculator.calculate(summarize([ordinary])));
    expect(a.score).toBeLessThan(100);
  });

  it('the baseline grandfathers a known guessed finding and gates on a new one', async () => {
    const known = await buildReport({ '/.git/config': ROUTES['/.git/config']! });
    const baseline = readBaseline(serializeBaseline(known.findings));
    expect(baseline.has('common-path-exposure::/.git/config')).toBe(true);
    expect(newFindings(known.findings, baseline).filter((f) => f.guessed)).toEqual([]);

    const later = await buildReport({ '/.git/config': ROUTES['/.git/config']!, '/.npmrc': ROUTES['/.npmrc']! });
    const fresh = newFindings(later.findings, baseline).filter((f) => f.guessed);
    expect(fresh.map((f) => f.endpoint)).toEqual(['/.npmrc']);
    expect(shouldFail(summarize(newFindings(later.findings, baseline)), 'critical')).toBe(true);
    expect(shouldFail(summarize(newFindings(known.findings, baseline)), 'critical')).toBe(false);
  });
});

import { IssueAggregator } from '../src/analysis/IssueAggregator';
import { ScoreCalculator, isNonScored } from '../src/analysis/ScoreCalculator';
import { SeverityScorer } from '../src/analysis/SeverityScorer';
import { newFindings, readBaseline, serializeBaseline, shouldFail, summarize, toCiJson } from '../src/core/CiGate';
import { ExportManager } from '../src/ui/ExportManager';
import { HtmlReporter } from '../src/ui/HtmlReporter';
import { IssuePresenter } from '../src/ui/IssuePresenter';
import { makeFinding, makeNote } from '../src/utils/finding';
import type { Finding, ScanReport } from '../src/types';

const note = (): Finding =>
  makeNote({
    rule: 'missing-rate-limit',
    title: 'Rate limiting on /login could not be verified',
    category: 'security',
    source: 'dynamic',
    endpoint: '/login',
    description: 'Not tested.',
    recommendation: 'Check it.',
  });

const realInfo = (): Finding =>
  makeFinding({
    rule: 'missing-cache-headers',
    title: 'No cache headers',
    severity: 'info',
    category: 'performance',
    source: 'dynamic',
    endpoint: '/',
    description: 'd',
    recommendation: 'r',
  });

const warning = (): Finding =>
  makeFinding({
    rule: 'cors-wildcard',
    title: 'CORS wildcard',
    severity: 'warning',
    category: 'security',
    source: 'static',
    file: 'a.js',
    line: 1,
    description: 'd',
    recommendation: 'r',
  });

const aiSuggestion = (): Finding =>
  makeFinding({
    rule: 'ai-thing',
    title: 'AI thing',
    severity: 'info',
    category: 'security',
    source: 'ai',
    unverified: true,
    file: 'a.js',
    description: 'd',
    recommendation: 'r',
  });

function reportOf(findings: Finding[]): ScanReport {
  const agg = IssueAggregator.process(findings);
  return {
    target: '/app',
    startedAt: '2026-06-06T00:00:00Z',
    finishedAt: '',
    version: '0.1.0',
    stack: { stack: 'express', language: 'javascript', evidence: [] },
    graph: { root: '/app', stack: { stack: 'express', language: 'javascript', evidence: [] }, entryPoints: [], modules: [], routes: [], fileCount: 1 },
    findings: agg.findings,
    score: agg.score,
    summary: agg.summary,
  } as ScanReport;
}

function terminal(report: ScanReport): string {
  const lines: string[] = [];
  const spy = jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void lines.push(a.join(' ')));
  try {
    IssuePresenter.display(report);
  } finally {
    spy.mockRestore();
  }
  // eslint-disable-next-line no-control-regex
  return lines.join('\n').replace(/\[[0-9;]*m/g, '');
}

describe('makeNote', () => {
  it('forces severity info and note: true, and keeps the rule', () => {
    const n = note();
    expect(n.severity).toBe('info');
    expect(n.note).toBe(true);
    expect(n.rule).toBe('missing-rate-limit');
    expect(n.unverified).toBeUndefined();
    expect(isNonScored(n)).toBe(true);
  });
});

describe('ScoreCalculator with notes', () => {
  it('a note changes neither the score nor critical/warning/info/total, and is counted in notes', () => {
    const base = ScoreCalculator.summarize([warning(), realInfo()]);
    const withNote = ScoreCalculator.summarize([warning(), realInfo(), note()]);
    expect(withNote).toMatchObject({ critical: 0, warning: 1, info: 1, total: 2, unverified: 0, notes: 1 });
    expect(withNote.critical).toBe(base.critical);
    expect(withNote.total).toBe(base.total);
    expect(ScoreCalculator.calculate(withNote)).toBe(ScoreCalculator.calculate(base));
    expect(ScoreCalculator.calculate(ScoreCalculator.summarize([note()]))).toBe(100);
  });

  it('keeps counting AI suggestions separately from notes', () => {
    expect(ScoreCalculator.summarize([note(), aiSuggestion()])).toMatchObject({
      total: 0,
      info: 0,
      unverified: 1,
      notes: 1,
    });
  });
});

describe('SeverityScorer / IssueAggregator with notes', () => {
  it('leaves a note untouched: still info, not turned into an AI suggestion', () => {
    const [n] = SeverityScorer.apply([note()]);
    expect(n).toEqual(note());
    expect(n!.unverified).toBeUndefined();
    expect(n!.source).toBe('dynamic');
  });

  it('aggregates to score 100 with notes counted separately', () => {
    const agg = IssueAggregator.process([note()]);
    expect(agg.score).toBe(100);
    expect(agg.summary).toMatchObject({ critical: 0, warning: 0, info: 0, total: 0, notes: 1, unverified: 0 });
    expect(agg.findings).toHaveLength(1);
  });
});

describe('CiGate with notes', () => {
  it('a note alone passes every --fail-on level', () => {
    const s = summarize([note()]);
    for (const level of ['critical', 'warning', 'info', 'none'] as const) {
      expect(shouldFail(s, level)).toBe(false);
    }
  });

  it('a note plus a real info finding still fails --fail-on info because of the real one', () => {
    expect(shouldFail(summarize([note(), realInfo()]), 'info')).toBe(true);
    expect(shouldFail(summarize([note(), realInfo()]), 'warning')).toBe(false);
  });

  it('the baseline excludes notes and never grandfathers them', () => {
    const body = serializeBaseline([note(), realInfo()]);
    const set = readBaseline(body);
    expect(set.size).toBe(1);
    const poisoned = new Set([...set, 'missing-rate-limit::/login']);
    const fresh = newFindings([note(), realInfo()], poisoned);
    expect(fresh).toHaveLength(1);
    expect(fresh.map((f) => f.rule)).toEqual(['missing-rate-limit']);
    expect(summarize(fresh)).toMatchObject({ total: 0, notes: 1 });
    expect(shouldFail(summarize(fresh), 'info')).toBe(false);
  });

  it('toCiJson exposes note per finding and notes in the summary', () => {
    const json = toCiJson(reportOf([note(), warning()]), 'info') as {
      passed: boolean;
      summary: { notes: number; total: number };
      findings: Array<{ rule: string; note: boolean; unverified: boolean }>;
    };
    expect(json.summary.notes).toBe(1);
    expect(json.summary.total).toBe(1);
    expect(json.findings.find((f) => f.rule === 'missing-rate-limit')).toMatchObject({ note: true, unverified: false });
    expect(json.findings.find((f) => f.rule === 'cors-wildcard')!.note).toBe(false);
    expect(json.passed).toBe(false);
    const onlyNote = toCiJson(reportOf([note()]), 'info') as { passed: boolean };
    expect(onlyNote.passed).toBe(true);
  });
});

describe('presentation of notes', () => {
  const report = () => reportOf([warning(), realInfo(), note(), aiSuggestion()]);

  it('markdown: NOTES section, not in a severity group, not in totals', () => {
    const md = ExportManager.toMarkdown(report());
    expect(md).toContain('## NOTES (not scored) (1)');
    expect(md).toContain('0 critical · 1 warning · 1 info');
    expect(md).toContain('- **Notes:** 1 (not scored)');
    const infoSection = md.slice(md.indexOf('## INFO'), md.indexOf('## NOTES'));
    expect(infoSection).toContain('No cache headers');
    expect(infoSection).not.toContain('could not be verified');
    expect(md.slice(md.indexOf('## NOTES'))).toContain('could not be verified');
    expect(md).toContain('## AI SUGGESTIONS — unverified, not scored (1)');
  });

  it('markdown: no NOTES section without notes', () => {
    expect(ExportManager.toMarkdown(reportOf([warning()]))).not.toContain('NOTES');
  });

  it('html: note card, filter, NOTE badge, distinct from UNVERIFIED', () => {
    const html = HtmlReporter.render(report());
    expect(html).toContain('data-f="note"');
    expect(html).toContain('Notes, not scored (1)');
    expect(html).toContain('data-sev="note"');
    expect(html).toContain('>NOTE</span>');
    expect(html).toContain('>UNVERIFIED</span>');
    expect(html).toContain('Info (1)');
    expect(html).toContain('stat-l">Notes<');
  });

  it('html: no notes filter or card when there are none', () => {
    const html = HtmlReporter.render(reportOf([warning()]));
    expect(html).not.toContain('data-f="note"');
    expect(html).not.toContain('stat-l">Notes<');
  });

  it('terminal: own NOTES section with NOTE badge, not under INFO, not in the summary counts', () => {
    const out = terminal(report());
    expect(out).toContain('NOTES (not scored) (1)');
    expect(out).toContain('NOTE');
    expect(out).toContain('Summary: 0 critical, 1 warnings, 1 info');
    const infoPart = out.slice(out.indexOf('INFO ('), out.indexOf('AI SUGGESTIONS'));
    expect(infoPart).toContain('No cache headers');
    expect(infoPart).not.toContain('could not be verified');
    expect(out.slice(out.indexOf('NOTES (not scored)'))).toContain('could not be verified');
    expect(out).toContain('AI SUGGESTIONS (unverified, not scored) (1)');
  });

  it('terminal: a note-only report still shows the note and a zero summary', () => {
    const out = terminal(reportOf([note()]));
    expect(out).toContain('NOTES (not scored) (1)');
    expect(out).toContain('Summary: 0 critical, 0 warnings, 0 info');
  });
});

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parseAiResponse } from '../src/ai/parseAiResponse';
import { verifyAiFindings } from '../src/ai/verifyAiFindings';
import { IssueAggregator } from '../src/analysis/IssueAggregator';
import { ScoreCalculator } from '../src/analysis/ScoreCalculator';
import { newFindings, serializeBaseline, readBaseline, shouldFail, summarize, toCiJson } from '../src/core/CiGate';
import { ExportManager } from '../src/ui/ExportManager';
import { HtmlReporter } from '../src/ui/HtmlReporter';
import { IssuePresenter } from '../src/ui/IssuePresenter';
import { makeFinding } from '../src/utils/finding';
import type { Finding, ScanReport } from '../src/types';

function project(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-ai-'));
  fs.writeFileSync(path.join(dir, 'app.js'), 'console.log(1);\n');
  fs.mkdirSync(path.join(dir, 'sub'));
  fs.writeFileSync(path.join(dir, 'sub', 'real.js'), 'x\n');
  return dir;
}

const staticFinding = (): Finding =>
  makeFinding({
    rule: 'eval-usage',
    title: 'eval',
    severity: 'critical',
    category: 'security',
    source: 'static',
    file: 'app.js',
    line: 1,
    description: 'd',
    recommendation: 'r',
  });

function aiText(entries: Array<Record<string, unknown>>): string {
  return JSON.stringify({ summary: 'Looks risky.', findings: entries });
}

function entry(file: string | undefined, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    rule: `ai-${file ?? 'general'}`,
    title: `AI says ${file ?? 'general'}`,
    severity: 'critical',
    category: 'security',
    description: 'Something scary.',
    recommendation: 'Fix it.',
    file,
    ...extra,
  };
}

function reportOf(findings: Finding[]): ScanReport {
  const agg = IssueAggregator.process(findings);
  return {
    target: '/app', startedAt: '2026-06-06T00:00:00Z', finishedAt: '', version: '0.1.0',
    stack: { stack: 'express', language: 'javascript', evidence: [] },
    graph: { root: '/app', stack: { stack: 'express', language: 'javascript', evidence: [] }, entryPoints: [], modules: [], routes: [], fileCount: 1 },
    findings: agg.findings, score: agg.score, summary: agg.summary,
  } as ScanReport;
}

describe('AI findings are unverified suggestions', () => {
  it('parseAiResponse labels every AI finding unverified', () => {
    const { findings } = parseAiResponse(aiText([entry('app.js'), entry(undefined)]));
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.source === 'ai' && f.unverified === true)).toBe(true);
  });

  it('drops findings for nonexistent files, traversal, absolute paths, and directories', async () => {
    const dir = project();
    const abs = path.resolve(dir, 'app.js');
    const parsed = parseAiResponse(
      aiText([
        entry('does/not/exist.js'),
        entry('../../etc/passwd'),
        entry('sub/../../outside.js'),
        entry('/etc/passwd'),
        entry('C:\\Windows\\win.ini'),
        entry(abs),
        entry('sub'),
        entry('app.js'),
        entry(undefined),
      ]),
    );
    const { findings, dropped } = await verifyAiFindings(parsed.findings, dir);
    expect(dropped).toBe(7);
    expect(findings.map((f) => f.file)).toEqual(['app.js', undefined]);
  });

  it('caps severity at info but keeps the model suggestion visible', async () => {
    const dir = project();
    const parsed = parseAiResponse(aiText([entry('sub/real.js')]));
    const { findings } = await verifyAiFindings(parsed.findings, dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.unverified).toBe(true);
    expect(findings[0]!.description).toContain('AI-suggested severity: critical.');
    expect(findings[0]!.file).toBe('sub/real.js');
  });

  it('AI findings do not change the score or the summary counts', async () => {
    const dir = project();
    const baseline = IssueAggregator.process([staticFinding()]);
    const parsed = parseAiResponse(aiText([entry('app.js'), entry('sub/real.js'), entry(undefined)]));
    const { findings } = await verifyAiFindings(parsed.findings, dir);
    const withAi = IssueAggregator.process([staticFinding()], findings);
    expect(withAi.score).toBe(baseline.score);
    expect(withAi.summary).toMatchObject({ critical: 1, warning: 0, info: 0, total: 1, unverified: 3 });
    expect(withAi.findings).toHaveLength(4);
  });

  it('even unverified-by-source findings with a critical severity are never scored', () => {
    const parsed = parseAiResponse(aiText([entry('app.js')]));
    const raw = parsed.findings.map((f) => ({ ...f, unverified: undefined }));
    expect(raw[0]!.severity).toBe('critical');
    const agg = IssueAggregator.process(raw);
    expect(agg.score).toBe(100);
    expect(agg.summary).toMatchObject({ critical: 0, total: 0, unverified: 1 });
    expect(agg.findings[0]!.severity).toBe('info');
    expect(ScoreCalculator.summarize(raw).critical).toBe(0);
  });

  it('a critical AI finding does not trip the CI gate', async () => {
    const dir = project();
    const parsed = parseAiResponse(aiText([entry('app.js')]));
    const { findings } = await verifyAiFindings(parsed.findings, dir);
    const agg = IssueAggregator.process(findings);
    for (const gate of ['critical', 'warning', 'info'] as const) {
      expect(shouldFail(agg.summary, gate)).toBe(false);
    }
  });

  it('keeps dedup precedence: an AI finding duplicating a static one is dropped', async () => {
    const dir = project();
    const parsed = parseAiResponse(aiText([entry('app.js', { rule: 'eval-usage', line: undefined })]));
    const dup = { ...parsed.findings[0]!, line: 1 };
    const { findings } = await verifyAiFindings([dup], dir);
    const agg = IssueAggregator.process([staticFinding()], findings);
    expect(agg.findings).toHaveLength(1);
    expect(agg.findings[0]!.source).toBe('static');
    expect(agg.summary.unverified).toBe(0);
  });

  it('baseline never records or suppresses AI findings', async () => {
    const dir = project();
    const parsed = parseAiResponse(aiText([entry('app.js', { rule: 'eval-usage' })]));
    const { findings: ai } = await verifyAiFindings(parsed.findings, dir);
    const body = serializeBaseline([staticFinding(), ...ai]);
    expect(readBaseline(body).size).toBe(1);

    const poisoned = new Set([`eval-usage:app.js:`, ...readBaseline(body)]);
    const fresh = newFindings(ai, poisoned);
    expect(fresh).toHaveLength(1);
    expect(summarize(fresh)).toMatchObject({ critical: 0, total: 0, unverified: 1 });
  });

  it('CI JSON carries the unverified flag and count', async () => {
    const dir = project();
    const parsed = parseAiResponse(aiText([entry('app.js')]));
    const { findings } = await verifyAiFindings(parsed.findings, dir);
    const json = toCiJson(reportOf([staticFinding(), ...findings]), 'critical') as {
      summary: { unverified: number };
      findings: Array<{ source: string; unverified: boolean }>;
    };
    expect(json.summary.unverified).toBe(1);
    expect(json.findings.find((f) => f.source === 'ai')!.unverified).toBe(true);
    expect(json.findings.find((f) => f.source === 'static')!.unverified).toBe(false);
  });

  it('markdown and HTML label AI suggestions as unverified and escape their content', async () => {
    const dir = project();
    const parsed = parseAiResponse(
      aiText([entry('app.js', { title: '<img src=x onerror=alert(1)>', description: '<script>alert(1)</script>' })]),
    );
    const { findings } = await verifyAiFindings(parsed.findings, dir);
    const report = reportOf([staticFinding(), ...findings]);

    const md = ExportManager.toMarkdown(report);
    expect(md).toMatch(/unverified/i);
    expect(md).toContain('AI SUGGESTIONS');
    expect(md).toContain('1 critical · 0 warning · 0 info');

    const html = HtmlReporter.render(report);
    expect(html).toContain('UNVERIFIED');
    expect(html).toContain('data-sev="unverified"');
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('terminal output lists AI findings separately as unverified and not scored', async () => {
    const dir = project();
    const parsed = parseAiResponse(aiText([entry('app.js')]));
    const { findings } = await verifyAiFindings(parsed.findings, dir);
    const lines: string[] = [];
    const spy = jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void lines.push(a.join(' ')));
    try {
      IssuePresenter.display(reportOf([staticFinding(), ...findings]));
    } finally {
      spy.mockRestore();
    }
    const out = lines.join('\n');
    expect(out).toContain('AI SUGGESTIONS (unverified, not scored) (1)');
    expect(out).toContain('1 AI suggestions (unverified, not scored)');
    expect(out).toContain('AI-suggested severity: critical.');
    expect(out).toContain('CRITICAL (1)');
  });
});

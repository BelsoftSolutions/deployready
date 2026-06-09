import { HtmlReporter } from '../src/ui/HtmlReporter';
import { makeFinding } from '../src/utils/finding';
import type { ScanReport } from '../src/types';

function report(findings = []): ScanReport {
  return {
    target: '/app', startedAt: '2026-06-06T00:00:00Z', finishedAt: '', version: '0.1.0',
    stack: { stack: 'express', language: 'javascript', evidence: [] },
    graph: { root: '/app', stack: { stack: 'express', language: 'javascript', evidence: [] }, entryPoints: [], modules: [], routes: [], fileCount: 3 },
    findings, score: 62, summary: { critical: 1, warning: 1, info: 0, total: 2 },
    aiSummary: 'Top issue is an exposed key.',
  } as ScanReport;
}

describe('HtmlReporter', () => {
  it('produces a self-contained HTML document with the score', () => {
    const html = HtmlReporter.render(report());
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toContain('>62<');
    expect(html).toContain('<style>'); // inline CSS
    expect(html).toContain('AI Summary');
  });

  it('loads no external resources (offline-safe), but may link out via anchors', () => {
    const html = HtmlReporter.render(report());
    expect(html).not.toMatch(/<script\s+src=/i); // no external scripts
    expect(html).not.toMatch(/<link\b/i); // no external stylesheets/fonts
    expect(html).not.toMatch(/@import/i); // no CSS imports
    expect(html).not.toMatch(/src=["']https?:/i); // no remote images/iframes
  });

  it('is branded and links to the DeployReady website', () => {
    const html = HtmlReporter.render(report());
    expect(html).toContain('#00ff88'); // brand accent
    expect(html).toContain('https://www.deployready.dev/');
  });

  it('includes a deployment recommendation derived from the stack', () => {
    const html = HtmlReporter.render(report());
    expect(html).toMatch(/Recommended deployment|Deploy/i);
  });

  it('HTML-escapes finding content so the report cannot become an XSS vector', () => {
    const evil = makeFinding({
      rule: 'xss', title: '<img src=x onerror=alert(1)>', severity: 'critical', category: 'security',
      source: 'static', description: 'bad <script>', recommendation: 'fix & escape',
      file: 'a.js', line: 1, evidence: `innerHTML = "<b>"`,
    });
    const html = HtmlReporter.render(report([evil] as never));
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).toContain('fix &amp; escape');
  });
});

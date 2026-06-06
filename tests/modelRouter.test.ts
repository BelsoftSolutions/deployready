import { ModelRouter } from '../src/ai/ModelRouter';
import { PromptBuilder } from '../src/ai/PromptBuilder';
import { ContextChunker } from '../src/ai/ContextChunker';
import { makeFinding } from '../src/utils/finding';
import type { AppConfig, ScanReport } from '../src/types';

function fakeReport(findingCount = 3): ScanReport {
  const findings = Array.from({ length: findingCount }, (_, i) =>
    makeFinding({
      rule: `r${i}`, title: `Issue ${i}`, severity: 'warning', category: 'security',
      source: 'static', description: 'desc', recommendation: 'fix it', file: `f${i}.js`, line: i,
    }),
  );
  return {
    target: '/tmp/app', startedAt: '', finishedAt: '', version: '0.1.0',
    stack: { stack: 'express', language: 'javascript', evidence: [] },
    graph: { root: '/tmp/app', stack: { stack: 'express', language: 'javascript', evidence: [] }, entryPoints: [], modules: [], routes: [], fileCount: 1 },
    findings, score: 85, summary: { critical: 0, warning: findingCount, info: 0, total: findingCount },
  };
}

const ollamaConfig: AppConfig = {
  model: 'ollama', claudeApiKey: null, openaiApiKey: null,
  ollamaPort: 11434, ollamaModel: 'llama3', warnBeforeExternalSend: true, defaultPorts: [3000],
};

describe('ModelRouter', () => {
  it('reports ollama as local (no external send) and configured', () => {
    const router = new ModelRouter(ollamaConfig);
    expect(router.sendsExternally).toBe(false);
    expect(router.isConfigured()).toBe(true);
  });

  it('claude without a key is not configured', () => {
    const prev = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    const router = new ModelRouter({ ...ollamaConfig, model: 'claude' });
    expect(router.isConfigured()).toBe(false);
    if (prev) process.env.ANTHROPIC_API_KEY = prev;
  });
});

describe('PromptBuilder', () => {
  it('never includes raw source and redacts the payload', () => {
    const report = fakeReport();
    const prompt = PromptBuilder.build(report);
    expect(prompt.user).toContain('findings');
    expect(prompt.user).not.toMatch(/function |require\(|=>/); // no code
  });
});

describe('ContextChunker', () => {
  it('trims findings to fit a tiny budget, keeping criticals first', () => {
    const report = fakeReport(50);
    report.findings[0] = makeFinding({
      rule: 'crit', title: 'Critical', severity: 'critical', category: 'security',
      source: 'static', description: 'd', recommendation: 'f',
    });
    const fitted = ContextChunker.fit(report, 50); // ~200 chars budget
    expect(fitted.findings.length).toBeLessThan(report.findings.length);
    expect(fitted.findings[0].severity).toBe('critical');
  });
});

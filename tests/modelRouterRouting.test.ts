import axios from 'axios';
import { ModelRouter } from '../src/ai/ModelRouter';
import { PromptBuilder } from '../src/ai/PromptBuilder';
import { ContextChunker } from '../src/ai/ContextChunker';
import { verifyAiFindings } from '../src/ai/verifyAiFindings';
import { makeFinding } from '../src/utils/finding';
import type { AppConfig, Finding, ScanReport } from '../src/types';

const FAKE_KEY = 'fake-test-key-not-real';

const base: AppConfig = {
  model: 'claude',
  claudeApiKey: FAKE_KEY,
  openaiApiKey: FAKE_KEY,
  ollamaPort: 11999,
  ollamaModel: 'tiny',
  warnBeforeExternalSend: true,
  defaultPorts: [3000],
  probeCommonPaths: false,
};

function finding(over: Partial<Finding> = {}): Finding {
  return makeFinding({
    rule: 'r', title: 'T', severity: 'warning', category: 'security', source: 'static',
    description: 'd', recommendation: 'fix it', file: 'a.js', line: 1, ...over,
  });
}

function report(findings: Finding[]): ScanReport {
  const stack = { stack: 'express' as const, language: 'javascript' as const, evidence: [] };
  return {
    target: '/tmp/app', startedAt: '', finishedAt: '', version: '0.0.0', stack,
    graph: { root: '/tmp/app', stack, entryPoints: ['index.js'], modules: [], routes: [], fileCount: 2 },
    findings, score: 80, summary: { critical: 0, warning: findings.length, info: 0, total: findings.length },
  };
}

let post: jest.SpyInstance;
const savedEnv = { a: process.env.ANTHROPIC_API_KEY, o: process.env.OPENAI_API_KEY };
beforeEach(() => {
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.OPENAI_API_KEY;
  post = jest.spyOn(axios, 'post');
});
afterEach(() => {
  jest.restoreAllMocks();
  if (savedEnv.a !== undefined) process.env.ANTHROPIC_API_KEY = savedEnv.a;
  if (savedEnv.o !== undefined) process.env.OPENAI_API_KEY = savedEnv.o;
});

describe('ModelRouter configuration flags', () => {
  it.each([
    ['claude', true],
    ['openai', true],
    ['ollama', false],
  ] as const)('%s: sendsExternally=%s', (model, external) => {
    expect(new ModelRouter({ ...base, model }).sendsExternally).toBe(external);
  });

  it('isConfigured is false for hosted models with a null key, true with a key', () => {
    expect(new ModelRouter({ ...base, model: 'claude', claudeApiKey: null }).isConfigured()).toBe(false);
    expect(new ModelRouter({ ...base, model: 'openai', openaiApiKey: null }).isConfigured()).toBe(false);
    expect(new ModelRouter({ ...base, model: 'claude' }).isConfigured()).toBe(true);
    expect(new ModelRouter({ ...base, model: 'openai' }).isConfigured()).toBe(true);
  });

  it('previewPayload equals the exact user prompt that would be sent', () => {
    const r = report([finding()]);
    expect(new ModelRouter(base).previewPayload(r)).toBe(PromptBuilder.build(r).user);
  });
});

describe('ModelRouter.analyze routing', () => {
  const aiJson = JSON.stringify({ summary: 'S', findings: [{ rule: 'x', title: 'X', severity: 'critical' }] });

  it('claude: calls the Anthropic endpoint with the configured key and returns parsed findings', async () => {
    post.mockResolvedValue({ data: { content: [{ type: 'text', text: aiJson }] } });
    const a = await new ModelRouter({ ...base, model: 'claude' }).analyze(report([finding()]));
    expect(post.mock.calls[0][0]).toContain('api.anthropic.com');
    expect(post.mock.calls[0][2].headers['x-api-key']).toBe(FAKE_KEY);
    expect(a.summary).toBe('S');
    expect(a.findings[0]).toMatchObject({ source: 'ai', unverified: true });
  });

  it('openai: calls the OpenAI endpoint', async () => {
    post.mockResolvedValue({ data: { choices: [{ message: { content: aiJson } }] } });
    const a = await new ModelRouter({ ...base, model: 'openai' }).analyze(report([]));
    expect(post.mock.calls[0][0]).toContain('api.openai.com');
    expect(a.findings).toHaveLength(1);
  });

  it('ollama: only talks to loopback on the configured port', async () => {
    post.mockResolvedValue({ data: { message: { content: aiJson } } });
    await new ModelRouter({ ...base, model: 'ollama' }).analyze(report([]));
    expect(post.mock.calls[0][0]).toBe('http://127.0.0.1:11999/api/chat');
  });

  it('never puts source code or evidence in the request: only the structured report is sent', async () => {
    post.mockResolvedValue({ data: { content: [{ type: 'text', text: '{}' }] } });
    const f = finding({ evidence: 'const secretValue = "LEAK-ME-12345"' });
    await new ModelRouter(base).analyze(report([f]));
    const sent = JSON.stringify(post.mock.calls[0][1]);
    expect(sent).not.toContain('LEAK-ME-12345');
    expect(sent).toContain('structured scan report');
  });

  it('claude without a key throws an actionable error and makes no request', async () => {
    await expect(new ModelRouter({ ...base, claudeApiKey: null }).analyze(report([]))).rejects.toThrow(/No Claude API key configured/);
    expect(post).not.toHaveBeenCalled();
  });

  it('openai without a key throws an actionable error and makes no request', async () => {
    await expect(new ModelRouter({ ...base, model: 'openai', openaiApiKey: null }).analyze(report([]))).rejects.toThrow(
      /No OpenAI API key configured/,
    );
    expect(post).not.toHaveBeenCalled();
  });

  it('an unknown model name is rejected', async () => {
    const bad = { ...base, model: 'gemini' } as unknown as AppConfig;
    await expect(new ModelRouter(bad).analyze(report([]))).rejects.toThrow('Unknown model: gemini');
  });

  it('propagates handler failures', async () => {
    post.mockRejectedValue(new Error('network down'));
    await expect(new ModelRouter(base).analyze(report([]))).rejects.toThrow('Claude API request failed: network down');
  });
});

describe('ModelRouter.suggestFix', () => {
  const f = finding({ title: 'Hardcoded secret', recommendation: 'Use an env var' });

  it('redacts the snippet before sending and returns the parsed fix', async () => {
    const snippet = 'const k = "sk-ant-' + 'a'.repeat(30) + '";';
    post.mockResolvedValue({ data: { content: [{ type: 'text', text: 'Use env.\n```js\nconst k = process.env.K;\n```' }] } });
    const fix = await new ModelRouter(base).suggestFix(f, snippet);
    expect(fix).toEqual({ explanation: 'Use env.', newCode: 'const k = process.env.K;' });
    const user = post.mock.calls[0][1].messages[0].content as string;
    expect(user).not.toContain('a'.repeat(30));
    expect(user).toContain('Hardcoded secret');
  });

  it('throws when the model returns nothing usable', async () => {
    post.mockResolvedValue({ data: { content: [{ type: 'text', text: 'I am unable to fix this.' }] } });
    await expect(new ModelRouter(base).suggestFix(f, 'x')).rejects.toThrow('The model did not return a usable fix.');
  });

  it('throws when the model returns an empty completion', async () => {
    post.mockResolvedValue({ data: { content: [] } });
    await expect(new ModelRouter(base).suggestFix(f, 'x')).rejects.toThrow('did not return a usable fix');
  });

  it('accepts the strict-JSON fallback format', async () => {
    post.mockResolvedValue({ data: { content: [{ type: 'text', text: '{"explanation":"e","newCode":"y"}' }] } });
    expect(await new ModelRouter(base).suggestFix(f, 'x')).toEqual({ explanation: 'e', newCode: 'y' });
  });
});

describe('PromptBuilder', () => {
  it('build() sends only structured fields, never description/evidence/recommendation text', () => {
    const f = finding({ evidence: 'EVIDENCE-TEXT', description: 'DESCRIPTION-TEXT', recommendation: 'RECOMMENDATION-TEXT' });
    const p = PromptBuilder.build(report([f]));
    expect(p.system).toContain('STRICT JSON');
    expect(p.user).not.toContain('EVIDENCE-TEXT');
    expect(p.user).not.toContain('DESCRIPTION-TEXT');
    expect(p.user).not.toContain('RECOMMENDATION-TEXT');
    const payload = JSON.parse(p.user.slice(p.user.indexOf('{')));
    expect(payload.architecture).toEqual({ entryPoints: ['index.js'], fileCount: 2, routeCount: 0 });
    expect(payload.findings[0]).toMatchObject({ rule: 'r', title: 'T', file: 'a.js' });
  });

  it('preview() is exactly build().user', () => {
    const r = report([finding()]);
    expect(PromptBuilder.preview(r)).toBe(PromptBuilder.build(r).user);
  });

  it('buildFixPrompt includes issue details and the snippet; omits OWASP when absent', () => {
    const p = PromptBuilder.buildFixPrompt(finding({ title: 'Bad thing', severity: 'critical' }), 'let a = 1;');
    expect(p.system).toContain('ONE issue');
    expect(p.user).toContain('Issue: Bad thing');
    expect(p.user).toContain('Severity: critical\n');
    expect(p.user).toContain('Recommendation: fix it');
    expect(p.user).toContain('let a = 1;');
  });

  it('buildFixPrompt appends the OWASP reference when present', () => {
    const p = PromptBuilder.buildFixPrompt(finding({ severity: 'warning', owasp: 'A02:2025' }), 'x');
    expect(p.user).toContain('Severity: warning (A02:2025)');
  });
});

describe('ContextChunker', () => {
  it('returns the same report object when it already fits', () => {
    const r = report([finding()]);
    expect(ContextChunker.fit(r, 100_000)).toBe(r);
  });

  it('orders kept findings critical > warning > info when trimming', () => {
    const fs = [
      finding({ rule: 'i', severity: 'info', line: 1 }),
      finding({ rule: 'w', severity: 'warning', line: 2 }),
      finding({ rule: 'c', severity: 'critical', line: 3 }),
    ];
    const one = JSON.stringify(fs[0]).length;
    const fitted = ContextChunker.fit(report(fs), Math.ceil((one * 2.5) / 4));
    expect(fitted.findings.map((x) => x.rule)).toEqual(['c', 'w']);
  });

  it('yields no findings when even one does not fit, and does not mutate the input', () => {
    const r = report([finding(), finding({ line: 2 })]);
    const fitted = ContextChunker.fit(r, 1);
    expect(fitted.findings).toEqual([]);
    expect(r.findings).toHaveLength(2);
  });
});

describe('verifyAiFindings with an unusable project root', () => {
  it('drops every AI finding that names a file when the root does not exist, keeps file-less ones', async () => {
    const r = await verifyAiFindings(
      [finding({ file: 'a.js', source: 'ai' }), finding({ rule: 'nofile', file: undefined, severity: 'critical', source: 'ai' })],
      '/definitely/not/a/real/dir-xyz',
    );
    expect(r.dropped).toBe(1);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ rule: 'nofile', severity: 'info', unverified: true, source: 'ai' });
    expect(r.findings[0].description).toContain('AI-suggested severity: critical.');
  });
});

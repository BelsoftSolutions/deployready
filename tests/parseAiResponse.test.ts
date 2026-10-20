import { parseAiResponse } from '../src/ai/parseAiResponse';

describe('parseAiResponse (untrusted model output)', () => {
  it('returns the trimmed text as summary when there is no JSON object', () => {
    expect(parseAiResponse('  just prose  ')).toEqual({ summary: 'just prose', findings: [] });
  });

  it('caps a non-JSON summary at 2000 chars', () => {
    expect(parseAiResponse('a'.repeat(5000)).summary).toHaveLength(2000);
  });

  it('returns an empty analysis for empty input', () => {
    expect(parseAiResponse('')).toEqual({ summary: '', findings: [] });
  });

  it('falls back to the raw text when the JSON is truncated', () => {
    const r = parseAiResponse('{"summary": "x", "findings": [');
    expect(r.findings).toEqual([]);
    expect(r.summary).toContain('"summary"');
  });

  it('falls back to the raw text when a balanced block is not valid JSON', () => {
    const r = parseAiResponse("{'summary': 'single quotes'}");
    expect(r.findings).toEqual([]);
    expect(r.summary).toBe("{'summary': 'single quotes'}");
  });

  it('extracts JSON embedded in prose and code fences', () => {
    const r = parseAiResponse('Sure!\n```json\n{"summary":"S","findings":[]}\n```\nHope that helps.');
    expect(r).toEqual({ summary: 'S', findings: [] });
  });

  it('handles nested braces inside the JSON', () => {
    const r = parseAiResponse('{"summary":"S","findings":[{"rule":"r","title":"t","extra":{"a":{"b":1}}}]}');
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].rule).toBe('r');
  });

  it('uses only the first JSON object when several are present', () => {
    const r = parseAiResponse('{"summary":"first","findings":[]} {"summary":"second","findings":[]}');
    expect(r.summary).toBe('first');
  });

  it('coerces a non-string summary and a non-array findings field to safe defaults', () => {
    expect(parseAiResponse('{"summary": 42, "findings": "nope"}')).toEqual({ summary: '', findings: [] });
  });

  it('skips non-object finding entries but keeps valid ones', () => {
    const r = parseAiResponse('{"summary":"","findings":[null,"str",7,{"title":"ok"}]}');
    expect(r.findings.map((f) => f.title)).toEqual(['ok']);
  });

  it('defaults invalid severity/category and wrongly-typed fields; always marks findings as unverified AI', () => {
    const r = parseAiResponse(
      JSON.stringify({ findings: [{ severity: 'catastrophic', category: 'vibes', rule: 5, title: null, description: {} }] }),
    );
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({
      rule: 'ai-finding',
      title: 'AI-identified issue',
      severity: 'info',
      category: 'security',
      source: 'ai',
      unverified: true,
      description: '',
      recommendation: '',
    });
    expect(r.findings[0].file).toBeUndefined();
    expect(r.findings[0].endpoint).toBeUndefined();
  });

  it('keeps valid optional fields and generates a stable id', () => {
    const raw = JSON.stringify({
      findings: [{ rule: 'r', title: 'T', severity: 'warning', category: 'performance', file: 'a.js', endpoint: '/x', owasp: 'A01:2025', cwe: 'CWE-1' }],
    });
    const [a] = parseAiResponse(raw).findings;
    const [b] = parseAiResponse(raw).findings;
    expect(a).toMatchObject({ severity: 'warning', category: 'performance', file: 'a.js', endpoint: '/x', owasp: 'A01:2025', cwe: 'CWE-1' });
    expect(a.id).toMatch(/^[0-9a-f]{12}$/);
    expect(a.id).toBe(b.id);
  });
});

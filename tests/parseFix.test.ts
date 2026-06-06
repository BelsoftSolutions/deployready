import { extractFix } from '../src/ai/parseFix';

describe('extractFix', () => {
  it('parses a fenced code block with a preceding explanation', () => {
    const reply = 'This replaces eval with JSON.parse.\n```js\nconst x = JSON.parse(input);\nreturn x;\n```';
    const r = extractFix(reply)!;
    expect(r.newCode).toBe('const x = JSON.parse(input);\nreturn x;');
    expect(r.explanation).toMatch(/replaces eval/);
  });

  it('handles code with literal newlines/quotes that would break JSON', () => {
    const reply = '```\nrouter.post("/login", limiter, (req, res) => {\n  res.send("ok");\n});\n```';
    const r = extractFix(reply)!;
    expect(r.newCode).toContain('limiter');
    expect(r.newCode).toContain('res.send("ok")');
  });

  it('falls back to JSON when no fence is present', () => {
    const reply = '{"explanation":"use param query","newCode":"db.query(sql,[id])"}';
    const r = extractFix(reply)!;
    expect(r.newCode).toBe('db.query(sql,[id])');
    expect(r.explanation).toBe('use param query');
  });

  it('returns null when nothing usable is found', () => {
    expect(extractFix('I cannot help with that.')).toBeNull();
  });
});

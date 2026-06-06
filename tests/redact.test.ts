import { redact, redactObject, containsSecret } from '../src/utils/redact';

describe('redact', () => {
  it('redacts Anthropic-style keys', () => {
    const s = 'key = sk-ant-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345';
    expect(redact(s)).not.toContain('sk-ant-aBcDeFgHiJkLmNoPqRsTuVwXyZ');
    expect(redact(s)).toContain('«REDACTED»');
  });

  it('redacts AWS access keys', () => {
    expect(redact('AKIAIOSFODNN7EXAMPLE')).toContain('«REDACTED»');
  });

  it('redacts secret-named assignments', () => {
    const out = redact('const apiKey = "abcd1234efgh5678"');
    expect(out).toContain('«REDACTED»');
    expect(out).not.toContain('abcd1234efgh5678');
  });

  it('leaves benign text untouched', () => {
    const s = 'const total = price + tax;';
    expect(redact(s)).toBe(s);
  });

  it('detects secrets via containsSecret', () => {
    expect(containsSecret('AKIAIOSFODNN7EXAMPLE')).toBe(true);
    expect(containsSecret('just some code')).toBe(false);
  });

  it('drops secret-named object keys entirely', () => {
    const obj = redactObject({ password: 'p@ss', nested: { token: 'abc' }, keep: 'me' });
    expect(obj.password).toBe('«REDACTED»');
    expect(obj.nested.token).toBe('«REDACTED»');
    expect(obj.keep).toBe('me');
  });
});

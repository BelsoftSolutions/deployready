/**
 * Redaction primitive + detection tiers. Includes the 10 audit samples against 0.4.0
 * (5 were redacted, 5 were missed or partial); all 10 must be fully redacted now.
 * Values are assembled at runtime so the repo itself holds no scanner-tripping literal.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { containsSecret, detectSecret, redact, redactDeep, redactObject } from '../../src/utils/redact';
import { detectSecrets, gitleaksToFindings, isPlaceholder, parseGitleaksReport, runGitleaks, findGitleaks } from '../../src/secrets';
import { VulnerabilityDetector } from '../../src/analysis/VulnerabilityDetector';

const j = (...p: string[]): string => p.join('');
const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload: Record<string, unknown>): string => [b64url({ alg: 'HS256' }), b64url(payload), 'c2lnbmF0dXJlLWNhbmFyeS0xMjM0NTY'].join('.');

describe('audit samples (10 synthetic credentials)', () => {
  const pw = j('hunter2', 'Qx9zLm');
  const samples: { name: string; text: string; secret: string[] }[] = [
    { name: 'password assignment', text: `password = "${pw}"`, secret: [pw] },
    { name: 'password in structured object', text: JSON.stringify(redactObject({ password: pw })), secret: [pw] },
    { name: 'OpenAI-shaped key', text: j('k=sk-', 'proj-', 'A1b2C3d4E5f6G7h8I9j0K1l2'), secret: ['A1b2C3d4E5f6G7h8I9j0K1l2'] },
    { name: 'Bearer token', text: j('Authorization: Bearer ', 'abcDEF123456ghiJKL7890mn'), secret: ['abcDEF123456ghiJKL7890mn'] },
    { name: 'DB connection string', text: j('postgres://admin:', 'S3cr3tPw', '@db.example.com/app'), secret: ['S3cr3tPw'] },
    { name: 'password inside raw JSON text', text: `{"password":"${pw}"}`, secret: [pw] },
    { name: 'Supabase secret key', text: j('const k = "sb_', 'secret_', 'AbCdEf1234567890GhIjKl_mn"'), secret: ['AbCdEf1234567890GhIjKl'] },
    {
      name: 'GitHub fine-grained PAT',
      text: j('GH=github', '_pat_', '11ABCDEFG0123456789_', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV'),
      secret: ['abcdefghijklmnopqrstuvwxyz0123'],
    },
    {
      name: 'multiline private key',
      text: j('-----BEGIN ', 'RSA PRIVATE KEY-----\n', 'MIIEowIBAAKCAQEAuZ9x7Kq3mNp2LrT8sVwY4zH6jQe1\n', 'dF5gH7jK9lM2nP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2\n', '-----END RSA ', 'PRIVATE KEY-----'),
      secret: ['MIIEowIBAAKCAQEAuZ9x7Kq3mNp2', 'dF5gH7jK9lM2nP4qR6sT8u'],
    },
    {
      name: 'passwords starting with placeholder-like words',
      text: ['password = "test-Xy9!' + 'realPw42"', 'password = "demo' + 'Q7zR!x81"', 'password = "example' + 'Kp3$Tz9"'].join('\n'),
      secret: ['test-Xy9!', 'demoQ7zR', 'exampleKp3'],
    },
  ];
  it.each(samples)('$name is fully redacted', ({ text, secret }) => {
    const out = redact(text);
    for (const s of secret) expect(out).not.toContain(s);
    expect(out).toContain('«REDACTED»');
  });
});

describe('redaction policy', () => {
  it('keeps clear placeholders and env references readable (whole value only)', () => {
    for (const v of ['changeme', 'your-key-here', '<YOUR_TOKEN>', 'xxxxxxxx', 'example', '', '${API_KEY}', 'process.env.API_KEY', '${{ secrets.DB_PASSWORD }}']) {
      expect({ v, placeholder: isPlaceholder(v) }).toEqual({ v, placeholder: true });
    }
    for (const v of ['test-Xy9!realPw42', 'demoQ7zR!x81', 'example-Kp3$Tz9', 'sample_9f8e7d6c']) {
      expect({ v, placeholder: isPlaceholder(v) }).toEqual({ v, placeholder: false });
    }
    expect(redact('password = "changeme"')).toBe('password = "changeme"');
    expect(redact('API_KEY=${API_KEY}')).toBe('API_KEY=${API_KEY}');
  });

  it('leaves ordinary code untouched', () => {
    for (const s of [
      'const total = price + tax;',
      'headers: { Authorization: `Bearer ${token}` }',
      "headers: { Authorization: 'Bearer ' + token }",
      'const token = req.headers.authorization;',
      'password: z.string().min(8),',
      'const { password } = req.body;',
      'tokenStorage: "localStorage",',
      'max_tokens: 4096,',
      'author: "Jane Doe",',
      'def login(token: str = Depends(oauth2)):',
      'curl -i --oauth2-bearer "$TOKEN" https://x.test/api',
      'Basic authentication is supported',
    ]) {
      expect(redact(s)).toBe(s);
    }
  });

  it('covers YAML, TOML, .env, query strings, headers and cookies', () => {
    const v = j('Zq', '9xLmP2vR7tWk');
    const cases = [
      `db_password: ${v}`,
      `api_token = "${v}"`,
      `SECRET_KEY=${v}`,
      `https://api.test/x?token=${v}&page=2`,
      `https://api.test/x?a=1&password=${v}`,
      `Cookie: session=${v}; theme=dark`,
      `Set-Cookie: sid=${v}; Path=/; HttpOnly`,
      `X-Api-Key: ${v}`,
      `redis://:${v}@cache:6379`,
      `amqp://user:${v}@mq:5672`,
      `Authorization: Basic ${Buffer.from(`admin:${v}`).toString('base64')}`,
    ];
    for (const c of cases) expect({ c, out: redact(c).includes(v) || redact(c).includes(Buffer.from(`admin:${v}`).toString('base64')) }).toEqual({ c, out: false });
    expect(redact(`Set-Cookie: sid=${v}; Path=/; HttpOnly`)).toContain('Path=/; HttpOnly');
  });

  it('redacts escaped one-line private keys (service-account JSON) and keeps line count', () => {
    const body = j('MIIEvQIBADANBgkqhkiG9w0BAQEFAASC', 'BKcwggSjAgEAAoIBAQC7');
    const json = `{"private_key": "-----BEGIN PRIVATE KEY-----\\n${body}\\n-----END PRIVATE KEY-----\\n"}`;
    expect(redact(json)).not.toContain(body);
    const multi = `a\n-----BEGIN OPENSSH PRIVATE KEY-----\n${body}\n${body}\n-----END OPENSSH PRIVATE KEY-----\nb`;
    const out = redact(multi);
    expect(out).not.toContain(body);
    expect(out.split('\n')).toHaveLength(multi.split('\n').length);
    expect(out.startsWith('a\n') && out.endsWith('\nb')).toBe(true);
  });

  it('redacts an unterminated key block without swallowing following code', () => {
    const body = j('MIIEvQIBADANBgkqhkiG9w0BAQEFAASC', 'BKcwggSjAgEAAoIBAQC7');
    const out = redact(`-----BEGIN PRIVATE KEY-----\n${body}\nconst x = 1;`);
    expect(out).not.toContain(body);
    expect(out).toContain('const x = 1;');
    expect(redact("if (pem.startsWith('-----BEGIN PRIVATE KEY-----')) {\n  ok();\n}")).toContain('ok();');
  });

  it('is idempotent', () => {
    const s = j('token = "', 'ghp_', 'A'.repeat(36), '"\npassword: hunter2xyz');
    expect(redact(redact(s))).toBe(redact(s));
  });

  it('redactDeep masks secret-named keys and strings but keeps the shape', () => {
    const out = redactDeep({ password: j('pw', 'Z9x!q'), nested: { text: j('sk_', 'live_', 'a1B2c3D4e5F6g7H8i9J0k1L2') }, keep: 'me', count: 3, placeholder: { token: 'changeme' } });
    expect(out).toEqual({ password: '«REDACTED»', nested: { text: '«REDACTED»' }, keep: 'me', count: 3, placeholder: { token: 'changeme' } });
  });

  it('containsSecret still works', () => {
    expect(containsSecret(j('AK', 'IAIOSFODNN7EXAMPLE'))).toBe(true);
    expect(containsSecret('just some code')).toBe(false);
  });
});

describe('detection tiers', () => {
  const ids = (s: string) => detectSecrets(s).map((h) => `${h.id}:${h.confidence}`);

  it('known shapes are high confidence', () => {
    expect(detectSecret(j('sb_', 'secret_', 'AbCdEf1234567890GhIjKl'))).toBe('high');
    expect(detectSecret(j('github', '_pat_', '11ABCDEFG0123456789_abcdefghijklmnop'))).toBe('high');
    for (const p of ['ghp', 'gho', 'ghu', 'ghs', 'ghr']) expect(detectSecret(j(p, '_', 'a1B2'.repeat(9)))).toBe('high');
    expect(detectSecret(j('wh', 'sec_', 'a1B2'.repeat(8)))).toBe('high');
    expect(detectSecret(j('rk', '_live_', 'a1B2'.repeat(6)))).toBe('high');
    expect(detectSecret(j('aws_secret_access_key = ', 'wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYzzzzzzzzzz'))).toBe('high');
    expect(detectSecret(`AccountKey=${'a1B2'.repeat(22)}==;`)).toBe('high');
    expect(detectSecret(j('postgres://app:', 'S3cr3t!x', '@db:5432/app'))).toBe('high');
    expect(detectSecret(j('-----BEGIN EC ', 'PRIVATE KEY-----'))).toBe('high');
  });

  it('public keys are not secrets', () => {
    expect(detectSecret(j('const k = "sb_', 'publishable_', 'AbCdEf1234567890GhIjKl"'))).toBeNull();
    expect(detectSecret(j('pk', '_live_', 'a1B2'.repeat(6)))).toBeNull();
    expect(detectSecret(`const anon = "${jwt({ role: 'anon', ref: 'abcdefghijklmnopqrst' })}"`)).toBeNull();
    expect(ids(`const k = "${jwt({ role: 'service_role', ref: 'abcdefghijklmnopqrst' })}"`)).toContain('supabase-service-role-jwt:high');
  });

  it('secret-named literals are low; placeholders and config words are not secrets', () => {
    expect(detectSecret('password = "test-Xy9!realPw42"')).toBe('low');
    expect(detectSecret('{"password":"hunter2Qx9zLm"}')).toBe('low');
    expect(detectSecret('password = "changeme"')).toBeNull();
    expect(detectSecret('token_type = "bearer"')).toBeNull();
    expect(detectSecret('postgres://postgres:password@localhost/db')).toBeNull();
    expect(ids(`api_key = "${j('aZ3kQ9wE7rT1yU5iO2pL', '8sD4fG6hJ0zXcVbNm')}"`)).toEqual(['generic-high-entropy:low']);
  });

  it('flags a hardcoded secret in a config / key file (secret-only scan)', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-secret-files-'));
    fs.writeFileSync(path.join(root, 'app.yml'), j('slack: xo', 'xb-1234567890-9876543210-', 'abcdefghijklmnopqrstuv\n'));
    fs.writeFileSync(path.join(root, 'package-lock.json'), j('{"t":"sk_', 'live_', 'a1B2c3D4e5F6g7H8i9J0k1L2"}'));
    fs.writeFileSync(path.join(root, 'local.json'), '{"password":"devpass123"}');
    const findings = await VulnerabilityDetector.scan(root);
    expect(findings.map((f) => `${f.file}:${f.rule}`)).toEqual(['app.yml:hardcoded-secret']);
    expect(findings[0]!.evidence).not.toContain('abcdefghijklmnop');
  });
});

describe('optional Gitleaks adapter', () => {
  it('is not used when the binary is absent or disabled', async () => {
    expect(findGitleaks({ PATH: '' })).toBeNull();
    expect(findGitleaks({ PATH: process.env.PATH, DEPLOYREADY_GITLEAKS: '0' })).toBeNull();
    expect(await runGitleaks('.', null)).toEqual([]);
  });

  it('parses a report, confines paths and never carries the secret', () => {
    const report = JSON.stringify([
      { RuleID: 'aws-access-token', Description: 'AWS', File: '/proj/src/a.ts', StartLine: 3, Secret: 'REDACTED', Match: 'REDACTED' },
      { RuleID: 'generic-api-key', File: 'src/b.ts', StartLine: 7 },
      { RuleID: 'x', File: '/elsewhere/c.ts', StartLine: 1 },
    ]);
    const hits = parseGitleaksReport(report, '/proj');
    expect(hits.map((h) => `${h.file}:${h.line}`)).toEqual(['src/a.ts:3', 'src/b.ts:7']);
    const existing = [{ id: 'x', rule: 'hardcoded-secret', title: '', severity: 'critical', category: 'security', source: 'static', file: 'src/a.ts', line: 3, description: '', recommendation: '' }] as never;
    const merged = gitleaksToFindings(hits, existing);
    expect(merged.map((f) => `${f.rule}:${f.severity}:${f.file}`)).toEqual(['possible-hardcoded-secret:warning:src/b.ts']);
    expect(JSON.stringify(merged)).not.toContain('REDACTED');
  });

  it('runs a gitleaks found on PATH and merges its hits', async () => {
    if (process.platform === 'win32') return;
    const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-fake-gitleaks-'));
    const script = path.join(bin, 'gitleaks');
    // Fake binary: writes a report to the --report-path it is given.
    fs.writeFileSync(
      script,
      '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "--report-path" ]; then shift; printf \'[{"RuleID":"stripe-access-token","File":"pay.ts","StartLine":2}]\' > "$1"; fi; shift; done\n',
    );
    fs.chmodSync(script, 0o755);
    expect(findGitleaks({ PATH: bin })).toBe(script);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-gl-proj-'));
    const hits = await runGitleaks(root, script);
    expect(hits).toEqual([{ ruleId: 'stripe-access-token', description: '', file: 'pay.ts', line: 2 }]);
  });
});

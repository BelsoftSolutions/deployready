import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { compareToBaseline, fingerprint, gatedFindings, parseBaseline, serializeBaseline, shouldFail, summarize } from '../src/core/CiGate';
import { clearFingerprintCache, fingerprintAll, normalizeContext } from '../src/core/baselineFingerprint';
import { makeFinding } from '../src/utils/finding';
import type { Finding } from '../src/types';

let root: string;
const write = (file: string, body: string): void => {
  fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
  fs.writeFileSync(path.join(root, file), body);
  clearFingerprintCache();
};
const mk = (over: Partial<Finding>): Finding =>
  makeFinding({
    rule: 'hardcoded-secret', title: 't', severity: 'critical', category: 'security', source: 'static',
    description: '', recommendation: '', file: 'src/a.js', line: 1, ...over,
  });
const NOW = new Date('2026-06-01T00:00:00Z');
const cmp = (fs_: Finding[], body: string, now = NOW) => compareToBaseline(fs_, parseBaseline(body), { root, now });

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-baseline-'));
  clearFingerprintCache();
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

describe('reproduction of the 0.4.0 identity bugs (legacy fingerprint)', () => {
  it('legacy identity collides for two secrets in one file', () => {
    expect(fingerprint(mk({ line: 1 }))).toBe(fingerprint(mk({ line: 9 })));
  });
  it('legacy identity ignores severity', () => {
    expect(fingerprint(mk({ severity: 'warning' }))).toBe(fingerprint(mk({ severity: 'critical' })));
  });
});

describe('baseline v2', () => {
  const SRC = "function a() {\n  const k = 'sk_live_AAAAAAAAAAAA';\n}\n";

  it('a moved issue stays known', () => {
    write('src/a.js', SRC);
    const body = serializeBaseline([mk({ line: 2 })], { root, now: NOW });
    write('src/a.js', '// header\n// more\n' + SRC);
    const c = cmp([mk({ line: 4 })], body);
    expect(c.known).toHaveLength(1);
    expect(gatedFindings(c)).toHaveLength(0);
  });

  it('a new secret in a different file is new', () => {
    write('src/a.js', SRC);
    write('src/b.js', SRC);
    const body = serializeBaseline([mk({ line: 2 })], { root, now: NOW });
    const c = cmp([mk({ line: 2 }), mk({ file: 'src/b.js', line: 2 })], body);
    expect(c.new).toHaveLength(1);
  });

  it('a second independent secret in the SAME file is new', () => {
    write('src/a.js', SRC);
    const body = serializeBaseline([mk({ line: 2 })], { root, now: NOW });
    write('src/a.js', SRC + "function b() {\n  const t = 'whsec_BBBBBBBBBBBBBBBBBBBB';\n}\n");
    const c = cmp([mk({ line: 2 }), mk({ line: 5 })], body);
    expect(c.known).toHaveLength(1);
    expect(c.new).toHaveLength(1);
    expect(shouldFail(summarize(gatedFindings(c)), 'critical')).toBe(true);
  });

  it('identical lines in one file get distinct fingerprints', () => {
    write('src/a.js', "x('sk_live_AAAAAAAAAAAA');\nx('sk_live_AAAAAAAAAAAA');\n");
    const fps = fingerprintAll([mk({ line: 1 }), mk({ line: 2 })], root).map((x) => x.fingerprint);
    expect(new Set(fps).size).toBe(2);
  });

  it('an escalation (warning -> critical) is reported and gates', () => {
    write('src/a.js', SRC);
    const body = serializeBaseline([mk({ line: 2, severity: 'warning' })], { root, now: NOW });
    const c = cmp([mk({ line: 2, severity: 'critical' })], body);
    expect(c.escalated).toHaveLength(1);
    expect(c.escalated[0].was).toBe('warning');
    expect(shouldFail(summarize(gatedFindings(c)), 'critical')).toBe(true);
  });

  it('a de-escalation stays known', () => {
    write('src/a.js', SRC);
    const body = serializeBaseline([mk({ line: 2 })], { root, now: NOW });
    expect(cmp([mk({ line: 2, severity: 'warning' })], body).known).toHaveLength(1);
  });

  it('a resolved finding that reappears is reopened and gates until re-accepted', () => {
    write('src/a.js', SRC);
    const f1 = [mk({ line: 2 })];
    const v1 = serializeBaseline(f1, { root, now: NOW });
    const v2 = serializeBaseline([], { root, previous: parseBaseline(v1), now: NOW });
    expect(JSON.parse(v2).entries[0].resolvedAt).toBe('2026-06-01');
    const c = cmp(f1, v2);
    expect(c.reopened).toHaveLength(1);
    expect(c.stale).toHaveLength(0);
    expect(gatedFindings(c)).toHaveLength(1);
    const v3 = serializeBaseline(f1, { root, previous: parseBaseline(v2), now: NOW });
    expect(cmp(f1, v3).known).toHaveLength(1);
  });

  it('expired entries no longer suppress', () => {
    write('src/a.js', SRC);
    const body = JSON.parse(serializeBaseline([mk({ line: 2 })], { root, now: NOW }));
    body.entries[0].expiresAt = '2026-05-31';
    const c = cmp([mk({ line: 2 })], JSON.stringify(body));
    expect(c.expired).toHaveLength(1);
    expect(gatedFindings(c)).toHaveLength(1);
    body.entries[0].expiresAt = '2026-06-01';
    expect(cmp([mk({ line: 2 })], JSON.stringify(body)).known).toHaveLength(1);
  });

  it('stale suppressions are reported', () => {
    write('src/a.js', SRC);
    const body = serializeBaseline([mk({ line: 2 })], { root, now: NOW });
    const c = cmp([], body);
    expect(c.stale).toHaveLength(1);
  });

  it('--write-baseline keeps reason/owner/acceptedAt and output is stable and sorted', () => {
    write('src/a.js', SRC);
    write('src/b.js', SRC);
    const fs_ = [mk({ file: 'src/b.js', line: 2 }), mk({ line: 2 })];
    const first = JSON.parse(serializeBaseline(fs_, { root, now: NOW }));
    expect(first.entries.map((e: { file: string }) => e.file)).toEqual(['src/a.js', 'src/b.js']);
    first.entries[0].reason = 'legacy, tracked in JIRA-1';
    first.entries[0].owner = 'alice';
    const again = serializeBaseline(fs_, { root, previous: parseBaseline(JSON.stringify(first)), now: new Date('2026-07-01T00:00:00Z') });
    const parsed = JSON.parse(again);
    expect(parsed.entries[0]).toMatchObject({ reason: 'legacy, tracked in JIRA-1', owner: 'alice', acceptedAt: '2026-06-01' });
    expect(serializeBaseline(fs_.slice().reverse(), { root, previous: parseBaseline(again), now: NOW })).toBe(again);
  });

  it('never stores source text, secrets or secret hashes', () => {
    write('src/a.js', SRC);
    const body = serializeBaseline([mk({ line: 2 })], { root, now: NOW });
    expect(body).not.toContain('sk_live');
    expect(normalizeContext("const k = 'sk_live_AAAAAAAAAAAA';")).toBe("const k = 'S32';");
    // changing only the secret's value (same length class) keeps identity
    write('src/a.js', SRC.replace('AAAAAAAAAAAA', 'CCCCCCCCCCCC'));
    expect(cmp([mk({ line: 2 })], body).known).toHaveLength(1);
  });

  it('reads v1 baselines with a migration warning', () => {
    write('src/a.js', SRC);
    const v1 = JSON.stringify({ format: 'deployready-baseline/1', fingerprints: [fingerprint(mk({}))] });
    const c = cmp([mk({ line: 2 })], v1);
    expect(c.known).toHaveLength(1);
    expect(c.warnings[0]).toMatch(/v1/);
    // migrating keeps working and drops the warning
    const v2 = serializeBaseline([mk({ line: 2 })], { root, previous: parseBaseline(v1), now: NOW });
    expect(cmp([mk({ line: 2 })], v2).warnings).toHaveLength(0);
  });
});

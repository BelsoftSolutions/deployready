import {
  parseFailOn,
  shouldFail,
  toCiJson,
  EXIT,
  fingerprint,
  serializeBaseline,
  readBaseline,
  newFindings,
  summarize,
} from '../src/core/CiGate';
import { makeFinding } from '../src/utils/finding';
import type { Finding, ScanReport } from '../src/types';

const summary = (critical: number, warning: number, info: number) => ({
  critical,
  warning,
  info,
  total: critical + warning + info,
});

describe('parseFailOn', () => {
  it('accepts valid values case-insensitively', () => {
    expect(parseFailOn('CRITICAL')).toBe('critical');
    expect(parseFailOn('none')).toBe('none');
  });
  it('rejects invalid values', () => {
    expect(() => parseFailOn('high')).toThrow(/Invalid --fail-on/);
  });
});

describe('shouldFail', () => {
  it('critical: fails only when criticals exist', () => {
    expect(shouldFail(summary(1, 0, 0), 'critical')).toBe(true);
    expect(shouldFail(summary(0, 9, 9), 'critical')).toBe(false);
  });
  it('warning: fails on critical or warning', () => {
    expect(shouldFail(summary(0, 1, 0), 'warning')).toBe(true);
    expect(shouldFail(summary(0, 0, 5), 'warning')).toBe(false);
  });
  it('info: fails on any finding', () => {
    expect(shouldFail(summary(0, 0, 1), 'info')).toBe(true);
    expect(shouldFail(summary(0, 0, 0), 'info')).toBe(false);
  });
  it('none: never fails', () => {
    expect(shouldFail(summary(9, 9, 9), 'none')).toBe(false);
  });
});

describe('toCiJson', () => {
  it('produces a passed flag and lean findings', () => {
    const report = {
      target: '/app', startedAt: '', finishedAt: '', version: '0.1.0',
      stack: { stack: 'express', language: 'javascript', evidence: [] },
      graph: { root: '/app', stack: { stack: 'express', language: 'javascript', evidence: [] }, entryPoints: [], modules: [], routes: [], fileCount: 1 },
      findings: [{ id: 'a', rule: 'r', title: 't', severity: 'critical', category: 'security', source: 'static', description: 'd', recommendation: 'f' }],
      score: 80, summary: summary(1, 0, 0),
    } as ScanReport;
    const json = toCiJson(report, 'critical') as { passed: boolean; findings: unknown[]; tool: string };
    expect(json.tool).toBe('deployready');
    expect(json.passed).toBe(false);
    expect(json.findings).toHaveLength(1);
  });
});

describe('EXIT codes', () => {
  it('uses 0/1/2', () => {
    expect(EXIT).toEqual({ OK: 0, ERROR: 1, GATE: 2 });
  });
});

describe('baseline', () => {
  const f = (over: Partial<Finding>): Finding =>
    makeFinding({
      rule: 'sql-injection', title: 't', severity: 'critical', category: 'security',
      source: 'static', description: '', recommendation: '', file: 'a.js', line: 10, ...over,
    });

  it('fingerprint ignores the line number (resilient to code drift)', () => {
    expect(fingerprint(f({ line: 10 }))).toBe(fingerprint(f({ line: 42 })));
    expect(fingerprint(f({ file: 'a.js' }))).not.toBe(fingerprint(f({ file: 'b.js' })));
  });

  it('serialize -> read round-trips the fingerprint set', () => {
    const findings = [f({ file: 'a.js' }), f({ file: 'b.js', rule: 'eval-usage' })];
    const set = readBaseline(serializeBaseline(findings));
    expect(set.has(fingerprint(findings[0]))).toBe(true);
    expect(set.has(fingerprint(findings[1]))).toBe(true);
    expect(set.size).toBe(2);
  });

  it('newFindings returns only findings absent from the baseline', () => {
    const known = f({ file: 'a.js' });
    const fresh = f({ file: 'c.js', rule: 'cors-wildcard', severity: 'warning' });
    const baseline = readBaseline(serializeBaseline([known]));
    const result = newFindings([known, fresh], baseline);
    expect(result).toHaveLength(1);
    expect(result[0].file).toBe('c.js');
  });

  it('a known finding that moved lines still counts as known', () => {
    const baseline = readBaseline(serializeBaseline([f({ line: 10 })]));
    expect(newFindings([f({ line: 99 })], baseline)).toHaveLength(0);
  });

  it('summarize recomputes a severity breakdown for a finding subset', () => {
    const s = summarize([f({ severity: 'critical', file: 'a.js' }), f({ severity: 'warning', file: 'b.js' })]);
    expect(s).toEqual({ critical: 1, warning: 1, info: 0, total: 2 });
  });

  it('readBaseline tolerates an empty/garbage file by returning an empty set', () => {
    expect(readBaseline('').size).toBe(0);
    expect(readBaseline('not json').size).toBe(0);
  });
});

import { parseFailOn, shouldFail, toCiJson, EXIT } from '../src/core/CiGate';
import type { ScanReport } from '../src/types';

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

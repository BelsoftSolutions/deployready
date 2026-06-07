import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { IssueAggregator } from '../src/analysis/IssueAggregator';
import { ScoreCalculator } from '../src/analysis/ScoreCalculator';
import { makeFinding } from '../src/utils/finding';

const SAMPLE = path.join(__dirname, 'sample-app');

describe('VulnerabilityDetector', () => {
  it('finds the planted vulnerabilities in the sample app', async () => {
    const findings = await VulnerabilityDetector.scan(SAMPLE);
    const rules = new Set(findings.map((f) => f.rule));
    expect(rules.has('hardcoded-secret')).toBe(true);
    expect(rules.has('sql-injection')).toBe(true);
    expect(rules.has('eval-usage')).toBe(true);
    expect(rules.has('cors-wildcard')).toBe(true);
    expect(rules.has('env-not-ignored')).toBe(true);
  });

  it('does NOT flag env-not-ignored when .env is gitignored', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'er-env-'));
    fs.writeFileSync(path.join(dir, '.env'), 'API_TOKEN=abc123def456ghi789');
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules\n.env\n');
    const findings = await VulnerabilityDetector.scan(dir);
    expect(findings.some((f) => f.rule === 'env-not-ignored')).toBe(false);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe('ScoreCalculator', () => {
  it('is 100 only when fully clean', () => {
    expect(ScoreCalculator.calculate({ critical: 0, warning: 0, info: 0, total: 0 })).toBe(100);
  });

  it('weighted decay: penalty 33 → ~48', () => {
    const summary = { critical: 2, warning: 3, info: 4, total: 9 };
    // penalty = 2*10 + 3*3 + 4*1 = 33 ; 100*30/(30+33) = 47.6 → 48
    expect(ScoreCalculator.calculate(summary)).toBe(48);
  });

  it('stays positive under heavy load and rises as issues are resolved', () => {
    const heavy = ScoreCalculator.calculate({ critical: 10, warning: 0, info: 0, total: 10 });
    const lighter = ScoreCalculator.calculate({ critical: 3, warning: 0, info: 0, total: 3 });
    expect(heavy).toBeGreaterThan(0); // never stuck at a flat 0
    expect(lighter).toBeGreaterThan(heavy); // fixing issues moves the number up
  });
});

describe('IssueAggregator', () => {
  it('deduplicates identical findings and sorts by severity', () => {
    const a = makeFinding({
      rule: 'x', title: 't', severity: 'warning', category: 'security',
      source: 'static', description: '', recommendation: '', file: 'a.js', line: 1,
    });
    const b = makeFinding({
      rule: 'x', title: 't', severity: 'warning', category: 'security',
      source: 'static', description: '', recommendation: '', file: 'a.js', line: 1,
    });
    const crit = makeFinding({
      rule: 'y', title: 'c', severity: 'critical', category: 'security',
      source: 'static', description: '', recommendation: '',
    });
    const res = IssueAggregator.process([a, b], [crit]);
    expect(res.findings).toHaveLength(2);
    expect(res.findings[0].severity).toBe('critical');
  });

  it('prefers dynamic source over ai on dedup', () => {
    const base = {
      rule: 'r', title: 't', severity: 'warning' as const, category: 'security' as const,
      description: '', recommendation: '', endpoint: '/x',
    };
    const ai = makeFinding({ ...base, source: 'ai' });
    const dyn = makeFinding({ ...base, source: 'dynamic' });
    const res = IssueAggregator.process([ai], [dyn]);
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].source).toBe('dynamic');
  });
});

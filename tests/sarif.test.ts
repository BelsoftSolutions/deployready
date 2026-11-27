import { toSarif } from '../src/ui/Sarif';
import type { Finding, ScanReport } from '../src/types';

function f(over: Partial<Finding>): Finding {
  return {
    id: 'x', rule: 'hardcoded-secret', title: 'Hardcoded secret', severity: 'critical', category: 'security',
    source: 'static', description: 'A secret is in source.', recommendation: 'Move it to env.', ...over,
  };
}
const report = (findings: Finding[]) => ({ findings } as unknown as ScanReport);

describe('toSarif', () => {
  const log = toSarif(
    report([
      f({ file: 'src\\a.ts', line: 12, cwe: 'CWE-798', owasp: 'A07:2025', evidence: 'sk-****' }),
      f({ file: 'src/b.ts', severity: 'warning', rule: 'cors-wildcard', title: 'CORS' }),
      f({ endpoint: 'GET /admin', rule: 'open-admin' }),
      f({ file: 'c.ts', unverified: true, rule: 'ai-guess' }),
      f({ file: 'd.ts', note: true, rule: 'a-note' }),
    ]),
    '9.9.9',
  );
  const run = log.runs[0] as any;

  it('has SARIF 2.1.0 envelope and tool driver', () => {
    expect(log.version).toBe('2.1.0');
    expect(log.$schema).toContain('sarif-2.1.0');
    expect(run.tool.driver.name).toBe('DeployReady');
    expect(run.tool.driver.version).toBe('9.9.9');
  });

  it('emits one rule per id with help, tags and security-severity', () => {
    const ids = run.tool.driver.rules.map((r: any) => r.id);
    expect(ids).toEqual(['cors-wildcard', 'hardcoded-secret']);
    const r = run.tool.driver.rules[1];
    expect(r.help.text).toBe('Move it to env.');
    expect(r.properties.tags).toEqual(expect.arrayContaining(['external/cwe/cwe-798', 'external/owasp/A07:2025']));
    expect(r.properties['security-severity']).toBe('9.0');
  });

  it('results carry normalized file/line regions and valid ruleIndex', () => {
    expect(run.results).toHaveLength(2);
    const a = run.results.find((x: any) => x.ruleId === 'hardcoded-secret');
    expect(a.level).toBe('error');
    expect(a.locations[0].physicalLocation.artifactLocation.uri).toBe('src/a.ts');
    expect(a.locations[0].physicalLocation.region.startLine).toBe(12);
    expect(run.tool.driver.rules[a.ruleIndex].id).toBe('hardcoded-secret');
    expect(a.message.text).toContain('sk-****');
    const b = run.results.find((x: any) => x.ruleId === 'cors-wildcard');
    expect(b.locations[0].physicalLocation.region.startLine).toBe(1);
  });

  it('skips file-less, unverified and note findings, noting only the file-less one', () => {
    const notes = run.invocations[0].toolExecutionNotifications;
    expect(notes).toHaveLength(1);
    expect(notes[0].message.text).toContain('open-admin');
    expect(JSON.stringify(log)).not.toContain('ai-guess');
  });
});

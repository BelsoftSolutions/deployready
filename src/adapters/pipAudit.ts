/**
 * pip-audit adapter (Apache-2.0). Audits a pinned requirements.txt only, with
 * `--no-deps --disable-pip`, so no package is installed or built (no setup.py code runs).
 * pyproject.toml is reported as skipped. Sends package names/versions to PyPI/OSV.
 */
import * as fs from 'fs';
import * as path from 'path';
import type { Finding } from '../types';
import type { EngineAdapter, EngineResult, EngineRunOptions } from './types';
import { execFailure, isObj, parseJson, runBinary, str } from './exec';
import { detectBinary, emptyCoverage, engineFinding, result, withKeys } from './common';
import type { EngineCoverage } from './types';

const ID = 'pip-audit';

export function parsePipAudit(stdout: string, file: string, coverage: EngineCoverage): Finding[] | undefined {
  const j = parseJson(stdout);
  if (!isObj(j) || !Array.isArray(j.dependencies)) { coverage.errors.push('pip-audit: output was not the expected JSON'); return undefined; }
  const out: Finding[] = [];
  for (const d of j.dependencies) {
    if (!isObj(d) || !Array.isArray(d.vulns)) continue;
    const name = str(d.name), version = str(d.version);
    if (!name) continue;
    for (const v of d.vulns) {
      if (!isObj(v)) continue;
      const id = str(v.id); if (!id) continue;
      const fixes = Array.isArray(v.fix_versions) ? v.fix_versions.filter((x): x is string => typeof x === 'string') : [];
      const aliases = Array.isArray(v.aliases) ? v.aliases.filter((x): x is string => typeof x === 'string') : [];
      out.push(withKeys(engineFinding(ID, {
        key: `${file}:${name}@${version}:${id}`,
        rule: 'dependency-vulnerability',
        // pip-audit gives no severity; advisories are reported as warning rather than guessed.
        severity: 'warning',
        title: `${name}${version ? `@${version}` : ''}: ${id}`,
        description: `${name}${version ? ` ${version}` : ''} is affected by ${[id, ...aliases].join(' / ')}${str(v.description) ? `: ${str(v.description)}` : ''}${fixes.length ? ` Fixed in ${fixes.join(', ')}.` : ''}`,
        recommendation: fixes.length ? `Upgrade ${name} to ${fixes[0]} or later (pip install "${name}>=${fixes[0]}").` : `No fixed version is published; replace or patch ${name}.`,
        file,
        owasp: 'A03:2025',
      }), [id, ...aliases]));
    }
  }
  return out;
}

export const pipAuditAdapter: EngineAdapter = {
  id: ID,
  label: 'pip-audit (Python dependency advisories)',
  capabilities: ['dependencies'],
  networked: true,
  detect: () => detectBinary('pip-audit'),
  applicable: (root) => fs.existsSync(path.join(root, 'requirements.txt')) || fs.existsSync(path.join(root, 'pyproject.toml')),
  async run(root: string, opts: EngineRunOptions): Promise<EngineResult> {
    const started = Date.now();
    const coverage = emptyCoverage();
    if (fs.existsSync(path.join(root, 'pyproject.toml'))) coverage.skipped.push('pyproject.toml: auditing it would build the project (runs build backends); not done. Pin dependencies in requirements.txt to audit them');
    if (!fs.existsSync(path.join(root, 'requirements.txt'))) return result([], coverage, started);
    const bin = (await detectBinary('pip-audit')).path;
    if (!bin) { coverage.errors.push('pip-audit is not installed'); return result([], coverage, started); }
    const r = await runBinary(bin, ['-f', 'json', '--no-deps', '--disable-pip', '-r', 'requirements.txt'], { cwd: root, timeoutMs: opts.timeoutMs });
    const fail = execFailure(r, 'pip-audit');
    if (fail) { coverage.errors.push(fail); return result([], coverage, started); }
    if (r.code !== 0 && r.code !== 1) {
      coverage.errors.push(`pip-audit exited with code ${r.code}: ${r.stderr.trim().slice(0, 200)} (requirements must be fully pinned with ==)`);
      return result([], coverage, started);
    }
    const parsed = parsePipAudit(r.stdout, 'requirements.txt', coverage);
    if (parsed) coverage.checked.push('requirements.txt');
    return result(parsed ?? [], coverage, started);
  },
};

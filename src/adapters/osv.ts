/**
 * OSV-Scanner adapter (Apache-2.0, https://github.com/google/osv-scanner). Used only when
 * `osv-scanner` is already on PATH; DeployReady never downloads it. Needs v2 (`scan source`).
 * It sends package names/versions to api.osv.dev (no source code).
 */
import * as fs from 'fs';
import * as path from 'path';
import type { Finding, Severity } from '../types';
import type { EngineAdapter, EngineCoverage, EngineResult, EngineRunOptions } from './types';
import { execFailure, isObj, parseJson, runBinary, str } from './exec';
import { depSeverity, detectBinary, emptyCoverage, engineFinding, result, withKeys } from './common';

const ID = 'osv-scanner';
const MANIFESTS = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt', 'poetry.lock', 'Pipfile.lock', 'go.mod', 'Cargo.lock', 'Gemfile.lock', 'composer.lock', 'pom.xml'];

function cvssSeverity(score: number): Severity {
  return score >= 9 ? 'critical' : score >= 4 ? 'warning' : 'info';
}

export function parseOsv(stdout: string, root: string, coverage: EngineCoverage): Finding[] | undefined {
  const j = parseJson(stdout);
  if (!isObj(j) || !Array.isArray(j.results)) { coverage.errors.push('osv-scanner: output was not the expected JSON'); return undefined; }
  const out: Finding[] = [];
  for (const res of j.results) {
    if (!isObj(res) || !Array.isArray(res.packages)) continue;
    const src = isObj(res.source) ? str(res.source.path) : undefined;
    let rel = src ? path.relative(root, path.resolve(root, src)) : '';
    if (rel.startsWith('..') || path.isAbsolute(rel)) rel = ''; // never report paths outside the project
    if (rel) coverage.checked.push(rel);
    for (const p of res.packages) {
      if (!isObj(p) || !isObj(p.package) || !Array.isArray(p.vulnerabilities)) continue;
      const name = str(p.package.name), version = str(p.package.version);
      if (!name) continue;
      const groups = Array.isArray(p.groups) ? p.groups.filter(isObj) : [];
      for (const v of p.vulnerabilities) {
        if (!isObj(v)) continue;
        const id = str(v.id); if (!id) continue;
        const aliases = Array.isArray(v.aliases) ? v.aliases.filter((a): a is string => typeof a === 'string') : [];
        const g = groups.find((x) => Array.isArray(x.ids) && x.ids.includes(id));
        const dbSev = isObj(v.database_specific) ? str(v.database_specific.severity) : undefined;
        const score = g ? Number.parseFloat(String(g.max_severity)) : NaN;
        const severity = dbSev ? depSeverity(dbSev) : Number.isFinite(score) ? cvssSeverity(score) : 'warning';
        const fixed = firstFixed(v);
        const cwe = isObj(v.database_specific) && Array.isArray(v.database_specific.cwe_ids)
          ? (v.database_specific.cwe_ids as unknown[]).find((c): c is string => typeof c === 'string' && /^CWE-\d+$/.test(c)) : undefined;
        out.push(withKeys(engineFinding(ID, {
          key: `${rel}:${name}@${version}:${id}`,
          rule: 'dependency-vulnerability',
          title: `${name}${version ? `@${version}` : ''}: ${str(v.summary) ?? id}`.slice(0, 200),
          severity,
          description: `${name}${version ? ` ${version}` : ''} is affected by ${[id, ...aliases].join(' / ')}${str(v.summary) ? `: ${str(v.summary)}` : ''}. Advisory: https://osv.dev/${id}${fixed ? ` Fixed in ${fixed}.` : ''}`,
          recommendation: fixed ? `Upgrade ${name} to ${fixed} or later.` : `No fixed version is published; replace or patch ${name}.`,
          file: rel || undefined,
          cwe,
          owasp: 'A03:2025',
        }), [id, ...aliases]));
      }
    }
  }
  return out;
}

function firstFixed(v: Record<string, unknown>): string | undefined {
  for (const a of Array.isArray(v.affected) ? v.affected : []) {
    if (!isObj(a)) continue;
    for (const r of Array.isArray(a.ranges) ? a.ranges : []) {
      if (!isObj(r)) continue;
      for (const e of Array.isArray(r.events) ? r.events : []) if (isObj(e) && str(e.fixed)) return str(e.fixed);
    }
  }
  return undefined;
}

export const osvAdapter: EngineAdapter = {
  id: ID,
  label: 'OSV-Scanner (dependency advisories, many ecosystems)',
  capabilities: ['dependencies'],
  networked: true,
  detect: () => detectBinary('osv-scanner'),
  applicable: (root) => MANIFESTS.some((m) => fs.existsSync(path.join(root, m))),
  async run(root: string, opts: EngineRunOptions): Promise<EngineResult> {
    const started = Date.now();
    const coverage = emptyCoverage();
    const bin = (await detectBinary('osv-scanner')).path;
    if (!bin) { coverage.errors.push('osv-scanner is not installed'); return result([], coverage, started); }
    const r = await runBinary(bin, ['scan', 'source', '--format', 'json', '-r', '.'], { cwd: root, timeoutMs: opts.timeoutMs });
    const fail = execFailure(r, 'osv-scanner');
    if (fail) { coverage.errors.push(fail); return result([], coverage, started); }
    // Exit 0 = clean, 1 = vulnerabilities found; anything else is an error (e.g. 128 = nothing to scan).
    if (r.code !== 0 && r.code !== 1) {
      if (r.code === 128) coverage.skipped.push('osv-scanner found no supported manifests');
      else coverage.errors.push(`osv-scanner exited with code ${r.code}: ${r.stderr.trim().slice(0, 200)}`);
      return result([], coverage, started);
    }
    const parsed = parseOsv(r.stdout, root, coverage);
    return result(parsed ?? [], coverage, started);
  },
};

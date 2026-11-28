/**
 * npm / pnpm audit adapter. Runs `npm audit --json --omit=dev` (package-lock.json) or
 * `pnpm audit --json --prod` (pnpm-lock.yaml) and maps advisories to findings.
 * Contacts the package registry with dependency names and versions (no source code).
 */
import * as fs from 'fs';
import * as path from 'path';
import type { Finding } from '../types';
import type { EngineAdapter, EngineCoverage, EngineResult, EngineRunOptions } from './types';
import { execFailure, isObj, parseJson, runBinary, str } from './exec';
import { depSeverity, detectBinary, emptyCoverage, engineFinding, failure, result, withKeys } from './common';

const ID = 'npm-audit';
const SEV = new Set(['info', 'low', 'moderate', 'high', 'critical']);

interface Advisory { id: string; title: string; url?: string; severity: string; cwe?: string; range?: string }

/** Installed version of a package from package-lock.json (v2/v3 `packages` map). */
function lockedVersion(lock: unknown, name: string): string | undefined {
  if (!isObj(lock) || !isObj(lock.packages)) return undefined;
  const e = lock.packages[`node_modules/${name}`];
  return isObj(e) ? str(e.version) : undefined;
}

function fixText(fix: unknown): { fixed?: string; command: string } {
  if (isObj(fix) && str(fix.name) && str(fix.version)) {
    const major = fix.isSemVerMajor === true ? ' (breaking: semver-major)' : '';
    return { fixed: str(fix.version), command: `npm install ${str(fix.name)}@${str(fix.version)}${major}` };
  }
  return { command: 'Run `npm audit` for details; no automatic fix is available, so replace or patch the package.' };
}

function advisoriesOf(v: Record<string, unknown>): Advisory[] {
  const out: Advisory[] = [];
  for (const via of Array.isArray(v.via) ? v.via : []) {
    if (!isObj(via)) continue; // string = reached through another vulnerable package
    const title = str(via.title);
    const sev = str(via.severity);
    if (!title || !sev || !SEV.has(sev)) continue;
    const cwe = Array.isArray(via.cwe) ? via.cwe.find((c): c is string => typeof c === 'string' && /^CWE-\d+$/.test(c)) : undefined;
    const url = str(via.url);
    out.push({ id: String(via.source ?? url ?? title).slice(0, 80), title, url, severity: sev, cwe, range: str(via.range) });
  }
  return out;
}

export function parseNpmAudit(stdout: string, lock: unknown, lockFile: string, coverage: EngineCoverage): Finding[] | undefined {
  const j = parseJson(stdout);
  if (!isObj(j)) { coverage.errors.push('npm audit: output was not valid JSON'); return undefined; }
  if (isObj(j.error)) { coverage.errors.push(`npm audit: ${str(j.error.summary) ?? str(j.error.code) ?? 'error'}`); return undefined; }
  if (!isObj(j.vulnerabilities)) { coverage.errors.push('npm audit: unexpected JSON shape (no "vulnerabilities")'); return undefined; }
  const findings: Finding[] = [];
  for (const [name, raw] of Object.entries(j.vulnerabilities)) {
    if (!isObj(raw)) continue;
    const advs = advisoriesOf(raw);
    const installed = lockedVersion(lock, name);
    const { fixed, command } = fixText(raw.fixAvailable);
    // Packages affected only through a vulnerable dependency have no advisory of their own.
    const list: Advisory[] = advs.length
      ? advs
      : [{ id: `via-${name}`, title: `Depends on a vulnerable package`, severity: str(raw.severity) ?? 'low' }];
    for (const a of list) {
      const direct = raw.isDirect === true ? 'direct dependency' : 'transitive dependency';
      findings.push(withKeys(engineFinding(ID, {
        key: `${name}@${installed ?? '?'}:${a.id}`,
        rule: 'dependency-vulnerability',
        title: `${name}${installed ? `@${installed}` : ''}: ${a.title}`.slice(0, 200),
        severity: depSeverity(a.severity),
        description: `${name}${installed ? ` ${installed}` : ''} (${direct}) has a known ${a.severity} advisory: ${a.title}.${a.range ? ` Affected range: ${a.range}.` : ''}${a.url ? ` Advisory: ${a.url}` : ''}${fixed ? ` Fixed in ${fixed}.` : ''}`,
        recommendation: command,
        file: lockFile,
        cwe: a.cwe,
        owasp: 'A03:2025',
      }), [a.id, ...(a.url ? [a.url.split('/').pop() ?? ''] : [])].filter(Boolean)));
    }
  }
  return findings;
}

export const npmAuditAdapter: EngineAdapter = {
  id: ID,
  label: 'npm/pnpm audit (dependency advisories)',
  capabilities: ['dependencies'],
  networked: true,
  detect: () => detectBinary('npm'),
  applicable: (root) => fs.existsSync(path.join(root, 'package-lock.json')) || fs.existsSync(path.join(root, 'pnpm-lock.yaml')) || fs.existsSync(path.join(root, 'yarn.lock')),
  async run(root: string, opts: EngineRunOptions): Promise<EngineResult> {
    const started = Date.now();
    const coverage = emptyCoverage();
    const findings: Finding[] = [];
    const has = (f: string): boolean => fs.existsSync(path.join(root, f));

    if (has('yarn.lock') && !has('package-lock.json') && !has('pnpm-lock.yaml')) {
      coverage.skipped.push('yarn.lock: yarn audit is not supported; use OSV-Scanner (osv-scanner) to cover yarn lockfiles');
      return result([], coverage, started);
    }
    if (has('package-lock.json')) {
      const npm = (await detectBinary('npm')).path;
      if (!npm) coverage.errors.push('package-lock.json: npm is not installed');
      else {
        let lock: unknown;
        try { lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8')); } catch { /* version lookup is best effort */ }
        const r = await runBinary(npm, ['audit', '--json', '--omit=dev'], { cwd: root, timeoutMs: opts.timeoutMs });
        const fail = execFailure(r, 'npm audit');
        if (fail) coverage.errors.push(fail);
        else {
          const parsed = parseNpmAudit(r.stdout, lock, 'package-lock.json', coverage);
          if (parsed) { findings.push(...parsed); coverage.checked.push('package-lock.json (production dependencies)'); }
        }
      }
    }
    if (has('pnpm-lock.yaml')) {
      const pnpm = (await detectBinary('pnpm')).path;
      if (!pnpm) coverage.skipped.push('pnpm-lock.yaml: pnpm is not installed');
      else {
        const r = await runBinary(pnpm, ['audit', '--json', '--prod'], { cwd: root, timeoutMs: opts.timeoutMs });
        const fail = execFailure(r, 'pnpm audit');
        if (fail) coverage.errors.push(fail);
        else {
          const parsed = parsePnpmAudit(r.stdout, coverage);
          if (parsed) { findings.push(...parsed); coverage.checked.push('pnpm-lock.yaml (production dependencies)'); }
        }
      }
    }
    if (!coverage.checked.length && !coverage.errors.length && !coverage.skipped.length) coverage.skipped.push('no supported lockfile');
    return result(findings, coverage, started);
  },
};

/** pnpm audit --json: { advisories: { id: { module_name, severity, title, url, cves, cwe, findings:[{version}], patched_versions } } } */
export function parsePnpmAudit(stdout: string, coverage: EngineCoverage): Finding[] | undefined {
  const j = parseJson(stdout);
  if (!isObj(j)) { coverage.errors.push('pnpm audit: output was not valid JSON'); return undefined; }
  if (isObj(j.error)) { coverage.errors.push(`pnpm audit: ${str(j.error.message) ?? str(j.error.code) ?? 'error'}`); return undefined; }
  if (!isObj(j.advisories)) { coverage.errors.push('pnpm audit: unexpected JSON shape (no "advisories")'); return undefined; }
  const out: Finding[] = [];
  for (const [id, raw] of Object.entries(j.advisories)) {
    if (!isObj(raw)) continue;
    const name = str(raw.module_name), title = str(raw.title), sev = str(raw.severity);
    if (!name || !title || !sev) continue;
    const versions = Array.isArray(raw.findings) ? raw.findings.flatMap((f) => (isObj(f) && str(f.version) ? [str(f.version) as string] : [])) : [];
    const patched = str(raw.patched_versions);
    const cwe = typeof raw.cwe === 'string' && /^CWE-\d+$/.test(raw.cwe) ? raw.cwe : undefined;
    const cves = Array.isArray(raw.cves) ? raw.cves.filter((c): c is string => typeof c === 'string') : [];
    out.push(withKeys(engineFinding('npm-audit', {
      key: `pnpm:${name}:${id}`,
      rule: 'dependency-vulnerability',
      title: `${name}${versions[0] ? `@${versions[0]}` : ''}: ${title}`.slice(0, 200),
      severity: depSeverity(sev),
      description: `${name}${versions.length ? ` ${versions.join(', ')}` : ''} has a known ${sev} advisory: ${title}.${str(raw.url) ? ` Advisory: ${str(raw.url)}` : ''}${patched ? ` Patched in ${patched}.` : ''}`,
      recommendation: patched ? `Upgrade ${name} to ${patched} (pnpm update ${name}).` : `No patched version is listed; replace or patch ${name}.`,
      file: 'pnpm-lock.yaml',
      cwe,
      owasp: 'A03:2025',
    }), [id, ...cves, ...(str(raw.url) ? [(str(raw.url) as string).split('/').pop() ?? ''] : [])].filter(Boolean)));
  }
  return out;
}

export { failure };

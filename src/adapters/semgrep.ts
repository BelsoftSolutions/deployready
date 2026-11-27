/**
 * Semgrep CE adapter (LGPL-2.1). Opt-in only (`--engines semgrep`) and runs only when the user
 * passes `--semgrep-config`. DeployReady ships no rules. Metrics and version checks are forced
 * off. `--config auto` is refused: Semgrep requires metrics for it. A registry config (p/..., r/...,
 * URL) downloads rules from semgrep.dev (no code is sent); a local path stays fully offline.
 */
import * as fs from 'fs';
import * as path from 'path';
import type { Finding, Severity } from '../types';
import type { EngineAdapter, EngineResult, EngineRunOptions } from './types';
import { execFailure, isObj, parseJson, runBinary, str } from './exec';
import { detectBinary, emptyCoverage, engineFinding, result } from './common';

const ID = 'semgrep';

export function isLocalConfig(cfg: string): boolean {
  return !/^(p|r|s)\//.test(cfg) && !/^https?:\/\//.test(cfg) && cfg !== 'auto' && !/^[a-z]+:/.test(cfg);
}

const SEV: Record<string, Severity> = { ERROR: 'warning', WARNING: 'warning', INFO: 'info' };

export const semgrepAdapter: EngineAdapter = {
  id: ID,
  label: 'Semgrep CE (static analysis, your rules)',
  capabilities: ['sast'],
  networked: false, // decided per config; see run()
  optIn: true,
  detect: () => detectBinary('semgrep'),
  applicable: () => true,
  async run(root: string, opts: EngineRunOptions): Promise<EngineResult> {
    const started = Date.now();
    const coverage = emptyCoverage();
    const cfg = opts.semgrepConfig;
    if (!cfg) { coverage.skipped.push('semgrep: pass --semgrep-config <rules-path-or-registry-id>; DeployReady ships no Semgrep rules and never picks a registry for you'); return result([], coverage, started); }
    if (cfg === 'auto') { coverage.errors.push('semgrep: --semgrep-config auto is not supported (it requires Semgrep metrics, which DeployReady keeps off)'); return result([], coverage, started); }
    const local = isLocalConfig(cfg);
    let cfgArg = cfg;
    if (local) {
      const abs = path.resolve(cfg);
      if (!fs.existsSync(abs)) { coverage.errors.push(`semgrep: config path not found: ${cfg}`); return result([], coverage, started); }
      cfgArg = abs;
    } else if (opts.offline) {
      coverage.skipped.push('semgrep: registry config needs the network (skipped by --offline)');
      return result([], coverage, started);
    }
    const bin = (await detectBinary('semgrep')).path;
    if (!bin) { coverage.errors.push('semgrep is not installed'); return result([], coverage, started); }
    const r = await runBinary(bin, ['scan', '--config', cfgArg, '--metrics=off', '--disable-version-check', '--json', '--quiet', '--timeout', '30', '--max-target-bytes', '1000000', '.'], {
      cwd: root, timeoutMs: opts.timeoutMs, env: { SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0' },
    });
    const fail = execFailure(r, 'semgrep');
    if (fail) { coverage.errors.push(fail); return result([], coverage, started); }
    const j = parseJson(r.stdout);
    if (!isObj(j) || !Array.isArray(j.results)) {
      coverage.errors.push(`semgrep exited with code ${r.code}: ${r.stderr.trim().slice(0, 200) || 'output was not the expected JSON'}`);
      return result([], coverage, started);
    }
    const findings: Finding[] = [];
    for (const m of j.results) {
      if (!isObj(m) || !isObj(m.extra) || !isObj(m.start)) continue;
      const rel = str(m.path) ? path.relative(root, path.resolve(root, str(m.path) as string)) : '';
      if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) continue; // never report paths outside the project
      const checkId = (str(m.check_id) ?? 'rule').split('.').slice(-1)[0] as string;
      const meta = isObj(m.extra.metadata) ? m.extra.metadata : {};
      const cweRaw = Array.isArray(meta.cwe) ? meta.cwe[0] : meta.cwe;
      const cwe = typeof cweRaw === 'string' ? cweRaw.match(/CWE-\d+/i)?.[0]?.toUpperCase() : undefined;
      const line = typeof m.start.line === 'number' ? m.start.line : undefined;
      findings.push(engineFinding(ID, {
        key: `${str(m.check_id)}:${rel}:${line}`,
        rule: `semgrep:${checkId}`.slice(0, 80),
        title: (str(m.extra.message) ?? checkId).split('\n')[0]!.slice(0, 200),
        severity: SEV[String(m.extra.severity)] ?? 'info',
        description: `Semgrep rule ${str(m.check_id) ?? checkId} matched. ${str(m.extra.message) ?? ''}`.trim(),
        recommendation: 'Review the match; fix guidance comes from the rule author. Semgrep findings come from rules you chose and are not verified by DeployReady.',
        file: rel,
        line,
        cwe,
      }));
    }
    coverage.checked.push(`${findings.length ? 'files with matches' : 'project files'} (rules: ${local ? 'local' : 'registry'})`);
    if (Array.isArray(j.errors)) for (const e of j.errors.slice(0, 10)) if (isObj(e)) coverage.errors.push(`semgrep: ${str(e.message) ?? str(e.type) ?? 'rule/parse error'}`.slice(0, 300));
    return result(findings, coverage, started);
  },
};

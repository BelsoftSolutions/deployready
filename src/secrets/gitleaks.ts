/**
 * Optional Gitleaks adapter (https://github.com/gitleaks/gitleaks, MIT).
 *
 * Decision: Gitleaks is distributed as a Go binary, so we neither vendor it nor
 * download it. If a `gitleaks` executable is already on PATH we run it in
 * no-git directory mode with `--redact` (it never prints the secret), parse its
 * JSON report, and merge its hits with our own detectors (deduplicated by
 * file:line). Set DEPLOYREADY_GITLEAKS=0 to disable. Any failure is silent:
 * the built-in detectors always run regardless.
 */
import { execFile } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { makeFinding } from '../utils/finding';
import type { Finding } from '../types';

export interface GitleaksHit {
  ruleId: string;
  description: string;
  file: string;
  line: number;
}

/** Locate an executable `gitleaks` on PATH (no shell, no download). */
export function findGitleaks(env: NodeJS.ProcessEnv = process.env): string | null {
  if (env.DEPLOYREADY_GITLEAKS === '0') return null;
  const names = process.platform === 'win32' ? ['gitleaks.exe', 'gitleaks'] : ['gitleaks'];
  for (const dir of (env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    for (const n of names) {
      const p = path.join(dir, n);
      try {
        fs.accessSync(p, fs.constants.X_OK);
        if (fs.statSync(p).isFile()) return p;
      } catch {
        /* not here */
      }
    }
  }
  return null;
}

/** Parse a Gitleaks JSON report (array of findings). Secret/Match fields are ignored. */
export function parseGitleaksReport(json: string, projectPath: string): GitleaksHit[] {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    return [];
  }
  if (!Array.isArray(data)) return [];
  const root = path.resolve(projectPath);
  const out: GitleaksHit[] = [];
  for (const r of data as Record<string, unknown>[]) {
    if (!r || typeof r !== 'object') continue;
    const file = typeof r.File === 'string' ? r.File : '';
    const line = typeof r.StartLine === 'number' ? r.StartLine : 0;
    if (!file) continue;
    const abs = path.resolve(root, file);
    const rel = path.relative(root, abs).split(path.sep).join('/');
    if (rel.startsWith('..')) continue;
    out.push({
      ruleId: typeof r.RuleID === 'string' ? r.RuleID.slice(0, 80) : 'gitleaks',
      description: typeof r.Description === 'string' ? r.Description.slice(0, 160) : '',
      file: rel,
      line,
    });
  }
  return out;
}

/** Run gitleaks (if installed) over a directory. Resolves to [] on any problem. */
export function runGitleaks(projectPath: string, bin: string | null = findGitleaks(), timeoutMs = 120_000): Promise<GitleaksHit[]> {
  if (!bin) return Promise.resolve([]);
  let tmp: string;
  try {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-gitleaks-'));
  } catch {
    return Promise.resolve([]);
  }
  const report = path.join(tmp, 'report.json');
  const args = ['detect', '--no-git', '--source', path.resolve(projectPath), '--report-format', 'json', '--report-path', report, '--redact', '--no-banner', '--exit-code', '0', '--log-level', 'error'];
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: timeoutMs, maxBuffer: 1024 * 1024, windowsHide: true }, () => {
      let hits: GitleaksHit[] = [];
      try {
        hits = parseGitleaksReport(fs.readFileSync(report, 'utf8'), projectPath);
      } catch {
        hits = [];
      }
      fs.rmSync(tmp, { recursive: true, force: true });
      resolve(hits);
    });
  });
}

/** Generic Gitleaks rules are noisier: report them as possible (warning), the rest as critical. */
const GENERIC_RULE_RE = /^generic|entropy/i;

/** Gitleaks hits not already reported by the built-in detectors, as findings. */
export function gitleaksToFindings(hits: GitleaksHit[], existing: Finding[]): Finding[] {
  const taken = new Set(existing.filter((f) => f.file && f.line).map((f) => `${f.file}:${f.line}`));
  const out: Finding[] = [];
  for (const h of hits) {
    const key = `${h.file}:${h.line}`;
    if (taken.has(key)) continue;
    taken.add(key);
    const generic = GENERIC_RULE_RE.test(h.ruleId);
    out.push(
      makeFinding({
        rule: generic ? 'possible-hardcoded-secret' : 'hardcoded-secret',
        title: generic ? 'Possible hardcoded secret (reported by Gitleaks)' : 'Hardcoded secret / credential in source (reported by Gitleaks)',
        severity: generic ? 'warning' : 'critical',
        category: 'security',
        source: 'static',
        file: h.file,
        line: h.line || undefined,
        owasp: 'A02:2025',
        cwe: 'CWE-798',
        description: `Gitleaks rule "${h.ruleId}"${h.description ? ` (${h.description})` : ''} matched in ${h.file}.`,
        recommendation: 'Move the secret to an environment variable or secret manager, rotate the exposed value immediately, and ensure it is gitignored.',
        evidence: `gitleaks: ${h.ruleId}`,
      }),
    );
  }
  return out;
}

/** Convenience: run (if installed) and convert. Never throws. */
export async function gitleaksFindings(projectPath: string, existing: Finding[]): Promise<Finding[]> {
  try {
    return gitleaksToFindings(await runGitleaks(projectPath), existing);
  } catch {
    return [];
  }
}

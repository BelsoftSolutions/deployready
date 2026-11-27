/**
 * Engine registry and runner. Engines run only when installed and applicable; every
 * outcome (ran / skipped / error) is recorded so a missing or failing engine is visible.
 */
import * as path from 'path';
import type { Finding } from '../types';
import type { EngineAdapter, EngineRunOptions, EngineRunSummary } from './types';
import { npmAuditAdapter } from './npmAudit';
import { osvAdapter } from './osv';
import { pipAuditAdapter } from './pipAudit';
import { semgrepAdapter } from './semgrep';
import { advisoryKeys } from './common';
import { DEFAULT_TIMEOUT_MS } from './exec';

export * from './types';

export const ADAPTERS: EngineAdapter[] = [npmAuditAdapter, osvAdapter, pipAuditAdapter, semgrepAdapter];

export interface EngineStepOptions {
  /** --no-deps: skip all dependency engines. */
  noDeps?: boolean;
  /** --engines: comma list of engine ids (or "all"); opt-in engines run only when named here. */
  engines?: string;
  /** --offline: skip engines that contact a network service. */
  offline?: boolean;
  semgrepConfig?: string;
  timeoutMs?: number;
}

export interface EngineStepResult {
  findings: Finding[];
  runs: EngineRunSummary[];
}

const emptyCov = () => ({ checked: [], skipped: [], errors: [] as string[] });

function selected(a: EngineAdapter, o: EngineStepOptions, named: Set<string>): boolean {
  if (a.optIn) return named.has(a.id);
  if (a.capabilities.includes('dependencies') && o.noDeps) return false;
  return named.size === 0 || named.has('all') || named.has(a.id);
}

export async function runEngines(projectRoot: string, o: EngineStepOptions = {}, adapters: EngineAdapter[] = ADAPTERS): Promise<EngineStepResult> {
  const root = path.resolve(projectRoot);
  const named = new Set((o.engines ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
  const opts: EngineRunOptions = { offline: Boolean(o.offline), timeoutMs: o.timeoutMs ?? DEFAULT_TIMEOUT_MS, semgrepConfig: o.semgrepConfig };
  const findings: Finding[] = [];
  const runs: EngineRunSummary[] = [];
  for (const id of named) if (id !== 'all' && !adapters.some((a) => a.id === id)) {
    runs.push({ id, status: 'error', reason: `unknown engine "${id}" (available: ${adapters.map((a) => a.id).join(', ')})`, findings: 0, coverage: { ...emptyCov(), errors: [`unknown engine "${id}"`] }, durationMs: 0 });
  }
  for (const a of adapters) {
    if (!selected(a, o, named)) continue;
    const skip = (reason: string, status: 'skipped' | 'error' = 'skipped', version?: string): void => {
      runs.push({ id: a.id, status, reason, version, findings: 0, coverage: { ...emptyCov(), skipped: [reason] }, durationMs: 0 });
    };
    try {
      if (!a.applicable(root, opts)) continue; // nothing for this engine in this project
      if (opts.offline && a.networked) { skip('skipped: --offline (this engine contacts a registry with package names and versions)'); continue; }
      const det = await a.detect();
      if (!det.installed) {
        // An explicitly requested engine that is missing is an error; an auto engine is just not applicable.
        if (named.has(a.id)) skip(`${a.id} is not installed`, 'error');
        else skip(`${a.id} not installed (optional; see docs/ENGINES.md)`);
        continue;
      }
      const r = await a.run(root, opts);
      findings.push(...r.findings);
      runs.push({ id: a.id, status: r.coverage.errors.length ? 'error' : 'ran', version: det.version, findings: r.findings.length, coverage: r.coverage, durationMs: r.durationMs, reason: r.coverage.errors[0] });
    } catch (e) {
      runs.push({ id: a.id, status: 'error', reason: `${a.id} failed: ${(e as Error).message}`, findings: 0, coverage: { ...emptyCov(), errors: [`${a.id} failed: ${(e as Error).message}`] }, durationMs: 0 });
    }
  }
  return { findings: dedupeEngineFindings(findings), runs };
}

/** Merge engine findings that describe the same advisory for the same package (e.g. npm audit + OSV). */
export function dedupeEngineFindings(findings: Finding[]): Finding[] {
  const out: Finding[] = [];
  const index = new Map<string, Finding>();
  for (const f of findings) {
    const keys = advisoryKeys.get(f) ?? [];
    const pkg = `${f.rule}|${f.title.split(':')[0]}`;
    const hit = keys.map((k) => index.get(`${pkg}|${k}`)).find(Boolean);
    if (hit) {
      const other = f.source.replace('engine:', '');
      if (!hit.description.includes(`also reported by ${other}`)) hit.description += ` (also reported by ${other})`;
      continue;
    }
    out.push(f);
    for (const k of keys) index.set(`${pkg}|${k}`, f);
  }
  return out;
}

/**
 * Native findings win. An engine finding at the same file+line+CWE as a native one is dropped
 * and the native finding gets "also reported by <engine>". Returns the surviving engine findings
 * and the (possibly annotated) native findings.
 */
export function dedupeAgainstNative(native: Finding[], engine: Finding[]): { native: Finding[]; engine: Finding[] } {
  const byLoc = new Map<string, number[]>();
  native.forEach((n, i) => {
    if (!n.file || n.line === undefined || !n.cwe) return;
    const k = `${n.file}|${n.line}|${n.cwe}`;
    byLoc.set(k, [...(byLoc.get(k) ?? []), i]);
  });
  const outNative = native.slice();
  const keep: Finding[] = [];
  for (const e of engine) {
    const idx = e.file && e.line !== undefined && e.cwe ? byLoc.get(`${e.file}|${e.line}|${e.cwe}`) : undefined;
    if (!idx) { keep.push(e); continue; }
    const name = e.source.replace('engine:', '');
    for (const i of idx) {
      const n = outNative[i]!;
      if (!n.description.includes(`also reported by ${name}`)) outNative[i] = { ...n, description: `${n.description} (also reported by ${name})` };
    }
  }
  return { native: outNative, engine: keep };
}

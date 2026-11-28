import * as crypto from 'crypto';
import type { Finding, Severity } from '../types';
import type { EngineAdapter, EngineCoverage, EngineDetection, EngineResult } from './types';
import { findOnPath, runBinary } from './exec';

export const emptyCoverage = (): EngineCoverage => ({ checked: [], skipped: [], errors: [] });

export function result(findings: Finding[], coverage: EngineCoverage, started: number): EngineResult {
  return { findings, coverage, durationMs: Date.now() - started };
}

export function failure(coverage: EngineCoverage, started: number, msg: string): EngineResult {
  coverage.errors.push(msg);
  return result([], coverage, started);
}

/** Detect a binary on PATH and read its version with `--version`. */
export async function detectBinary(bin: string, versionArgs: string[] = ['--version']): Promise<EngineDetection> {
  const p = findOnPath(bin);
  if (!p) return { installed: false };
  const r = await runBinary(p, versionArgs, { cwd: process.cwd(), timeoutMs: 15_000 });
  const version = r.code === 0 ? (r.stdout.match(/\d+\.\d+\.\d+[\w.-]*/)?.[0]) : undefined;
  return { installed: true, path: p, version };
}

export function engineFinding(engineId: string, f: Omit<Finding, 'id' | 'source' | 'category'> & { key: string }): Finding {
  const { key, ...rest } = f;
  const id = crypto.createHash('sha1').update(`${engineId}:${key}`).digest('hex').slice(0, 12);
  return { id, source: `engine:${engineId}`, category: 'security', ...rest };
}

export type { Severity, EngineAdapter };

/** Advisory ids/aliases per dependency finding, used to dedupe across engines. Not part of the Finding shape. */
export const advisoryKeys = new WeakMap<Finding, string[]>();
export function withKeys(f: Finding, keys: string[]): Finding {
  advisoryKeys.set(f, keys.map((k) => k.toUpperCase()));
  return f;
}

/** Shared severity policy for dependency advisories (documented in docs/ENGINES.md). */
export function depSeverity(level: string | undefined): Severity {
  switch ((level ?? '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': case 'moderate': case 'medium': return 'warning';
    default: return 'info';
  }
}

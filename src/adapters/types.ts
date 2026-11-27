/**
 * Engine adapter contract. An adapter wraps an external scanner (npm audit,
 * OSV-Scanner, pip-audit, Semgrep) and normalizes its output into DeployReady
 * findings with source `engine:<id>`. Adapters never throw into the scan: every
 * failure is reported as an error in coverage so it can never read as a clean pass.
 */
import type { Finding } from '../types';

export interface EngineDetection {
  installed: boolean;
  version?: string;
  path?: string;
}

export interface EngineRunOptions {
  /** Skip engines that contact a network service. */
  offline: boolean;
  /** Per-process timeout in ms. */
  timeoutMs: number;
  /** Semgrep only: explicit rule config (local path or registry id). */
  semgrepConfig?: string;
}

export interface EngineCoverage {
  /** Things the engine looked at (lockfiles, manifests, files). */
  checked: string[];
  /** Things that were applicable but not analyzed, each with a reason. */
  skipped: string[];
  /** Failures (non-zero exit, timeout, unparseable output). Non-empty means the result is incomplete. */
  errors: string[];
}

export interface EngineResult {
  findings: Finding[];
  coverage: EngineCoverage;
  durationMs: number;
}

export interface EngineAdapter {
  id: string;
  /** Short human description, e.g. "npm audit (dependency advisories)". */
  label: string;
  capabilities: Array<'dependencies' | 'sast'>;
  /** True when the engine sends data (package names/versions) to a remote service. */
  networked: boolean;
  /** Opt-in engines run only when named in --engines. */
  optIn?: boolean;
  detect(): Promise<EngineDetection>;
  /** Cheap check on the project: does this engine apply (e.g. a lockfile exists)? */
  applicable(projectRoot: string, opts: EngineRunOptions): boolean;
  run(projectRoot: string, opts: EngineRunOptions): Promise<EngineResult>;
}

/** Status of one engine in a scan, surfaced on the report. */
export interface EngineRunSummary {
  id: string;
  status: 'ran' | 'skipped' | 'error';
  reason?: string;
  version?: string;
  findings: number;
  coverage: EngineCoverage;
  durationMs: number;
}

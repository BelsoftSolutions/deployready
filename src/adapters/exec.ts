/**
 * Safe child-process runner for engines: execFile with an argument array (never a
 * shell), a timeout, an output cap, a cwd that must be the project root, and a
 * minimal environment (no tokens or API keys are passed through).
 */
import { execFile } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

export const MAX_OUTPUT_BYTES = 20 * 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 120_000;

/** Variables an engine may need to reach a registry through a proxy. Nothing else is inherited. */
const PASSTHROUGH = [
  'PATH', 'HOME', 'USERPROFILE', 'TMPDIR', 'TEMP', 'TMP', 'LANG', 'LC_ALL', 'SYSTEMROOT',
  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy',
  'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
];

export function minimalEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const k of PASSTHROUGH) if (process.env[k] !== undefined) env[k] = process.env[k];
  env.CI = '1';
  env.NO_COLOR = '1';
  return { ...env, ...extra };
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  /** Exit code; null when killed (timeout) or the process could not start. */
  code: number | null;
  timedOut: boolean;
  /** Output exceeded the cap and the process was killed. */
  truncated: boolean;
  /** Spawn failure message (e.g. ENOENT). */
  spawnError?: string;
}

export interface ExecOptions {
  cwd: string;
  timeoutMs?: number;
  env?: Record<string, string>;
}

export function runBinary(bin: string, args: string[], opts: ExecOptions): Promise<ExecResult> {
  return new Promise((resolve) => {
    let cwd: string;
    try {
      cwd = fs.realpathSync(opts.cwd);
    } catch {
      resolve({ stdout: '', stderr: '', code: null, timedOut: false, truncated: false, spawnError: 'cwd does not exist' });
      return;
    }
    execFile(
      bin,
      args,
      { cwd, timeout: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, maxBuffer: MAX_OUTPUT_BYTES, env: minimalEnv(opts.env), shell: false, windowsHide: true, encoding: 'utf8' },
      (err, stdout, stderr) => {
        const e = err as (NodeJS.ErrnoException & { killed?: boolean; signal?: string; code?: unknown }) | null;
        if (!e) return resolve({ stdout, stderr, code: 0, timedOut: false, truncated: false });
        const truncated = e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER';
        const timedOut = Boolean(e.killed) && !truncated && e.signal === 'SIGTERM';
        if (typeof e.code === 'number') return resolve({ stdout, stderr, code: e.code, timedOut: false, truncated: false });
        resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), code: null, timedOut, truncated, spawnError: truncated || timedOut ? undefined : e.message });
      },
    );
  });
}

/** Find an executable on PATH without invoking a shell. */
export function findOnPath(name: string): string | undefined {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    const p = path.join(dir, name);
    try {
      fs.accessSync(p, fs.constants.X_OK);
      if (fs.statSync(p).isFile()) return p;
    } catch {
      /* next */
    }
  }
  return undefined;
}

/** Parse untrusted JSON; undefined when it is not valid JSON. */
export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

export const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
export const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v.slice(0, 2000) : undefined);

/** Standard failure text for a non-successful ExecResult; undefined when the run itself was fine. */
export function execFailure(r: ExecResult, label: string): string | undefined {
  if (r.spawnError) return `${label}: could not start (${r.spawnError})`;
  if (r.timedOut) return `${label}: timed out`;
  if (r.truncated) return `${label}: output exceeded ${MAX_OUTPUT_BYTES} bytes and was discarded`;
  return undefined;
}

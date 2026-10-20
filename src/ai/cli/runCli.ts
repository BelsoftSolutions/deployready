/**
 * Run a resolved CLI with: shell:false, a fresh EMPTY working directory, a deny-by-default
 * environment, the prompt on stdin, capped output, a hard timeout and process-tree kill.
 * Never logs stdout/stderr (status output can contain an email address).
 */
import { spawn } from 'child_process';
import type { ChildProcess, SpawnOptions } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { buildCliEnv } from './env';
import { ProviderError } from './errors';
import type { ResolvedCli } from './resolve';

export interface RunCliOptions {
  cli: ResolvedCli;
  argv: readonly string[];
  /** Written to the child's stdin then closed. Omit for no stdin. Ignored when `inheritStdio`. */
  stdin?: string;
  timeoutMs?: number;
  maxStdoutBytes?: number;
  /** Child attached to the user's terminal (interactive login). Output is not captured. */
  inheritStdio?: boolean;
  /** Pass the extra terminal/browser variables the interactive login needs. */
  login?: boolean;
  /** Parent environment to filter (default process.env). */
  env?: NodeJS.ProcessEnv;
  /** Where to create the fresh working dir (default os.tmpdir()). */
  tmpRoot?: string;
}

export interface RunCliResult {
  stdout: string;
  /** Last few KB of stderr, for classification only. Must be redacted before it is shown. */
  stderrTail: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  tooLarge: boolean;
  /** The empty directory the child ran in (already deleted when this returns). */
  cwd: string;
}

export const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_MAX_STDOUT_BYTES = 256 * 1024;
const STDERR_TAIL_BYTES = 8 * 1024;
const CLOSE_GRACE_MS = 1_500;
const SAFE_SHIM_ARG = /^[A-Za-z0-9._:=,\-[\]]*$/;
const UNSAFE_SHIM_PATH = /[%"!\r\n\0]/;

const liveDirs = new Set<string>();
let exitHookInstalled = false;

function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  process.on('exit', () => {
    for (const dir of [...liveDirs]) removeDir(dir);
  });
}

function removeDir(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {
    /* best effort: the directory is empty and in the OS temp area */
  }
  liveDirs.delete(dir);
}

function winRoot(parent: NodeJS.ProcessEnv): string {
  const key = Object.keys(parent).find((k) => /^(systemroot|windir)$/i.test(k));
  return (key && parent[key]) || 'C:\\Windows';
}

/** Build the file + args to spawn. Shims go through cmd.exe /d /s /c with every path quoted. */
export function buildSpawnTarget(
  cli: ResolvedCli,
  argv: readonly string[],
  parentEnv: NodeJS.ProcessEnv,
): { file: string; args: string[]; verbatim: boolean } {
  if (cli.kind !== 'shim') return { file: cli.path, args: [...argv], verbatim: false };
  if (UNSAFE_SHIM_PATH.test(cli.path)) {
    throw new ProviderError('invalid_config', 'Refusing to run a CLI shim whose path contains % ! or quote characters.');
  }
  for (const a of argv) {
    if (!SAFE_SHIM_ARG.test(a)) {
      throw new ProviderError('invalid_config', 'Refusing an argument that cannot be passed safely through a .cmd shim.');
    }
  }
  const cmdline = [`"${cli.path}"`, ...argv.map((a) => (a === '' ? '""' : a))].join(' ');
  return {
    file: path.win32.join(winRoot(parentEnv), 'System32', 'cmd.exe'),
    args: ['/d', '/s', '/c', `"${cmdline}"`],
    verbatim: true,
  };
}

export function killTree(child: ChildProcess, parentEnv: NodeJS.ProcessEnv = process.env): void {
  const pid = child.pid;
  if (!pid) return;
  if (process.platform === 'win32') {
    try {
      const tk = spawn(path.win32.join(winRoot(parentEnv), 'System32', 'taskkill.exe'), ['/PID', String(pid), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true,
        shell: false,
      });
      tk.on('error', () => child.kill());
    } catch {
      child.kill();
    }
    return;
  }
  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    try {
      child.kill('SIGKILL');
    } catch {
      /* already gone */
    }
  }
}

export async function runCli(opts: RunCliOptions): Promise<RunCliResult> {
  const parentEnv = opts.env ?? process.env;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxStdout = opts.maxStdoutBytes ?? DEFAULT_MAX_STDOUT_BYTES;
  const inherit = Boolean(opts.inheritStdio);

  const tmpRoot = fs.realpathSync.native(opts.tmpRoot ?? os.tmpdir());
  const cwd = fs.mkdtempSync(path.join(tmpRoot, 'deployready-ai-'));
  liveDirs.add(cwd);
  installExitHook();

  let child: ChildProcess | undefined;
  const sigHandlers: Array<[NodeJS.Signals, () => void]> = [];
  try {
    const env = buildCliEnv(parentEnv, { tempDir: cwd, login: opts.login });
    const target = buildSpawnTarget(opts.cli, opts.argv, parentEnv);
    const spawnOpts: SpawnOptions = {
      cwd,
      env,
      shell: false,
      windowsHide: true,
      windowsVerbatimArguments: target.verbatim,
      detached: process.platform !== 'win32' && !inherit,
      stdio: inherit ? 'inherit' : [opts.stdin === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
    };

    return await new Promise<RunCliResult>((resolve, reject) => {
      let timedOut = false;
      let tooLarge = false;
      let settled = false;
      let stdoutBytes = 0;
      const out: Buffer[] = [];
      let errTail: Buffer = Buffer.alloc(0);
      let timer: NodeJS.Timeout | undefined;
      let graceTimer: NodeJS.Timeout | undefined;

      const finish = (exitCode: number | null, signal: NodeJS.Signals | null): void => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        if (graceTimer) clearTimeout(graceTimer);
        resolve({
          stdout: Buffer.concat(out).toString('utf8'),
          stderrTail: errTail.toString('utf8'),
          exitCode,
          signal,
          timedOut,
          tooLarge,
          cwd,
        });
      };

      try {
        child = spawn(target.file, target.args, spawnOpts);
      } catch (err) {
        reject(new ProviderError('spawn_failed', `Could not start the CLI: ${(err as Error).message}`));
        return;
      }
      const c = child;

      for (const sig of ['SIGINT', 'SIGTERM'] as const) {
        const handler = (): void => {
          killTree(c, parentEnv);
          removeDir(cwd);
          process.removeListener(sig, handler);
          if (process.listenerCount(sig) === 0) process.kill(process.pid, sig);
        };
        sigHandlers.push([sig, handler]);
        process.on(sig, handler);
      }

      c.on('error', (err: NodeJS.ErrnoException) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        if (graceTimer) clearTimeout(graceTimer);
        const code = err.code === 'ENOENT' || err.code === 'EACCES' || err.code === 'EINVAL' ? 'cli_missing' : 'spawn_failed';
        reject(new ProviderError(code, `Could not start the CLI (${err.code ?? 'error'}).`));
      });

      if (!inherit) {
        c.stdout?.on('data', (chunk: Buffer) => {
          stdoutBytes += chunk.length;
          if (stdoutBytes > maxStdout) {
            if (!tooLarge) {
              tooLarge = true;
              killTree(c, parentEnv);
            }
            return;
          }
          out.push(chunk);
        });
        c.stderr?.on('data', (chunk: Buffer) => {
          errTail = Buffer.concat([errTail, chunk]);
          if (errTail.length > STDERR_TAIL_BYTES) errTail = errTail.subarray(errTail.length - STDERR_TAIL_BYTES);
        });
        if (opts.stdin !== undefined && c.stdin) {
          c.stdin.on('error', () => {
            /* the child may exit before reading everything */
          });
          c.stdin.end(opts.stdin, 'utf8');
        }
      }

      timer = setTimeout(() => {
        timedOut = true;
        killTree(c, parentEnv);
      }, timeoutMs);

      c.on('close', (code, signal) => finish(code, signal));
      c.on('exit', (code, signal) => {
        // Orphaned grandchildren can keep the pipes open: do not wait for them forever.
        graceTimer = setTimeout(() => {
          c.stdout?.destroy();
          c.stderr?.destroy();
          finish(code, signal);
        }, CLOSE_GRACE_MS);
      });
    });
  } finally {
    for (const [sig, handler] of sigHandlers) process.removeListener(sig, handler);
    if (child && child.exitCode === null && child.signalCode === null) killTree(child, parentEnv);
    removeDir(cwd);
  }
}

/** Throw the typed error for a run that was cut short; returns normally otherwise. */
export function assertRunCompleted(res: RunCliResult, what: string): void {
  if (res.timedOut) throw new ProviderError('timeout', `${what} timed out.`);
  if (res.tooLarge) throw new ProviderError('output_too_large', `${what} produced more output than allowed and was stopped.`);
}

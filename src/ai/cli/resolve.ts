/**
 * Locate the CLI executable ourselves (never through a shell). On Windows a real `.exe` is
 * preferred over `.cmd`/`.bat` shims; shims are run via cmd.exe with a fully quoted path.
 * The current directory is never searched and relative PATH entries are ignored, so a scanned
 * project cannot plant an executable that DeployReady would pick up.
 */
import * as fs from 'fs';
import * as path from 'path';
import { ProviderError } from './errors';
import type { CliProviderSpec } from './providers';

export interface ResolvedCli {
  path: string;
  /** exe / posix: spawn directly. shim: spawn through cmd.exe /d /s /c. */
  kind: 'exe' | 'shim' | 'posix';
}

export interface ResolveOptions {
  /** User-level `cliCommand` from the config file (never from the scanned project). */
  cliCommand?: string | null;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
}

const WIN_EXE = ['.exe', '.com'];
const WIN_SHIM = ['.cmd', '.bat'];

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function kindFor(p: string, platform: NodeJS.Platform): ResolvedCli['kind'] {
  if (platform !== 'win32') return 'posix';
  return WIN_SHIM.includes(path.extname(p).toLowerCase()) ? 'shim' : 'exe';
}

function getPathVar(env: NodeJS.ProcessEnv): string {
  const key = Object.keys(env).find((k) => k.toLowerCase() === 'path');
  return (key && env[key]) || '';
}

export function resolveCli(spec: CliProviderSpec, opts: ResolveOptions = {}): ResolvedCli | null {
  const platform = opts.platform ?? process.platform;
  const win = platform === 'win32';
  const pathMod = win ? path.win32 : path.posix;

  if (opts.cliCommand) return validateConfiguredCommand(spec, opts.cliCommand, platform);

  const dirs = getPathVar(opts.env ?? process.env)
    .split(win ? ';' : ':')
    .map((d) => d.trim().replace(/^"(.*)"$/, '$1'))
    .filter((d) => d && pathMod.isAbsolute(d));

  const passes: string[][] = win ? [WIN_EXE, WIN_SHIM] : [['']];
  for (const exts of passes) {
    for (const dir of dirs) {
      for (const ext of exts) {
        const candidate = pathMod.join(dir, spec.command + ext);
        if (isFile(candidate)) return { path: candidate, kind: kindFor(candidate, platform) };
      }
    }
  }
  return null;
}

/** A configured command must be an absolute path to an existing file named claude/codex (+ .exe/.cmd/.bat). */
export function validateConfiguredCommand(spec: CliProviderSpec, cmd: string, platform: NodeJS.Platform = process.platform): ResolvedCli {
  const win = platform === 'win32';
  const pathMod = win ? path.win32 : path.posix;
  const bad = (why: string): never => {
    throw new ProviderError('invalid_config', `Ignoring cliCommand: ${why}`, `It must be the absolute path of your ${spec.command} executable.`);
  };
  if (cmd.includes('\0')) bad('it contains a NUL byte.');
  if (!pathMod.isAbsolute(cmd)) bad('it is not an absolute path.');
  const ext = pathMod.extname(cmd).toLowerCase();
  const base = pathMod.basename(cmd, ext).toLowerCase();
  const allowedExt = win ? ['', ...WIN_EXE, ...WIN_SHIM] : [''];
  if (base !== spec.command || !allowedExt.includes(ext)) bad(`the file name must be "${spec.command}"${win ? ' (.exe, .cmd or .bat)' : ''}.`);
  if (!isFile(cmd)) bad('no such file.');
  return { path: cmd, kind: kindFor(cmd, platform) };
}

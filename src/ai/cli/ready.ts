/**
 * Readiness and login for the CLI providers. Login state comes ONLY from the CLI's own
 * status command (no model call). DeployReady never opens, copies or stores a token or auth file,
 * and never keeps the status output: for Claude only `loggedIn` and `authMethod` are read.
 */
import { ProviderError } from './errors';
import { resolveCli } from './resolve';
import type { ResolvedCli } from './resolve';
import { runCli } from './runCli';
import type { RunCliOptions } from './runCli';
import { safeSnippet } from './parseOutput';
import { CLI_PROVIDERS } from './providers';
import type { CliProviderId, CliProviderSpec } from './providers';

export type CliReadyState = 'ready' | 'missing' | 'not_logged_in' | 'unknown' | 'disabled';

export interface CliReadiness {
  state: CliReadyState;
  provider: CliProviderId;
  /** Short, safe, human text for the UI. Never contains the CLI's raw output. */
  message: string;
  /** Claude only: how the CLI says it is signed in (e.g. a subscription vs Console billing). */
  authMethod?: string;
  version?: string;
}

export interface CliContext {
  /** User-level cliCommand from config. */
  cliCommand?: string | null;
  env?: NodeJS.ProcessEnv;
  tmpRoot?: string;
  /** codex-cli is on unless this is exactly false (the user switched it off in config). */
  codexEnabled?: boolean;
  /** Test hook: override the status/login timeouts. */
  statusTimeoutMs?: number;
}

const STATUS_TIMEOUT_MS = 10_000;
const LOGIN_TIMEOUT_MS = 10 * 60_000;

function resolveFor(spec: CliProviderSpec, ctx: CliContext): ResolvedCli | null {
  return resolveCli(spec, { cliCommand: ctx.cliCommand, env: ctx.env });
}

/** Sync check used by `isConfigured()`: is the executable present? (login is checked async) */
export function cliInstalled(provider: CliProviderId, ctx: CliContext = {}): boolean {
  try {
    return resolveFor(CLI_PROVIDERS[provider], ctx) !== null;
  } catch {
    return false;
  }
}

function runOpts(cli: ResolvedCli, argv: readonly string[], ctx: CliContext, extra: Partial<RunCliOptions> = {}): RunCliOptions {
  return { cli, argv, env: ctx.env, tmpRoot: ctx.tmpRoot, ...extra };
}

export async function cliVersion(provider: CliProviderId, ctx: CliContext = {}): Promise<string | undefined> {
  try {
    const cli = resolveFor(CLI_PROVIDERS[provider], ctx);
    if (!cli) return undefined;
    const res = await runCli(runOpts(cli, ['--version'], ctx, { timeoutMs: 5_000, maxStdoutBytes: 4_096 }));
    if (res.exitCode !== 0) return undefined;
    const m = /\d+\.\d+\.\d+[\w.+-]*/.exec(res.stdout);
    return m?.[0];
  } catch {
    return undefined;
  }
}

export const CODEX_DISABLED_MESSAGE =
  'The Codex CLI provider is switched off in your DeployReady config ("codexEnabled": false). Remove that setting or set it to true to use it, or choose another provider.';

export async function checkCliReady(provider: CliProviderId, ctx: CliContext = {}): Promise<CliReadiness> {
  const spec = CLI_PROVIDERS[provider];
  if (provider === 'codex-cli' && ctx.codexEnabled === false) {
    return { state: 'disabled', provider, message: CODEX_DISABLED_MESSAGE };
  }
  let cli: ResolvedCli | null;
  try {
    cli = resolveFor(spec, ctx);
  } catch (err) {
    return { state: 'unknown', provider, message: (err as Error).message };
  }
  if (!cli) {
    return {
      state: 'missing',
      provider,
      message: `The \`${spec.command}\` CLI was not found on your PATH. Install it, or choose another provider.`,
    };
  }

  let res;
  try {
    res = await runCli(runOpts(cli, spec.statusArgv, ctx, { timeoutMs: ctx.statusTimeoutMs ?? STATUS_TIMEOUT_MS, maxStdoutBytes: 16 * 1024 }));
  } catch (err) {
    const e = err as ProviderError;
    return { state: e.code === 'cli_missing' ? 'missing' : 'unknown', provider, message: safeSnippet(e.message, 200) };
  }
  if (res.timedOut || res.tooLarge) {
    return { state: 'unknown', provider, message: `Could not read the login status of \`${spec.command}\` (it did not answer in time).` };
  }

  if (provider === 'claude-cli') {
    let loggedIn: boolean | undefined;
    let authMethod: string | undefined;
    try {
      const j = JSON.parse(res.stdout.trim()) as { loggedIn?: unknown; authMethod?: unknown };
      if (typeof j.loggedIn === 'boolean') loggedIn = j.loggedIn;
      if (typeof j.authMethod === 'string') authMethod = j.authMethod.replace(/[^A-Za-z0-9._-]/g, '').slice(0, 24);
    } catch {
      /* fall through to unknown */
    }
    if (loggedIn === true) {
      return { state: 'ready', provider, authMethod, message: `Logged in to Claude${authMethod && authMethod !== 'none' ? ` (${authMethod})` : ''}.` };
    }
    if (loggedIn === false) {
      return { state: 'not_logged_in', provider, message: `Not logged in. Run \`${spec.loginCommand}\`.` };
    }
    return { state: 'unknown', provider, message: 'Could not read the Claude login status (unexpected answer from the CLI).' };
  }

  // codex: exit code only; the output (which may name the account) is discarded.
  if (res.exitCode === 0) return { state: 'ready', provider, message: 'Logged in to Codex.' };
  if (res.exitCode === 1) return { state: 'not_logged_in', provider, message: `Not logged in. Run \`${spec.loginCommand}\`.` };
  return { state: 'unknown', provider, message: 'Could not read the Codex login status.' };
}

/**
 * Start the CLI's OWN login flow attached to the user's terminal. DeployReady never sees the
 * credentials: the user signs in inside the CLI. Returns true when the CLI exited with code 0.
 */
export async function startCliLogin(provider: CliProviderId, ctx: CliContext = {}): Promise<boolean> {
  const spec = CLI_PROVIDERS[provider];
  const cli = resolveFor(spec, ctx);
  if (!cli) throw new ProviderError('cli_missing', `The \`${spec.command}\` CLI was not found. Install it first.`);
  const res = await runCli(runOpts(cli, spec.loginArgv, ctx, { inheritStdio: true, login: true, timeoutMs: LOGIN_TIMEOUT_MS }));
  return res.exitCode === 0 && !res.timedOut;
}

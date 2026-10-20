/**
 * Provider/login step for the CLI providers (claude-cli, codex-cli), shared by `init` and the
 * in-session setup. Login state comes only from the CLI's own status command; login runs the CLI's
 * own login flow in the user's terminal. DeployReady never reads, copies or stores a credential.
 * Dependencies are injectable so the flow is testable without any real CLI.
 */
import { checkCliReady, startCliLogin } from '../ai/cli/ready';
import type { CliContext, CliReadiness } from '../ai/cli/ready';
import { CLI_PROVIDERS } from '../ai/cli/providers';
import type { CliProviderId } from '../ai/cli/providers';
import { logger } from '../utils/logger';

export interface CliSetupDeps {
  check?: (provider: CliProviderId, ctx: CliContext) => Promise<CliReadiness>;
  login?: (provider: CliProviderId, ctx: CliContext) => Promise<boolean>;
  confirm: (message: string, defaultValue: boolean) => Promise<boolean>;
  log?: Pick<typeof logger, 'info' | 'warn' | 'success'>;
  ctx?: CliContext;
}

export async function setupCliProvider(provider: CliProviderId, deps: CliSetupDeps): Promise<CliReadiness> {
  const spec = CLI_PROVIDERS[provider];
  const check = deps.check ?? checkCliReady;
  const login = deps.login ?? startCliLogin;
  const log = deps.log ?? logger;
  const ctx = deps.ctx ?? {};

  let status = await check(provider, ctx);
  if (status.state === 'ready') {
    log.success(status.message);
    return status;
  }
  if (status.state === 'missing' || status.state === 'disabled') {
    log.warn(status.message);
    return status;
  }

  log.warn(status.message);
  log.info(`DeployReady never sees your login: \`${spec.loginCommand}\` runs the CLI's own sign-in in this terminal.`);
  // Default is NO so closed or empty input can never start an interactive login on its own.
  if (!(await deps.confirm(`Run \`${spec.loginCommand}\` now?`, false))) {
    log.info(`Skipped. Run \`${spec.loginCommand}\` yourself before using AI analysis.`);
    return status;
  }
  try {
    await login(provider, ctx);
  } catch (err) {
    log.warn((err as Error).message);
  }
  status = await check(provider, ctx);
  if (status.state === 'ready') log.success(status.message);
  else log.warn(status.message);
  return status;
}

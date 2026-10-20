/** Static facts about the two CLI providers. Nothing here touches disk or the network. */
import type { AiModel } from '../../types';

export type CliProviderId = 'claude-cli' | 'codex-cli';

export interface CliProviderSpec {
  id: CliProviderId;
  /** Executable base name (without extension). */
  command: 'claude' | 'codex';
  label: string;
  /** Human wording for the consent prompt. */
  route: string;
  /** Subcommand argv that only reports login state (no model call). */
  statusArgv: readonly string[];
  /** Subcommand argv that starts the CLI's own interactive login. */
  loginArgv: readonly string[];
  /** The text a user types to log in manually. */
  loginCommand: string;
}

export const CLI_PROVIDERS: Record<CliProviderId, CliProviderSpec> = {
  'claude-cli': {
    id: 'claude-cli',
    command: 'claude',
    label: 'Claude (CLI login)',
    route: 'your local `claude` CLI, under your own Claude plan',
    statusArgv: ['auth', 'status', '--json'],
    loginArgv: ['auth', 'login', '--claudeai'],
    loginCommand: 'claude auth login',
  },
  'codex-cli': {
    id: 'codex-cli',
    command: 'codex',
    label: 'Codex (CLI login)',
    route: 'your local `codex` CLI, under your own ChatGPT/OpenAI plan',
    statusArgv: ['login', 'status'],
    loginArgv: ['login'],
    loginCommand: 'codex login',
  },
};

export function isCliModel(model: AiModel | string): model is CliProviderId {
  return model === 'claude-cli' || model === 'codex-cli';
}

/** Conservative model-name shape; anything else is refused before it can reach argv. */
export const MODEL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._:\-\[\]]{0,63}$/;

/**
 * The ONLY place argv for a model call is built. Everything is a constant except an
 * optional, shape-validated model name. The prompt never goes in argv (it is written
 * to stdin), so no scanned content, path or secret can reach the command line.
 */
import { MODEL_NAME_RE } from './providers';
import type { CliProviderId } from './providers';
import { ProviderError } from './errors';

/** All tools off, no MCP, no user/project settings or hooks, no skills, nothing persisted. */
const CLAUDE_BASE: readonly string[] = [
  '--print',
  '--output-format', 'json',
  '--tools', '',
  '--disallowedTools', 'Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,Task,NotebookEdit',
  '--strict-mcp-config',
  '--setting-sources', '',
  '--disable-slash-commands',
  '--no-session-persistence',
];

/** Read-only sandbox, ephemeral, no user config/rules, shell tool off. Prompt comes from stdin (`-`). */
const CODEX_BASE: readonly string[] = [
  'exec',
  '--json',
  '-s', 'read-only',
  '--ephemeral',
  '--skip-git-repo-check',
  '--ignore-user-config',
  '--ignore-rules',
  '--disable', 'shell_tool',
  '--disable', 'unified_exec',
  '-c', 'approval_policy=never',
  '-c', 'shell_environment_policy.inherit=none',
];

/** Flags that must never appear in any argv we build (permission bypass, extra access, extra tooling). */
export const FORBIDDEN_ARGV = /dangerous|bypass|yolo|full-auto|danger-full-access|--add-dir|--mcp-config|--allow-dangerously|--permission-mode|--allowedTools|--cd\b|--worktree|--oss|--approve-for-me|workspace-write/i;
/** `-C <dir>` changes Codex's working directory. Case-sensitive: lowercase `-c key=value` is an allowed config override. */
const FORBIDDEN_EXACT = /^-C$/;

export function validateModelName(model: string | null | undefined): string | null {
  if (model === null || model === undefined || model === '') return null;
  if (!MODEL_NAME_RE.test(model)) {
    throw new ProviderError('invalid_config', `Refusing model name "${model.slice(0, 40)}": it contains characters that are not allowed.`);
  }
  return model;
}

export function buildModelArgv(provider: CliProviderId, model?: string | null): string[] {
  const m = validateModelName(model);
  const argv = provider === 'claude-cli' ? [...CLAUDE_BASE] : [...CODEX_BASE];
  if (m) argv.push(provider === 'claude-cli' ? '--model' : '-m', m);
  if (provider === 'codex-cli') argv.push('-');
  assertSafeArgv(argv);
  return argv;
}

export function assertSafeArgv(argv: readonly string[]): void {
  for (const a of argv) {
    if (FORBIDDEN_ARGV.test(a) || FORBIDDEN_EXACT.test(a)) throw new ProviderError('invalid_config', `Refusing to run a CLI with the flag "${a}".`);
  }
}

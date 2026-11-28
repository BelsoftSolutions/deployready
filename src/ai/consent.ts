/**
 * The one consent rule for sending anything (redacted report or snippet) to an AI provider.
 * Pure so every caller (Orchestrator, interactive shell, ModelRouter) applies the same rule.
 *
 * `local`: nothing leaves the machine (Ollama). `approved`: the user pre-approved external sends
 * (--allow-external-ai or config `allowExternalAi: true`). `ask`: an interactive run must ask first.
 * `blocked`: non-interactive run without that opt-in, so AI is skipped. `--yes` / `--json` alone
 * never approve an external send. CLI providers (claude/codex CLI) count as external.
 */
import type { AppConfig } from '../types';

export type ExternalSendDecision = 'local' | 'approved' | 'ask' | 'blocked';

export const EXTERNAL_AI_BLOCKED =
  'AI analysis skipped: this run is non-interactive, so nobody could approve sending the redacted report to an external AI provider. Pass --allow-external-ai (or set "allowExternalAi": true in ~/.deployready/config.json) to allow it. --yes does not.';

export function externalSendDecision(
  sendsExternally: boolean,
  config: Pick<AppConfig, 'allowExternalAi'> | undefined,
  ctx: { interactive: boolean; allowExternalAi?: boolean },
): ExternalSendDecision {
  if (!sendsExternally) return 'local';
  if (ctx.allowExternalAi === true || config?.allowExternalAi === true) return 'approved';
  return ctx.interactive ? 'ask' : 'blocked';
}

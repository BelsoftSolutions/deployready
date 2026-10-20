/**
 * Single entry point for all AI analysis. Picks the right handler from config,
 * builds + chunks the prompt, and returns structured findings.
 *
 * CRITICAL: every other module talks to AI through here — never import the
 * individual handlers directly.
 *
 * Interface contract:
 *   const router = new ModelRouter(config);
 *   const analysis = await router.analyze(report);
 */
import { ClaudeHandler } from './ClaudeHandler';
import { OpenAIHandler } from './OpenAIHandler';
import { OllamaHandler } from './OllamaHandler';
import { CliHandler } from './CliHandler';
import { CLI_PROVIDERS, isCliModel } from './cli/providers';
import { checkCliReady, cliInstalled } from './cli/ready';
import type { CliContext, CliReadiness } from './cli/ready';
import { PromptBuilder } from './PromptBuilder';
import { ContextChunker } from './ContextChunker';
import { ConfigManager } from '../config/ConfigManager';
import { redact } from '../utils/redact';
import { extractFix, type FixSuggestion } from './parseFix';
import type { AiAnalysis, AppConfig, Finding, ScanReport } from '../types';

interface Handler {
  analyze(prompt: { system: string; user: string }): Promise<AiAnalysis>;
  complete(prompt: { system: string; user: string }): Promise<string>;
}

export type { FixSuggestion } from './parseFix';

export class ModelRouter {
  constructor(
    private readonly config: AppConfig,
    /** Test/advanced hook for the CLI providers (environment, temp root). */
    private readonly cliContext: CliContext = {},
  ) {}

  private get cliCtx(): CliContext {
    return { ...this.cliContext, cliCommand: this.config.cliCommand ?? null, codexEnabled: this.config.codexEnabled !== false };
  }

  /** True if data will leave the machine for this model (i.e. not Ollama). */
  get sendsExternally(): boolean {
    return this.config.model !== 'ollama';
  }

  /** Whether a usable handler can be constructed (key present, etc.). */
  isConfigured(): boolean {
    if (this.config.model === 'ollama') return true;
    if (isCliModel(this.config.model)) return cliInstalled(this.config.model, this.cliCtx);
    return Boolean(ConfigManager.resolveKey(this.config));
  }

  /**
   * Async readiness. API providers: same as isConfigured(). CLI providers: also asks the CLI's own
   * status command whether it is logged in (no model call, no token read).
   */
  async checkReady(): Promise<CliReadiness | { state: 'ready' | 'missing'; message: string }> {
    if (isCliModel(this.config.model)) return checkCliReady(this.config.model, this.cliCtx);
    const ok = this.isConfigured();
    return { state: ok ? 'ready' : 'missing', message: ok ? 'Configured.' : 'No API key configured.' };
  }

  /** Where data goes, for the consent prompt. CLI providers run under the user's own plan, not API terms. */
  consentNotice(kind: 'report' | 'snippet'): string {
    const what =
      kind === 'report'
        ? 'a STRUCTURED findings report (no source code, secrets redacted)'
        : 'the relevant snippet (secrets redacted)';
    if (isCliModel(this.config.model)) {
      const spec = CLI_PROVIDERS[this.config.model];
      return `This will send ${what} through ${spec.route}. It is handled under that plan's data policy (not API terms) and counts against your plan limit.`;
    }
    return kind === 'report'
      ? `This will send ${what} to the ${this.config.model} API.`
      : 'To fix code, the relevant snippet (secrets redacted) is sent to the AI model.';
  }

  /** Exactly what would be sent externally, for the consent prompt. */
  previewPayload(report: ScanReport): string {
    return PromptBuilder.preview(report);
  }

  async analyze(report: ScanReport): Promise<AiAnalysis> {
    const { handler, contextTokens } = this.resolveHandler();
    const fitted = ContextChunker.fit(report, contextTokens);
    const prompt = PromptBuilder.build(fitted);
    return handler.analyze(prompt);
  }

  /**
   * Ask the model to rewrite `snippet` to fix `finding`. The snippet is redacted
   * before sending. Caller is responsible for obtaining the user's consent.
   */
  async suggestFix(finding: Finding, snippet: string): Promise<FixSuggestion> {
    const { handler } = this.resolveHandler();
    const prompt = PromptBuilder.buildFixPrompt(finding, redact(snippet));
    const raw = await handler.complete(prompt);
    const parsed = extractFix(raw);
    if (!parsed) throw new Error('The model did not return a usable fix.');
    return parsed;
  }

  private resolveHandler(): { handler: Handler; contextTokens: number } {
    switch (this.config.model) {
      case 'claude': {
        const key = ConfigManager.resolveKey(this.config);
        if (!key) throw new Error('No Claude API key configured. Run `deployready init` or set ANTHROPIC_API_KEY.');
        return { handler: new ClaudeHandler(key), contextTokens: ClaudeHandler.contextTokens };
      }
      case 'openai': {
        const key = ConfigManager.resolveKey(this.config);
        if (!key) throw new Error('No OpenAI API key configured. Run `deployready init` or set OPENAI_API_KEY.');
        return { handler: new OpenAIHandler(key), contextTokens: OpenAIHandler.contextTokens };
      }
      case 'claude-cli':
      case 'codex-cli':
        return {
          handler: new CliHandler(this.config.model, { ...this.cliCtx, model: this.config.cliModel }),
          contextTokens: CliHandler.contextTokens,
        };
      case 'ollama':
        return {
          handler: new OllamaHandler(this.config.ollamaPort, this.config.ollamaModel),
          contextTokens: OllamaHandler.contextTokens,
        };
      default:
        throw new Error(`Unknown model: ${String(this.config.model)}`);
    }
  }
}


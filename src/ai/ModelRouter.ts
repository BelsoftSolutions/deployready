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
import { PromptBuilder } from './PromptBuilder';
import { ContextChunker } from './ContextChunker';
import { ConfigManager } from '../config/ConfigManager';
import { redact } from '../utils/redact';
import type { AiAnalysis, AppConfig, Finding, ScanReport } from '../types';

interface Handler {
  analyze(prompt: { system: string; user: string }): Promise<AiAnalysis>;
  complete(prompt: { system: string; user: string }): Promise<string>;
}

export interface FixSuggestion {
  explanation: string;
  newCode: string;
}

export class ModelRouter {
  constructor(private readonly config: AppConfig) {}

  /** True if data will leave the machine for this model (i.e. not Ollama). */
  get sendsExternally(): boolean {
    return this.config.model !== 'ollama';
  }

  /** Whether a usable handler can be constructed (key present, etc.). */
  isConfigured(): boolean {
    if (this.config.model === 'ollama') return true;
    return Boolean(ConfigManager.resolveKey(this.config));
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
        if (!key) throw new Error('No Claude API key configured. Run `enterpriseready init` or set ANTHROPIC_API_KEY.');
        return { handler: new ClaudeHandler(key), contextTokens: ClaudeHandler.contextTokens };
      }
      case 'openai': {
        const key = ConfigManager.resolveKey(this.config);
        if (!key) throw new Error('No OpenAI API key configured. Run `enterpriseready init` or set OPENAI_API_KEY.');
        return { handler: new OpenAIHandler(key), contextTokens: OpenAIHandler.contextTokens };
      }
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

/** Extract { explanation, newCode } from a model's (possibly noisy) JSON reply. */
function extractFix(text: string): FixSuggestion | null {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try {
    const obj = JSON.parse(text.slice(start, end + 1)) as Partial<FixSuggestion>;
    if (typeof obj.newCode !== 'string') return null;
    return { explanation: typeof obj.explanation === 'string' ? obj.explanation : '', newCode: obj.newCode };
  } catch {
    return null;
  }
}

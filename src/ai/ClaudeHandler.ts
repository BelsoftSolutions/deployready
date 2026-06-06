/**
 * Anthropic (Claude) API handler. Never import this directly outside
 * ModelRouter — all AI calls funnel through the router.
 */
import axios from 'axios';
import { parseAiResponse } from './parseAiResponse';
import type { BuiltPrompt } from './PromptBuilder';
import type { AiAnalysis } from '../types';

const API_URL = 'https://api.anthropic.com/v1/messages';
const DEFAULT_MODEL = 'claude-sonnet-4-6';
const ANTHROPIC_VERSION = '2023-06-01';

export class ClaudeHandler {
  /** Context window we target when chunking (Claude handles far more, but keep prompts lean). */
  static readonly contextTokens = 100_000;

  constructor(
    private readonly apiKey: string,
    private readonly model: string = DEFAULT_MODEL,
  ) {}

  async analyze(prompt: BuiltPrompt): Promise<AiAnalysis> {
    return parseAiResponse(await this.complete(prompt));
  }

  /** Raw text completion — used for fix suggestions and analysis alike. */
  async complete(prompt: BuiltPrompt): Promise<string> {
    try {
      const res = await axios.post(
        API_URL,
        {
          model: this.model,
          max_tokens: 4096,
          system: prompt.system,
          messages: [{ role: 'user', content: prompt.user }],
        },
        {
          timeout: 60_000,
          headers: {
            'x-api-key': this.apiKey,
            'anthropic-version': ANTHROPIC_VERSION,
            'content-type': 'application/json',
          },
        },
      );
      return (res.data?.content ?? [])
        .filter((b: { type: string }) => b.type === 'text')
        .map((b: { text: string }) => b.text)
        .join('\n');
    } catch (err) {
      throw new Error(`Claude API request failed: ${describeHttpError(err)}`);
    }
  }
}

/** Produce a safe, human-readable error without leaking the key or full body. */
export function describeHttpError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    if (err.response) {
      const status = err.response.status;
      if (status === 401 || status === 403) return 'authentication failed (check your API key)';
      if (status === 429) return 'rate limited (too many requests)';
      return `server returned ${status}`;
    }
    if (err.code === 'ECONNABORTED') return 'request timed out';
    return err.message;
  }
  return (err as Error).message ?? 'unknown error';
}

/**
 * Local Ollama handler. Fully offline — nothing leaves the machine, so no
 * external-send consent prompt is needed for this model.
 */
import axios from 'axios';
import { parseAiResponse } from './parseAiResponse';
import { describeHttpError } from './ClaudeHandler';
import type { BuiltPrompt } from './PromptBuilder';
import type { AiAnalysis } from '../types';

export class OllamaHandler {
  // Local models often have smaller windows; chunk more aggressively.
  static readonly contextTokens = 8_000;

  constructor(
    private readonly port: number,
    private readonly model: string,
  ) {}

  async analyze(prompt: BuiltPrompt): Promise<AiAnalysis> {
    return parseAiResponse(await this.complete(prompt));
  }

  /** Raw text completion against the local Ollama instance, with one retry. */
  async complete(prompt: BuiltPrompt): Promise<string> {
    const url = `http://127.0.0.1:${this.port}/api/chat`;
    const body = {
      model: this.model,
      stream: false,
      messages: [
        { role: 'system', content: prompt.system },
        { role: 'user', content: prompt.user },
      ],
    };

    let lastErr: unknown;
    // Local models can return a transient 5xx on cold load — retry once.
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const res = await axios.post(url, body, {
          timeout: 120_000,
          headers: { 'content-type': 'application/json' },
        });
        return res.data?.message?.content ?? '';
      } catch (err) {
        lastErr = err;
        if (attempt === 0) await new Promise((r) => setTimeout(r, 1200));
      }
    }
    throw new Error(
      `Ollama request failed: ${describeHttpError(lastErr)}. Is Ollama running on port ${this.port} with model "${this.model}"?`,
    );
  }
}

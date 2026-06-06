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
    const url = `http://127.0.0.1:${this.port}/api/chat`;
    try {
      const res = await axios.post(
        url,
        {
          model: this.model,
          stream: false,
          messages: [
            { role: 'system', content: prompt.system },
            { role: 'user', content: prompt.user },
          ],
        },
        { timeout: 120_000, headers: { 'content-type': 'application/json' } },
      );
      const text = res.data?.message?.content ?? '';
      return parseAiResponse(text);
    } catch (err) {
      throw new Error(
        `Ollama request failed: ${describeHttpError(err)}. Is Ollama running on port ${this.port} with model "${this.model}"?`,
      );
    }
  }
}

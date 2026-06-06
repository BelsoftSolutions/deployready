/**
 * OpenAI Chat Completions handler. Never import directly outside ModelRouter.
 */
import axios from 'axios';
import { parseAiResponse } from './parseAiResponse';
import { describeHttpError } from './ClaudeHandler';
import type { BuiltPrompt } from './PromptBuilder';
import type { AiAnalysis } from '../types';

const API_URL = 'https://api.openai.com/v1/chat/completions';
const DEFAULT_MODEL = 'gpt-4o-mini';

export class OpenAIHandler {
  static readonly contextTokens = 100_000;

  constructor(
    private readonly apiKey: string,
    private readonly model: string = DEFAULT_MODEL,
  ) {}

  async analyze(prompt: BuiltPrompt): Promise<AiAnalysis> {
    try {
      const res = await axios.post(
        API_URL,
        {
          model: this.model,
          messages: [
            { role: 'system', content: prompt.system },
            { role: 'user', content: prompt.user },
          ],
          response_format: { type: 'json_object' },
        },
        {
          timeout: 60_000,
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            'content-type': 'application/json',
          },
        },
      );
      const text = res.data?.choices?.[0]?.message?.content ?? '';
      return parseAiResponse(text);
    } catch (err) {
      throw new Error(`OpenAI API request failed: ${describeHttpError(err)}`);
    }
  }
}

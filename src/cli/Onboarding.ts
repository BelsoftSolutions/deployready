/**
 * First-run wizard: choose model, capture API key (or confirm Ollama), and
 * persist config. API keys are masked at input and never echoed.
 */
import inquirer from 'inquirer';
import axios from 'axios';
import { ConfigManager } from '../config/ConfigManager';
import { logger } from '../utils/logger';
import type { AiModel, AppConfig } from '../types';

export class Onboarding {
  static async run(): Promise<AppConfig> {
    logger.info('\nWelcome to DeployReady — first-time setup.\n');

    const { model } = await inquirer.prompt<{ model: AiModel }>([
      {
        type: 'list',
        name: 'model',
        message: 'Which AI model should power deeper analysis? (the local scan works without one)',
        choices: [
          { name: 'Claude (Anthropic API key)', value: 'claude' },
          { name: 'OpenAI (API key)', value: 'openai' },
          { name: 'Ollama (local, fully offline, no key)', value: 'ollama' },
        ],
      },
    ]);

    const config: AppConfig = {
      model,
      claudeApiKey: null,
      openaiApiKey: null,
      ollamaPort: 11434,
      ollamaModel: 'llama3',
      warnBeforeExternalSend: true,
      defaultPorts: [3000, 5000, 8000, 8080, 4000],
    };

    if (model === 'claude' || model === 'openai') {
      const envName = model === 'claude' ? 'ANTHROPIC_API_KEY' : 'OPENAI_API_KEY';
      if (process.env[envName]) {
        logger.info(`Detected ${envName} in your environment — I'll use that and won't store a key on disk.`);
      } else {
        const { key } = await inquirer.prompt<{ key: string }>([
          {
            type: 'password',
            name: 'key',
            mask: '*',
            message: `Paste your ${model === 'claude' ? 'Anthropic' : 'OpenAI'} API key:`,
            validate: (v: string) => (v.trim().length > 10 ? true : 'That key looks too short.'),
          },
        ]);
        if (model === 'claude') config.claudeApiKey = key.trim();
        else config.openaiApiKey = key.trim();
      }
    } else {
      await Onboarding.checkOllama(config);
    }

    await ConfigManager.save(config);
    logger.success(`Config saved to ${ConfigManager.configPath()} (permissions 0600).`);
    return config;
  }

  private static async checkOllama(config: AppConfig): Promise<void> {
    try {
      const res = await axios.get(`http://127.0.0.1:${config.ollamaPort}/api/tags`, { timeout: 3000 });
      const models = (res.data?.models ?? []).map((m: { name: string }) => m.name);
      if (models.length) {
        const { chosen } = await inquirer.prompt<{ chosen: string }>([
          { type: 'list', name: 'chosen', message: 'Which local Ollama model?', choices: models },
        ]);
        config.ollamaModel = chosen;
        logger.success(`Ollama reachable. Using model "${chosen}".`);
      } else {
        logger.warn('Ollama is running but has no models. Pull one, e.g. `ollama pull llama3`.');
      }
    } catch {
      logger.warn(`Could not reach Ollama on port ${config.ollamaPort}. Start it with \`ollama serve\` before scanning.`);
    }
  }
}

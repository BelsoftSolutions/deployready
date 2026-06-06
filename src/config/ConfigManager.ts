/**
 * Loads/saves ~/.deployready/config.json.
 *
 * Security posture:
 * - API keys from environment variables (ANTHROPIC_API_KEY / OPENAI_API_KEY)
 *   ALWAYS take precedence and are never written to disk.
 * - The config file is written with 0600 perms (owner read/write only).
 * - Keys are never logged (logger redacts anyway).
 *
 * The on-disk file is intentionally NOT encrypted in the MVP: encryption
 * without a user-supplied passphrase only provides obfuscation and a false
 * sense of safety. File permissions + env-var preference is the honest,
 * standard CLI approach (same as npm, aws-cli, gh). Documented in README.
 */
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import type { AppConfig } from '../types';

const CONFIG_DIR = path.join(os.homedir(), '.deployready');
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');

const DEFAULTS: AppConfig = {
  model: 'claude',
  claudeApiKey: null,
  openaiApiKey: null,
  ollamaPort: 11434,
  ollamaModel: 'llama3',
  warnBeforeExternalSend: true,
  defaultPorts: [3000, 5000, 8000, 8080, 4000],
};

export class ConfigManager {
  static configPath(): string {
    return CONFIG_PATH;
  }

  /** Load config, merging file values over defaults and env vars over both. */
  static async load(): Promise<AppConfig> {
    let fromFile: Partial<AppConfig> = {};
    try {
      const raw = await fs.readFile(CONFIG_PATH, 'utf8');
      fromFile = JSON.parse(raw) as Partial<AppConfig>;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw new Error(
          `Could not read config at ${CONFIG_PATH}. It may be corrupt — fix or delete it. (${(err as Error).message})`,
        );
      }
      // No config yet — caller should run onboarding.
    }

    const merged: AppConfig = { ...DEFAULTS, ...fromFile };

    // Environment variables win and are never persisted.
    if (process.env.ANTHROPIC_API_KEY) merged.claudeApiKey = process.env.ANTHROPIC_API_KEY;
    if (process.env.OPENAI_API_KEY) merged.openaiApiKey = process.env.OPENAI_API_KEY;

    return merged;
  }

  /** True if a config file exists on disk. */
  static async exists(): Promise<boolean> {
    try {
      await fs.access(CONFIG_PATH);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Persist config. Strips keys that came from the environment so we never
   * write an env-provided secret to disk.
   */
  static async save(config: AppConfig): Promise<void> {
    await fs.mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 });

    const toWrite: AppConfig = { ...config };
    if (process.env.ANTHROPIC_API_KEY && config.claudeApiKey === process.env.ANTHROPIC_API_KEY) {
      toWrite.claudeApiKey = null;
    }
    if (process.env.OPENAI_API_KEY && config.openaiApiKey === process.env.OPENAI_API_KEY) {
      toWrite.openaiApiKey = null;
    }

    const json = JSON.stringify(toWrite, null, 2);
    // Write with restrictive perms from the start (mode honored on POSIX).
    await fs.writeFile(CONFIG_PATH, json, { mode: 0o600 });
    try {
      await fs.chmod(CONFIG_PATH, 0o600);
    } catch {
      // chmod is a no-op / may fail on Windows; perms are enforced by NTFS ACLs.
    }
  }

  /** Resolve the active API key for the configured model, env var first. */
  static resolveKey(config: AppConfig): string | null {
    if (config.model === 'claude') return config.claudeApiKey;
    if (config.model === 'openai') return config.openaiApiKey;
    return null; // ollama needs no key
  }
}

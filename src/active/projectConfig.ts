/**
 * The project-level active config: `.deployready.json` → `"active"` at the root
 * of the scanned project (identities, policy, safety settings). Merged over the
 * `active` section of the user config (~/.deployready/config.json), key by key.
 *
 * Hosts the scanner may treat as owned (`ownedTargets`) are deliberately NOT
 * read from the project file: a cloned repository must never widen where
 * active requests may go. They come from the user config or the command line.
 */
import * as fsSync from 'fs';
import * as fs from 'fs/promises';
import * as path from 'path';
import type { ActiveConfigSection, AppConfig } from '../types';
import { parseIdentityConfigs, type IdentityConfig } from './identities';
import { parsePolicy, type AuthzPolicyConfig } from './policy';

export const PROJECT_CONFIG_FILE = '.deployready.json';
const MAX_BYTES = 1024 * 1024;

export interface ProjectActiveConfig {
  /** The raw `active` section of `.deployready.json` (empty when absent). */
  section: Record<string, unknown>;
  file?: string;
  /** Set when the file exists but cannot be read or parsed. */
  error?: string;
}

export async function loadProjectActiveConfig(projectPath: string): Promise<ProjectActiveConfig> {
  const file = path.join(projectPath, PROJECT_CONFIG_FILE);
  let raw: string;
  try {
    const st = await fs.stat(file);
    if (!st.isFile()) return { section: {} };
    if (st.size > MAX_BYTES) return { section: {}, file, error: `${PROJECT_CONFIG_FILE} is larger than 1 MB` };
    raw = await fs.readFile(file, 'utf8');
  } catch {
    return { section: {} };
  }
  try {
    const json = JSON.parse(raw) as Record<string, unknown>;
    const active = json && typeof json === 'object' ? json.active : undefined;
    return { section: active && typeof active === 'object' && !Array.isArray(active) ? (active as Record<string, unknown>) : {}, file };
  } catch (err) {
    return { section: {}, file, error: `${PROJECT_CONFIG_FILE} is not valid JSON (${(err as Error).message})` };
  }
}

/** User config with the project's `active` section merged over it. `ownedTargets` stay the user's. */
export function mergeActiveConfig(config: AppConfig, project: ProjectActiveConfig): AppConfig {
  const userActive = (config.active ?? {}) as Record<string, unknown>;
  return { ...config, active: { ...userActive, ...project.section } as ActiveConfigSection };
}

export interface AuthzSettings {
  identities: IdentityConfig[];
  policy: AuthzPolicyConfig | null;
  problems: string[];
  source: string;
}

/** Identities + policy from the merged active section. */
export function authzSettings(active: Record<string, unknown> | undefined, source: string): AuthzSettings {
  const ids = parseIdentityConfigs(active?.identities);
  const pol = parsePolicy(active?.policy);
  return { identities: ids.identities, policy: pol.policy, problems: [...ids.problems, ...pol.problems], source };
}

/** Synchronous check used by the CLI: does the project declare identities or a policy? */
export function projectDeclaresIdentities(projectPath: string): boolean {
  try {
    const file = path.join(projectPath, PROJECT_CONFIG_FILE);
    const st = fsSync.statSync(file);
    if (!st.isFile() || st.size > MAX_BYTES) return false;
    const json = JSON.parse(fsSync.readFileSync(file, 'utf8')) as { active?: { identities?: unknown; policy?: unknown } };
    return Array.isArray(json?.active?.identities) && json.active!.identities.length > 0;
  } catch {
    return false;
  }
}

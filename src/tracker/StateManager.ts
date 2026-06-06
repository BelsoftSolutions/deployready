/**
 * Persists per-project checklist state under ~/.enterpriseready/state so a
 * session can be resumed. Keyed by a hash of the project path.
 */
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import type { ItemStatus } from './ChecklistManager';

const STATE_DIR = path.join(os.homedir(), '.enterpriseready', 'state');

export class StateManager {
  private static fileFor(projectPath: string): string {
    const hash = crypto.createHash('sha1').update(path.resolve(projectPath)).digest('hex').slice(0, 16);
    return path.join(STATE_DIR, `${hash}.json`);
  }

  static async load(projectPath: string): Promise<Record<string, ItemStatus>> {
    try {
      const raw = await fs.readFile(StateManager.fileFor(projectPath), 'utf8');
      return JSON.parse(raw) as Record<string, ItemStatus>;
    } catch {
      return {};
    }
  }

  static async save(projectPath: string, state: Record<string, ItemStatus>): Promise<void> {
    await fs.mkdir(STATE_DIR, { recursive: true, mode: 0o700 });
    await fs.writeFile(StateManager.fileFor(projectPath), JSON.stringify(state, null, 2), { mode: 0o600 });
  }
}

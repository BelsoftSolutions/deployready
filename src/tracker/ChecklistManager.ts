/**
 * Tracks pass/fail/fixed status per finding. Backs the checklist view and lets
 * the score update as the user marks issues resolved.
 */
import type { Finding } from '../types';

export type ItemStatus = 'open' | 'fixed' | 'ignored';

export interface ChecklistItem {
  finding: Finding;
  status: ItemStatus;
}

export class ChecklistManager {
  private items = new Map<string, ChecklistItem>();

  constructor(findings: Finding[]) {
    for (const f of findings) this.items.set(f.id, { finding: f, status: 'open' });
  }

  list(): ChecklistItem[] {
    return [...this.items.values()];
  }

  setStatus(id: string, status: ItemStatus): boolean {
    const item = this.items.get(id);
    if (!item) return false;
    item.status = status;
    return true;
  }

  /** Findings still counting against the score (not fixed or ignored). */
  openFindings(): Finding[] {
    return this.list().filter((i) => i.status === 'open').map((i) => i.finding);
  }

  /** Serializable status map for persistence. */
  toState(): Record<string, ItemStatus> {
    const out: Record<string, ItemStatus> = {};
    for (const [id, item] of this.items) out[id] = item.status;
    return out;
  }

  applyState(state: Record<string, ItemStatus>): void {
    for (const [id, status] of Object.entries(state)) {
      const item = this.items.get(id);
      if (item) item.status = status;
    }
  }
}

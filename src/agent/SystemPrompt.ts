/**
 * Phase 1.5 — Builds the agentic session system prompt (report + tool defs).
 * Stub: the conversational agent loop ships in Phase 1.5. Kept here so the
 * structure matches the spec's Module 7 and can be extended without edits
 * elsewhere.
 */
import type { ScanReport } from '../types';

export class SystemPrompt {
  static build(_report: ScanReport): string {
    throw new Error('Agentic session (SystemPrompt) ships in Phase 1.5.');
  }
}

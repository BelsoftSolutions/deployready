/**
 * Phase 1.5 — Manages the conversational AI session: history, tool dispatch,
 * fix approvals. Stub for the MVP (Module 7 in the spec).
 *
 *   const session = new SessionManager(report, config);
 *   await session.start();
 */
import type { AppConfig, ScanReport } from '../types';

export class SessionManager {
  constructor(
    private readonly _report: ScanReport,
    private readonly _config: AppConfig,
  ) {}

  async start(): Promise<never> {
    throw new Error('Interactive agentic session ships in Phase 1.5.');
  }
}

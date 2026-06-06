/**
 * Phase 1.5 — Routes AI tool-call requests (run_security_test, read_file,
 * propose_fix, etc.) to the correct module. Stub for the MVP.
 */
export class ToolDispatcher {
  async dispatch(_tool: string, _args: Record<string, unknown>): Promise<never> {
    throw new Error('Agentic tool dispatch ships in Phase 1.5.');
  }
}

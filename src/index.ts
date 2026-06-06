/**
 * Library + CLI entry. `run()` parses argv and dispatches commands.
 * The bin shim (bin/deployready.js) calls run().
 */
import { buildProgram } from './cli/Commands';

export async function run(argv: string[] = process.argv): Promise<void> {
  const program = buildProgram();
  await program.parseAsync(argv);
}

// Public API surface for programmatic use / tests.
export { Orchestrator } from './core/Orchestrator';
export { CodeParser } from './parser/CodeParser';
export { VulnerabilityDetector } from './analysis/VulnerabilityDetector';
export { IssueAggregator } from './analysis/IssueAggregator';
export * from './types';

// Allow `tsx src/index.ts` / `node dist/index.js` to run directly.
if (require.main === module) {
  run().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

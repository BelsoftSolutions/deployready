/**
 * CLI command definitions via Commander.js: analyze, init, report.
 * Each action wraps its work in try/catch and exits with a human-readable error.
 */
import { Command } from 'commander';
import { Orchestrator } from '../core/Orchestrator';
import { InteractiveShell } from './InteractiveShell';
import { Onboarding } from './Onboarding';
import { ConfigManager } from '../config/ConfigManager';
import { ExportManager } from '../ui/ExportManager';
import { parseFailOn, shouldFail, toCiJson, EXIT } from '../core/CiGate';
import { logger, setVerbose, setQuiet } from '../utils/logger';

const VERSION = '0.1.0';

export function buildProgram(): Command {
  const program = new Command();

  program
    .name('deployready')
    .description('Local-first, AI-optional production-readiness scanner for your app.')
    .version(VERSION)
    .option('-v, --verbose', 'verbose debug output', false)
    .hook('preAction', (thisCmd) => {
      if (thisCmd.opts().verbose) setVerbose(true);
    });

  // Default: launch the interactive session.
  program
    .command('interactive', { isDefault: true })
    .alias('shell')
    .description('Start the interactive session (default when no command is given)')
    .argument('[path]', 'path to the project', '.')
    .action(async (path: string) => {
      await guard(async () => {
        await new InteractiveShell(path).start();
      });
    });

  // Explicit one-shot scan (non-interactive / CI).
  program
    .command('analyze')
    .description('Run a single non-interactive scan and print results')
    .argument('[path]', 'path to the project', '.')
    .option('-y, --yes', 'auto-approve all prompts (non-interactive)', false)
    .option('--no-dynamic', 'skip live localhost testing')
    .option('--no-ai', 'skip AI analysis (local results only)')
    .option('--aggressive', 'enable aggressive tests (rate-limit burst)', false)
    .option('--export', 'write deployready-report.md to the project root', false)
    .option('--json', 'print a machine-readable JSON report to stdout (implies --yes)', false)
    .option(
      '--fail-on <severity>',
      'exit non-zero (code 2) if findings at/above this severity exist: critical | warning | info | none',
      'none',
    )
    .action(async (path: string, opts) => {
      await guard(async () => {
        const failOn = parseFailOn(opts.failOn);
        if (opts.json) setQuiet(true); // keep stdout clean for JSON consumers

        const report = await Orchestrator.analyze(path, {
          yes: opts.yes || opts.json, // JSON mode is non-interactive
          noDynamic: !opts.dynamic, // commander sets .dynamic=false for --no-dynamic
          noAi: !opts.ai,
          aggressive: opts.aggressive,
          export: opts.export,
          json: opts.json,
        });

        if (opts.json) {
          process.stdout.write(JSON.stringify(toCiJson(report, failOn), null, 2) + '\n');
        }

        if (shouldFail(report.summary, failOn)) {
          logger.error(
            `Gate failed: findings at or above "${failOn}" (${report.summary.critical} critical, ${report.summary.warning} warning, ${report.summary.info} info).`,
          );
          process.exitCode = EXIT.GATE;
        }
      });
    });

  program
    .command('init')
    .description('Run the first-time setup wizard (choose model, store API key)')
    .action(async () => {
      await guard(async () => {
        await Onboarding.run();
      });
    });

  program
    .command('report')
    .description('Re-run a scan and export the markdown report')
    .argument('[path]', 'path to the project', '.')
    .action(async (path: string) => {
      await guard(async () => {
        const report = await Orchestrator.analyze(path, { noAi: true });
        const file = await ExportManager.saveMarkdown(report, path);
        logger.success(`Report saved to ${file}`);
      });
    });

  program
    .command('config')
    .description('Show the active config (secrets are never printed)')
    .action(async () => {
      await guard(async () => {
        const c = await ConfigManager.load();
        logger.info(
          JSON.stringify(
            {
              model: c.model,
              claudeApiKey: c.claudeApiKey ? '«set»' : null,
              openaiApiKey: c.openaiApiKey ? '«set»' : null,
              ollamaPort: c.ollamaPort,
              ollamaModel: c.ollamaModel,
              warnBeforeExternalSend: c.warnBeforeExternalSend,
              defaultPorts: c.defaultPorts,
            },
            null,
            2,
          ),
        );
      });
    });

  return program;
}

/** Run an async action, turning any error into a clean message + exit code. */
async function guard(fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    logger.error((err as Error).message || 'Unexpected error.');
    process.exitCode = 1;
  }
}

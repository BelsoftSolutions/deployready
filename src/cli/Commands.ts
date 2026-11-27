/**
 * CLI command definitions via Commander.js: analyze, init, report.
 * Each action wraps its work in try/catch and exits with a human-readable error.
 */
import * as fs from 'fs';
import { Command } from 'commander';
import { Orchestrator } from '../core/Orchestrator';
import { InteractiveShell } from './InteractiveShell';
import { Onboarding } from './Onboarding';
import { ConfigManager } from '../config/ConfigManager';
import { ExportManager } from '../ui/ExportManager';
import {
  parseFailOn,
  shouldFail,
  toCiJson,
  EXIT,
  serializeBaseline,
  parseBaseline,
  compareToBaseline,
  gatedFindings,
  describeComparison,
  summarize,
  type BaselineComparison,
} from '../core/CiGate';
import { logger, setVerbose, setQuiet } from '../utils/logger';
import { getVersion } from '../utils/version';
import { renderTokenHelp } from '../active/tokenHelp';
import { runAnalyzeFix } from '../mcp/analyzeFix';
import { startMcpServer } from '../mcp/server';
import { badgeMarkdown, badgeSvg } from '../ui/badge';
import { toSarif } from '../ui/Sarif';

const VERSION = getVersion();

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
    .option('--fix', 'apply safe deterministic fixes (with backups), then re-scan and report the new score', false)
    .option('--no-dynamic', 'skip live localhost testing')
    .option('--no-ai', 'skip AI analysis (local results only)')
    .option('--aggressive', 'enable aggressive tests (rate-limit burst)', false)
    .option('--export', 'write deployready-report.md to the project root', false)
    .option('--html', 'write an HTML dashboard (deployready-report.html)', false)
    .option('--open', 'open the HTML dashboard in your browser after the scan (implies --html)', false)
    .option('--json', 'print a machine-readable JSON report to stdout (implies --yes)', false)
    .option('--sarif <file>', 'write a SARIF 2.1.0 report (for GitHub code scanning) to this file')
    .option(
      '--fail-on <severity>',
      'exit non-zero (code 2) if findings at/above this severity exist: critical | warning | info | none',
      'none',
    )
    .option(
      '--baseline <file>',
      'gate only on findings NOT in this baseline file (existing issues are grandfathered)',
    )
    .option(
      '--write-baseline <file>',
      'write the current findings to a baseline file and exit 0 (accept current state)',
    )
    .option('--strict-baseline', 'also fail (exit 2) when the baseline has stale suppressions (entries with no matching finding)', false)
    .option(
      '--probe-common-paths',
      'opt in to the common-path probe: also request a fixed, printed list of well-known paths (/.env, /.git/config, ...) on your local app; see docs/COMMON-PATH-PROBE.md',
    )
    .option('--no-probe-common-paths', 'force the common-path probe off for this run, even if the config key enables it')
    .option('--active', 'run active (authenticated) authorization tests — needs --token', false)
    .option('--token <jwt>', 'bearer JWT for the active scan (your test user)')
    .option('--token-b <jwt>', 'second-identity JWT, for tenant/IDOR isolation tests')
    .option('--supabase', 'run live, read-only Supabase checks (only on a local or proven-owned project; see docs/SUPABASE.md)', false)
    .option('--supabase-url <url>', 'Supabase project URL (default: $SUPABASE_URL, then the project files)')
    .option('--supabase-anon-key <key>', 'anon/publishable key (default: $SUPABASE_ANON_KEY, then the project files)')
    .option('--supabase-service-key <key>', 'service_role key proving ownership (prefer $SUPABASE_SERVICE_ROLE_KEY)')
    .option('--supabase-access-token <token>', 'Supabase access token proving ownership (prefer $SUPABASE_ACCESS_TOKEN)')
    .option('--supabase-cross-user', 'also test whether test user A can read user B\'s rows ($SUPABASE_TEST_USER_A_EMAIL/_PASSWORD, _B_)', false)
    .option('--active-url <url>', 'base URL for the active scan (default: the app found on localhost); non-loopback needs --i-own-this-target')
    .option('--no-deps', 'skip dependency-vulnerability engines (npm/pnpm audit, OSV-Scanner, pip-audit)')
    .option('--engines <list>', 'comma-separated engines to run (npm-audit, osv-scanner, pip-audit, semgrep, all); semgrep runs only when named; see docs/ENGINES.md')
    .option('--offline', 'skip engines that contact a network service (they send package names/versions, never source code)', false)
    .option('--semgrep-config <path-or-registry>', 'rules for the opt-in semgrep engine (never defaulted; metrics are off)')
    .option(
      '--i-own-this-target <host>',
      'confirm you own this non-loopback host so active probes may target it (repeatable; exact host only)',
      (v: string, prev: string[]) => [...prev, v],
      [] as string[],
    )
    .action(async (path: string, opts) => {
      await guard(async () => {
        const failOn = parseFailOn(opts.failOn);
        if (opts.json) setQuiet(true); // keep stdout clean for JSON consumers

        // Active scan needs a token; if asked for without one, show how to get it.
        let active = Boolean(opts.active);
        if (active && !opts.token) {
          active = false;
          if (!opts.json) {
            logger.warn('--active needs a --token. Skipping the active scan for now.\n');
            console.log(renderTokenHelp());
            console.log('');
          }
        }

        const analyzeOpts = {
          yes: opts.yes || opts.json, // JSON mode is non-interactive
          noDynamic: !opts.dynamic, // commander sets .dynamic=false for --no-dynamic
          noAi: !opts.ai,
          aggressive: opts.aggressive,
          probeCommonPaths: opts.probeCommonPaths as boolean | undefined, // undefined = not on the command line
          export: opts.export,
          html: opts.html,
          open: opts.open,
          json: opts.json,
          active,
          token: opts.token,
          tokenB: opts.tokenB,
          engines: { noDeps: !opts.deps, engines: opts.engines as string | undefined, offline: opts.offline as boolean, semgrepConfig: opts.semgrepConfig as string | undefined },
          supabase: {
            live: opts.supabase,
            url: opts.supabaseUrl,
            anonKey: opts.supabaseAnonKey,
            serviceKey: opts.supabaseServiceKey,
            accessToken: opts.supabaseAccessToken,
            crossUser: opts.supabaseCrossUser,
          },
          activeUrl: opts.activeUrl as string | undefined,
          ownedHosts: opts.iOwnThisTarget as string[],
        };
        let report = await Orchestrator.analyze(path, analyzeOpts);
        const fixOutcome = opts.fix ? await runAnalyzeFix(path, report, analyzeOpts, opts) : undefined;
        if (fixOutcome) report = fixOutcome.report;

        // Accept the current findings as the baseline, then stop (no gating).
        if (opts.writeBaseline) {
          const previous = fs.existsSync(opts.writeBaseline)
            ? parseBaseline(fs.readFileSync(opts.writeBaseline, 'utf8'))
            : undefined;
          const body = serializeBaseline(report.findings, { root: report.target, previous });
          fs.writeFileSync(opts.writeBaseline, body);
          logger.success(`Wrote baseline with ${report.summary.total} finding(s) to ${opts.writeBaseline}.`);
          return;
        }

        if (opts.sarif) {
          fs.writeFileSync(opts.sarif, JSON.stringify(toSarif(report, VERSION), null, 2) + '\n');
          if (!opts.json) logger.success(`Wrote SARIF report to ${opts.sarif}`);
        }

        // Gate on new findings only when a baseline is supplied.
        let gateSummary = report.summary;
        let cmp: BaselineComparison | undefined;
        if (opts.baseline) {
          const baseline = fs.existsSync(opts.baseline)
            ? parseBaseline(fs.readFileSync(opts.baseline, 'utf8'))
            : { version: 2, entries: [], warnings: [] };
          cmp = compareToBaseline(report.findings, baseline, { root: report.target });
          gateSummary = summarize(gatedFindings(cmp));
          if (!opts.json) {
            for (const w of cmp.warnings) logger.warn(w);
            logger.info(`Baseline: ${cmp.known.length} known finding(s) grandfathered.\n${describeComparison(cmp).join('\n')}`);
          }
        }

        if (opts.json) {
          const body = toCiJson(report, failOn, cmp);
          if (fixOutcome) body.fix = fixOutcome.fix;
          process.stdout.write(JSON.stringify(body, null, 2) + '\n');
        }

        if (shouldFail(gateSummary, failOn)) {
          const scope = opts.baseline ? 'new findings' : 'findings';
          logger.error(
            `Gate failed: ${scope} at or above "${failOn}" (${gateSummary.critical} critical, ${gateSummary.warning} warning, ${gateSummary.info} info).`,
          );
          process.exitCode = EXIT.GATE;
        } else if (opts.strictBaseline && cmp && cmp.stale.length > 0) {
          logger.error(`Gate failed: ${cmp.stale.length} stale baseline suppression(s) (--strict-baseline). Re-run with --write-baseline.`);
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
              cliCommand: c.cliCommand ?? null,
              cliModel: c.cliModel ?? null,
              codexEnabled: c.codexEnabled !== false,
              warnBeforeExternalSend: c.warnBeforeExternalSend,
              defaultPorts: c.defaultPorts,
              probeCommonPaths: c.probeCommonPaths,
            },
            null,
            2,
          ),
        );
      });
    });

  program
    .command('badge')
    .description('Run a static scan and print a markdown score badge for your README')
    .argument('[path]', 'path to the project', '.')
    .option('--write-svg <file>', 'also write a local SVG badge to this file (no network)')
    .action(async (path: string, opts) => {
      await guard(async () => {
        setQuiet(true);
        const report = await Orchestrator.analyze(path, { yes: true, noAi: true, noDynamic: true, json: true });
        setQuiet(false);
        console.log(badgeMarkdown(report.score));
        if (opts.writeSvg) {
          fs.writeFileSync(opts.writeSvg, badgeSvg(report.score));
          logger.success(`Wrote SVG badge to ${opts.writeSvg}`);
        }
      });
    });

  program
    .command('mcp')
    .description('Start the MCP server (stdio) so your coding agent can scan, fix and verify')
    .argument('[path]', 'default project for tool calls', '.')
    .action(async (path: string) => {
      await guard(async () => {
        await startMcpServer(path);
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

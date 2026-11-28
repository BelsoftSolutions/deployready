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
  releaseExitCode,
  type BaselineComparison,
} from '../core/CiGate';
import { parseReleasePolicy, parseReleaseStateThreshold, withRelease } from '../core/releaseState';
import { logger, setVerbose, setQuiet } from '../utils/logger';
import { getVersion } from '../utils/version';
import { renderTokenHelp } from '../active/tokenHelp';
import { projectDeclaresIdentities } from '../active/projectConfig';
import { initPolicy } from '../active/policyInit';
import { CodeParser } from '../parser/CodeParser';
import { FileWalker } from '../utils/FileWalker';
import { runAnalyzeFix } from '../mcp/analyzeFix';
import { startMcpServer } from '../mcp/server';
import { badgeMarkdown, badgeSvg } from '../ui/badge';
import { toSarif } from '../ui/Sarif';
import { renderJson } from '../ui/sanitize';
import { parseOwnedHosts } from '../active/scope';
import { describeSession, loadSession, recordSession, scriptedLogin } from '../auth';

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
    .option('-y, --yes', 'auto-approve prompts (non-interactive); never approves sending data to an external AI provider, see --allow-external-ai', false)
    .option('--fix', 'apply safe deterministic fixes (with backups), then re-scan and report the new score', false)
    .option('--no-dynamic', 'skip live localhost testing')
    .option('--no-ai', 'skip AI analysis (local results only)')
    .option('--allow-external-ai', 'allow sending the redacted report to an external AI provider (API or claude/codex CLI) without a prompt; needed for AI in --yes/--json/CI runs', false)
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
      '--fail-on-release-state <state>',
      'exit 2 if the release state is at/worse than this (ready-with-accepted-risks | review-required | not-ready | insufficient-evidence); exit 3 when it is insufficient-evidence',
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
    .option('--active', 'run active (authenticated) authorization tests — needs --token, or identities + a policy in .deployready.json (docs/AUTHZ.md)', false)
    .option('--token <jwt>', 'bearer JWT for the active scan (your test user)')
    .option('--token-b <jwt>', 'second-identity JWT, for tenant/IDOR isolation tests')
    .option('--supabase', 'run live, read-only Supabase checks (only on a local or proven-owned project; see docs/SUPABASE.md)', false)
    .option('--supabase-url <url>', 'Supabase project URL (default: $SUPABASE_URL, then the project files)')
    .option('--supabase-anon-key <key>', 'anon/publishable key (default: $SUPABASE_ANON_KEY, then the project files)')
    .option('--supabase-service-key <key>', 'service_role key proving ownership (prefer $SUPABASE_SERVICE_ROLE_KEY)')
    .option('--supabase-access-token <token>', 'Supabase access token proving ownership (prefer $SUPABASE_ACCESS_TOKEN)')
    .option('--supabase-cross-user', 'also test whether test user A can read user B\'s rows ($SUPABASE_TEST_USER_A_EMAIL/_PASSWORD, _B_)', false)
    .option('--firebase-emulator', 'prove Firebase security rules with the Firebase Emulator Suite (needs your own firebase-tools + Java; localhost only; see docs/FIREBASE.md)', false)
    .option('--safety-level <level>', 'active-scan safety level: passive | read-only (default) | controlled-active | stateful')
    .option('--dry-run', 'list the active requests (or the authorization-matrix plan) that would be sent, without sending any', false)
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
        const releaseThreshold = opts.failOnReleaseState ? parseReleaseStateThreshold(opts.failOnReleaseState) : undefined;
        if (opts.json) setQuiet(true); // keep stdout clean for JSON consumers

        // Active scan needs a token; if asked for without one, show how to get it.
        let active = Boolean(opts.active);
        if (active && !opts.token && !projectDeclaresIdentities(path)) {
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
          allowExternalAi: opts.allowExternalAi === true,
          aggressive: opts.aggressive,
          probeCommonPaths: opts.probeCommonPaths as boolean | undefined, // undefined = not on the command line
          export: opts.export,
          html: opts.html,
          open: opts.open,
          json: opts.json,
          active,
          token: opts.token,
          tokenB: opts.tokenB,
          firebaseEmulator: Boolean(opts.firebaseEmulator),
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
          activeRequested: Boolean(opts.active),
          safetyLevel: opts.safetyLevel as string | undefined,
          dryRun: Boolean(opts.dryRun),
        };
        let report = await Orchestrator.analyze(path, analyzeOpts);
        const fixOutcome = opts.fix ? await runAnalyzeFix(path, report, analyzeOpts, opts) : undefined;
        if (fixOutcome) report = fixOutcome.report;
        const releaseCtx = {
          policy: report.release?.policy ?? parseReleasePolicy(undefined).policy,
          policyWarnings: report.release?.policyWarnings,
          verification: report.release?.verification
            ? { fixedVerified: report.release.verification.fixedVerified, fixedUnverified: report.release.verification.fixedUnverified }
            : undefined,
        };

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
          // Grandfathered findings are accepted risks: they do not block, but the release state says so.
          const before = report.release?.state;
          report = withRelease(report, { ...releaseCtx, accepted: cmp.known });
          if (!opts.json) {
            for (const w of cmp.warnings) logger.warn(w);
            logger.info(`Baseline: ${cmp.known.length} known finding(s) grandfathered.\n${describeComparison(cmp).join('\n')}`);
            if (report.release && report.release.state !== before) logger.info(report.release.line);
          }
        }

        if (opts.json) {
          const body = toCiJson(report, failOn, cmp, { failOnReleaseState: releaseThreshold });
          if (fixOutcome) body.fix = fixOutcome.fix;
          process.stdout.write(renderJson(body));
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
        } else if (releaseExitCode(report.release, releaseThreshold) !== EXIT.OK) {
          const code = releaseExitCode(report.release, releaseThreshold);
          logger.error(
            `Gate failed: release state "${report.release?.state}" is at or worse than "${releaseThreshold}" (--fail-on-release-state). ${report.release?.line ?? ''}`,
          );
          process.exitCode = code;
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

  const policyCmd = program.command('policy').description('Authorization policy for the active matrix (docs/AUTHZ.md)');
  policyCmd
    .command('init')
    .description('Draft an authorization policy from the discovered routes into .deployready.json (marked as a DRAFT for you to review)')
    .argument('[path]', 'path to the project', '.')
    .option('--force', 'replace an existing active.policy', false)
    .option('--print', 'print the draft instead of writing it', false)
    .action(async (path: string, opts: { force?: boolean; print?: boolean }) => {
      await guard(async () => {
        const root = await FileWalker.resolveRoot(path);
        const graph = await CodeParser.analyze(root);
        const res = await initPolicy(root, graph.routes, { force: opts.force === true, print: opts.print === true });
        if (!res.written) {
          process.stdout.write(res.json);
          return;
        }
        logger.success(`Wrote a DRAFT policy (${res.resources} resource(s), ${res.excluded} route(s) excluded) to ${res.file}.`);
        logger.warn('Every access level is a guess from the route name. Review it, fill in identities (tokenEnv, params, objects), set "draft": false, then run `deployready analyze --active --dry-run` to see the matrix plan.');
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
    .argument('[path]', 'server root: tool calls may only use this directory and its subdirectories', '.')
    .option('--allow-fixes', 'also expose apply_safe_fixes, which writes files (with backups) in the project', false)
    .option('--allow-live', 'also expose tools that send requests: scan_live, supabase_check_live, live verify', false)
    .action(async (path: string, opts: { allowFixes?: boolean; allowLive?: boolean }) => {
      await guard(async () => {
        await startMcpServer(path, { allowFixes: opts.allowFixes === true, allowLive: opts.allowLive === true });
      });
    });

  const auth = program
    .command('auth')
    .description('Save a logged-in browser session (cookies + localStorage) for authenticated testing; sessions are secrets');

  auth
    .command('record')
    .description('Open a browser, log in by hand, press Enter: saves .deployready/sessions/<name>.json (mode 0600)')
    .argument('<name>', 'session name')
    .requiredOption('--url <loginUrl>', 'login page URL (loopback, or a host you own)')
    .option('--i-own-this-target <host>', 'confirm you own a non-loopback host (repeatable, comma-separated)', collect, [] as string[])
    .option('--root <dir>', 'project root that holds .deployready/', '.')
    .action(async (name: string, opts: { url: string; iOwnThisTarget: string[]; root: string }) => {
      await guard(async () => {
        const file = await recordSession({
          root: opts.root,
          name,
          url: opts.url,
          ownedHosts: parseOwnedHosts(opts.iOwnThisTarget),
          log: (m) => logger.info(m),
        });
        logger.success(`Session "${name}" saved to ${file} (values are not shown).`);
        logger.info(describeSession(loadSession(opts.root, name)));
      });
    });

  auth
    .command('login')
    .description('Scripted form login for a TEST account (credentials from env vars only)')
    .argument('<name>', 'session name')
    .requiredOption('--url <loginUrl>', 'login page URL (loopback, or a host you own)')
    .requiredOption('--username-env <VAR>', 'env var holding the username')
    .requiredOption('--password-env <VAR>', 'env var holding the password')
    .option('--username-selector <css>', 'CSS selector of the username field')
    .option('--password-selector <css>', 'CSS selector of the password field')
    .option('--submit-selector <css>', 'CSS selector of the submit button')
    .option('--i-own-this-target <host>', 'confirm you own a non-loopback host (repeatable, comma-separated)', collect, [] as string[])
    .option('--root <dir>', 'project root that holds .deployready/', '.')
    .action(
      async (
        name: string,
        opts: {
          url: string;
          usernameEnv: string;
          passwordEnv: string;
          usernameSelector?: string;
          passwordSelector?: string;
          submitSelector?: string;
          iOwnThisTarget: string[];
          root: string;
        },
      ) => {
        await guard(async () => {
          const username = process.env[opts.usernameEnv];
          const password = process.env[opts.passwordEnv];
          if (!username || !password) {
            throw new Error(`Set the ${opts.usernameEnv} and ${opts.passwordEnv} environment variables (credentials are never taken from flags).`);
          }
          const file = await scriptedLogin({
            root: opts.root,
            name,
            url: opts.url,
            username,
            password,
            ...(opts.usernameSelector ? { usernameSelector: opts.usernameSelector } : {}),
            ...(opts.passwordSelector ? { passwordSelector: opts.passwordSelector } : {}),
            ...(opts.submitSelector ? { submitSelector: opts.submitSelector } : {}),
            ownedHosts: parseOwnedHosts(opts.iOwnThisTarget),
          });
          logger.success(`Session "${name}" saved to ${file} (values are not shown).`);
          logger.info(describeSession(loadSession(opts.root, name)));
        });
      },
    );

  return program;
}

function collect(value: string, prev: string[]): string[] {
  return [...prev, value];
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

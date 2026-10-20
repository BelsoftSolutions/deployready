/**
 * Runs the full scan pipeline and wires every module together:
 *   parse -> static scan -> (consent) dynamic scan -> aggregate
 *        -> (consent) AI analysis -> present -> export
 *
 * All "ask before acting" safety gates live here (dynamic probing, external
 * AI send). Everything below is non-interactive and pure.
 */
import * as path from 'path';
import inquirer from 'inquirer';
import ora from 'ora';
import { CodeParser } from '../parser/CodeParser';
import { FileWalker } from '../utils/FileWalker';
import { VulnerabilityDetector } from '../analysis/VulnerabilityDetector';
import { IssueAggregator } from '../analysis/IssueAggregator';
import { LocalhostDetector } from '../dynamic/LocalhostDetector';
import { DynamicTester, skippedScanNote } from '../dynamic/DynamicTester';
import { runCommonPathProbe, MAX_PROBE_REQUESTS } from '../dynamic/commonPaths/prober';
import { PROBE_PATHS } from '../dynamic/commonPaths/signatures';
import { ModelRouter } from '../ai/ModelRouter';
import { verifyAiFindings, droppedNote } from '../ai/verifyAiFindings';
import { ConfigManager } from '../config/ConfigManager';
import { IssuePresenter } from '../ui/IssuePresenter';
import { ExportManager } from '../ui/ExportManager';
import { openInBrowser } from '../utils/openBrowser';
import { logger } from '../utils/logger';
import { getVersion } from '../utils/version';
import { decodeJwt } from '../active/jwt';
import { planActiveRequests } from '../active/requestPlan';
import { createActiveHttpAdapter } from '../active/httpAdapter';
import { runActiveScan } from '../active/runner';
import type { CodeGraph, CommonPathReport, DynamicResults, Finding, ScanReport } from '../types';

export interface AnalyzeOptions {
  /** Auto-approve all consent prompts (CI / non-interactive). */
  yes?: boolean;
  /** Skip the live localhost dynamic suite. */
  noDynamic?: boolean;
  /** Skip the AI analysis step. */
  noAi?: boolean;
  /** Enable aggressive tests (rate-limit burst). Requires consent or --yes. */
  aggressive?: boolean;
  /** Write a markdown report to the project root. */
  export?: boolean;
  /** Write an HTML dashboard report to the project root. */
  html?: boolean;
  /** Open the HTML dashboard in the browser after the scan (implies html). */
  open?: boolean;
  /** Suppress the pretty terminal report (caller emits machine-readable JSON). */
  json?: boolean;
  /** Run the active (authenticated) authorization tests. Requires `token`. */
  active?: boolean;
  /** Bearer JWT for the primary test identity (active scan). */
  token?: string;
  /** Optional second-identity JWT — enables the cleanest tenant/IDOR proof. */
  tokenB?: string;
  /**
   * Opt-in common-path probe. Tri-state: `true`/`false` = given on the command line,
   * `undefined` = not given (then the config key applies, in interactive runs only).
   */
  probeCommonPaths?: boolean;
  /** Pause between probe requests in ms (default 250). Tests set 0. */
  commonPathDelayMs?: number;
}

interface ProbeDecision {
  /** Run the probe (still needs a dynamic scan, a local server and, interactively, a confirm). */
  enabled: boolean;
  nonInteractive: boolean;
  /** Print the "probe exists, is off" hint after the dynamic step. */
  hint: boolean;
}

const PROBE_HINT =
  'Tip: DeployReady has an opt-in common-path probe (it checks a fixed, printed list of well-known paths such as /.env on your local app). It is off. Enable it with --probe-common-paths; see docs/COMMON-PATH-PROBE.md.';

export class Orchestrator {
  static async analyze(target: string, opts: AnalyzeOptions = {}): Promise<ScanReport> {
    await FileWalker.resolveRoot(target);
    const projectPath = path.resolve(target);
    const startedAt = new Date().toISOString();

    // ---- 1. Static parse + vulnerability scan ----
    const spinner = ora('Parsing codebase…').start();
    const graph = await CodeParser.analyze(projectPath);
    spinner.text = 'Scanning for static vulnerabilities…';
    const staticFindings = await VulnerabilityDetector.scan(projectPath);
    spinner.succeed(
      `Static analysis done — ${graph.fileCount} files, ${graph.routes.length} routes, ${staticFindings.length} findings.`,
    );
    if (!opts.json && graph.gitignoreSkipped) {
      logger.info(`Skipped ${graph.gitignoreSkipped} path(s) listed in .gitignore.`);
    }
    if (!opts.json) {
      if (graph.specFiles?.length) {
        logger.info(`Read routes from OpenAPI/Swagger file(s) on disk: ${graph.specFiles.join(', ')}.`);
      }
      for (const note of graph.discoveryNotes ?? []) logger.info(note);
    }

    // ---- 2. Dynamic (live) testing, with consent ----
    let dynamic: DynamicResults | undefined;
    if (!opts.noDynamic) {
      const probe = await Orchestrator.decideProbe(opts);
      dynamic = await Orchestrator.runDynamic(graph.routes, opts, probe, projectPath);
      if (probe.hint && !opts.json) logger.info(PROBE_HINT);
    }
    const dynamicFindings = dynamic?.findings ?? [];

    // ---- 2b. Active (authenticated) authorization testing, opt-in + consent ----
    let activeFindings: Finding[] = [];
    if (opts.active) {
      activeFindings = await Orchestrator.runActive(graph, opts);
    }

    // ---- 3. Aggregate (active findings are dynamic-sourced) ----
    let agg = IssueAggregator.process(staticFindings, [...dynamicFindings, ...activeFindings]);

    // ---- 4. Build report ----
    let report: ScanReport = {
      target: projectPath,
      startedAt,
      finishedAt: new Date().toISOString(),
      version: getVersion(),
      stack: graph.stack,
      graph,
      dynamic,
      findings: agg.findings,
      score: agg.score,
      summary: agg.summary,
    };

    // ---- 5. Optional AI analysis ----
    if (!opts.noAi) {
      report = await Orchestrator.runAi(report, opts);
    }

    // ---- 6. Present + export ----
    if (!opts.json) IssuePresenter.display(report);
    if (opts.export) {
      const file = await ExportManager.saveMarkdown(report, projectPath);
      logger.success(`Markdown report saved to ${file}`);
    }
    // --open implies an HTML report. Don't auto-open in JSON/CI mode.
    if (opts.html || opts.open) {
      const file = await ExportManager.saveHtml(report, projectPath);
      logger.success(`HTML dashboard saved to ${file}`);
      if (opts.open && !opts.json) {
        openInBrowser(file);
        logger.info(`Opening ${file} in your browser…`);
      }
    }

    return report;
  }

  /**
   * Whether the common-path probe is switched on for this run. In non-interactive
   * runs (--yes, --json, env CI) only the command-line flag enables it; the config
   * key alone never does, so a saved preference cannot start guessing paths in CI.
   */
  private static async decideProbe(opts: AnalyzeOptions): Promise<ProbeDecision> {
    const nonInteractive = Boolean(opts.yes || opts.json || process.env.CI);
    if (opts.probeCommonPaths === true) return { enabled: true, nonInteractive, hint: false };
    if (opts.probeCommonPaths === false || nonInteractive) return { enabled: false, nonInteractive, hint: false };
    const config = await ConfigManager.load();
    const enabled = config.probeCommonPaths === true;
    return { enabled, nonInteractive, hint: !enabled };
  }

  private static async runDynamic(
    routes: ScanReport['graph']['routes'],
    opts: AnalyzeOptions,
    probe: ProbeDecision,
    projectPath: string,
  ): Promise<DynamicResults | undefined> {
    if (routes.length === 0) {
      logger.info('No routes discovered; dynamic checks skipped.');
      const skipped: DynamicResults = {
        baseUrl: '',
        reachable: false,
        endpoints: [],
        probed: [],
        skipped: [],
        findings: [skippedScanNote('dynamic-skipped', 0, [])],
      };
      if (!probe.enabled) return skipped;
      // The normal scan sends nothing here, so there is no first prompt; the probe asks for its own consent.
      const config = await ConfigManager.load();
      const detect = ora('Looking for a local server on localhost…').start();
      const app = await LocalhostDetector.find(config.defaultPorts);
      if (!app) {
        detect.info('No local server found listening on common ports — skipping the common-path probe.');
        return skipped;
      }
      detect.succeed(`Found a local server listening on port ${app.port} (${app.baseUrl}).`);
      const outcome = await Orchestrator.runProbe(app.baseUrl, [], opts, probe);
      if (!outcome) return skipped;
      return {
        ...skipped,
        baseUrl: app.baseUrl,
        reachable: true,
        findings: [...skipped.findings, ...outcome.findings],
        commonPaths: outcome.report,
      };
    }
    const config = await ConfigManager.load();
    const detectSpinner = ora('Looking for a local server on localhost…').start();
    const app = await LocalhostDetector.find(config.defaultPorts);
    if (!app) {
      detectSpinner.info('No local server found listening on common ports — skipping live tests.');
      return undefined;
    }
    detectSpinner.succeed(`Found a local server listening on port ${app.port} (${app.baseUrl}).`);

    if (!opts.yes) {
      const { ok } = await inquirer.prompt<{ ok: boolean }>([
        {
          type: 'confirm',
          name: 'ok',
          message: `Run live security/performance tests against ${app.baseUrl}? (GET requests only)`,
          default: true,
        },
      ]);
      if (!ok) {
        logger.info('Skipping live tests by your choice.');
        return undefined;
      }
    }

    let aggressive = opts.aggressive ?? false;
    if (!aggressive && !opts.yes) {
      const { agg } = await inquirer.prompt<{ agg: boolean }>([
        {
          type: 'confirm',
          name: 'agg',
          message: 'Also run aggressive tests (sends a small burst to probe rate limiting)?',
          default: false,
        },
      ]);
      aggressive = agg;
    }

    const spinner = ora('Running live tests…').start();
    let results: DynamicResults;
    try {
      results = await DynamicTester.run(app.baseUrl, routes, { aggressive, projectPath });
      spinner.succeed(`Live tests done — ${results.findings.length} runtime findings.`);
    } catch (err) {
      spinner.fail(`Live testing failed: ${(err as Error).message}`);
      return undefined;
    }

    if (probe.enabled) {
      const outcome = await Orchestrator.runProbe(
        app.baseUrl,
        results.probed.map((p) => p.path),
        opts,
        probe,
      );
      if (outcome) {
        results = { ...results, findings: [...results.findings, ...outcome.findings], commonPaths: outcome.report };
      }
    }
    return results;
  }

  /**
   * The opt-in common-path probe. Prints the target, the exact paths and the cap
   * before any request; interactive runs then ask (default No), a flag on the
   * command line is its own consent. Paths the normal scan requested are excluded.
   */
  private static async runProbe(
    baseUrl: string,
    requested: string[],
    opts: AnalyzeOptions,
    probe: ProbeDecision,
  ): Promise<{ findings: Finding[]; report: CommonPathReport } | undefined> {
    const say = (msg: string): void => (opts.json ? logger.stderr(msg) : logger.info(msg));
    const norm = (p: string): string => (p.split(/[?#]/)[0] ?? '').toLowerCase().replace(/\/+$/, '') || '/';
    const covered = new Set(requested.map(norm));
    const paths = PROBE_PATHS.map((p) => p.path).filter((p) => !covered.has(norm(p)));

    say(`Common-path probe (opt-in): guessed paths, lower confidence. Target: ${baseUrl}`);
    say(
      `It will send at most ${MAX_PROBE_REQUESTS} GET requests (no cookies, redirects not followed): 1 random control path, then ${paths.length} well-known path(s):`,
    );
    for (const p of paths) say(`  GET ${p}`);
    const coveredCount = PROBE_PATHS.length - paths.length;
    if (coveredCount > 0) say(`  (${coveredCount} well-known path(s) not listed: the normal scan already requests them.)`);

    if (!probe.nonInteractive) {
      const { ok } = await inquirer.prompt<{ ok: boolean }>([
        {
          type: 'confirm',
          name: 'ok',
          message: `Send these guessed-path requests to ${baseUrl}?`,
          default: false,
        },
      ]);
      if (!ok) {
        logger.info('Skipping the common-path probe by your choice.');
        return undefined;
      }
    }

    const spinner = ora('Probing common paths…').start();
    try {
      const outcome = await runCommonPathProbe(baseUrl, { exclude: requested, delayMs: opts.commonPathDelayMs });
      const found = outcome.findings.length;
      spinner.succeed(`Common-path probe done — ${found} ${found === 1 ? 'path' : 'paths'} proven exposed.`);
      return outcome;
    } catch (err) {
      spinner.fail(`Common-path probe failed: ${(err as Error).message}`);
      return undefined;
    }
  }

  /**
   * Active authorization testing: replays the user's own authenticated GET
   * requests with a tampered identity to prove access control holds. Opt-in
   * (`--active --token …`), consented, loopback-only, GET-only.
   */
  private static async runActive(graph: CodeGraph, opts: AnalyzeOptions): Promise<Finding[]> {
    if (!opts.token) return []; // CLI shows token instructions; nothing to do here.
    const claims = decodeJwt(opts.token)?.payload;
    if (!claims) {
      logger.warn('Active scan: --token is not a valid JWT — skipping.');
      return [];
    }
    if (graph.routes.length === 0) {
      logger.info('No routes discovered; active checks skipped.');
      return [skippedScanNote('active-skipped', 0, [])];
    }

    const plan = planActiveRequests(graph.routes, claims);
    for (const line of plan.log) logger.debug(line);
    if (plan.requests.length === 0) {
      logger.info('Active scan: no discovered route can be requested with your token — skipping.');
      return [skippedScanNote('active-skipped', graph.routes.length, plan.skipped)];
    }

    const config = await ConfigManager.load();
    const detect = ora('Active scan: looking for a local server on localhost…').start();
    const app = await LocalhostDetector.find(config.defaultPorts);
    if (!app) {
      detect.info('Active scan: no local server found listening — start your app, then re-run. Skipping.');
      return [];
    }
    detect.succeed(`Active scan target: local server listening on port ${app.port} (${app.baseUrl})`);

    if (!opts.yes) {
      const { ok } = await inquirer.prompt<{ ok: boolean }>([
        {
          type: 'confirm',
          name: 'ok',
          message: `Run ACTIVE authenticated tests against ${app.baseUrl}? Sends real GET requests as your token, including identity-tampered variants (no writes).`,
          default: false,
        },
      ]);
      if (!ok) {
        logger.info('Skipping active scan by your choice.');
        return [];
      }
    }

    const { requests } = plan;
    const adapter = createActiveHttpAdapter({ baseUrl: app.baseUrl });
    const spinner = ora(`Active scan: probing ${requests.length} endpoint(s)…`).start();
    try {
      const findings = await runActiveScan({ token: opts.token, tokenB: opts.tokenB, requests }, adapter);
      spinner.succeed(`Active scan done — ${findings.length} access-control finding(s).`);
      return findings;
    } catch (err) {
      spinner.fail(`Active scan failed: ${(err as Error).message}`);
      return [];
    }
  }

  private static async runAi(report: ScanReport, opts: AnalyzeOptions): Promise<ScanReport> {
    if (!(await ConfigManager.exists()) && !process.env.ANTHROPIC_API_KEY && !process.env.OPENAI_API_KEY) {
      logger.info('No AI model configured — showing local results only. Run `deployready init` to enable AI analysis.');
      return report;
    }

    const config = await ConfigManager.load();
    const router = new ModelRouter(config);
    if (!router.isConfigured()) {
      logger.warn('AI model selected but not fully configured (missing API key or CLI) — skipping AI analysis.');
      return report;
    }
    const ready = await router.checkReady();
    if (ready.state !== 'ready') {
      logger.warn(`AI provider not ready: ${ready.message} Skipping AI analysis.`);
      return report;
    }

    // Consent before any external send.
    if (router.sendsExternally && config.warnBeforeExternalSend && !opts.yes) {
      logger.warn(router.consentNotice('report'));
      const { ok } = await inquirer.prompt<{ ok: boolean }>([
        { type: 'confirm', name: 'ok', message: 'Continue with AI analysis?', default: true },
      ]);
      if (!ok) {
        logger.info('Skipping AI analysis by your choice.');
        return report;
      }
    }

    const spinner = ora(`Analyzing with ${config.model}…`).start();
    try {
      const analysis = await router.analyze(report);
      const verified = await verifyAiFindings(analysis.findings as Finding[], report.target);
      const merged = IssueAggregator.process(report.findings, verified.findings);
      spinner.succeed('AI analysis complete.');
      let aiSummary = analysis.summary || '';
      if (verified.dropped > 0) {
        const note = droppedNote(verified.dropped);
        logger.warn(note);
        aiSummary = aiSummary ? `${aiSummary}\n(${note})` : note;
      }
      return {
        ...report,
        aiSummary: aiSummary || undefined,
        findings: merged.findings,
        score: merged.score,
        summary: merged.summary,
      };
    } catch (err) {
      spinner.fail(`AI analysis failed: ${(err as Error).message}`);
      return report; // degrade gracefully — local results still stand
    }
  }
}

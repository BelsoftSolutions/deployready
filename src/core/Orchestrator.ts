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
import { VulnerabilityDetector } from '../analysis/VulnerabilityDetector';
import { IssueAggregator } from '../analysis/IssueAggregator';
import { LocalhostDetector } from '../dynamic/LocalhostDetector';
import { DynamicTester } from '../dynamic/DynamicTester';
import { ModelRouter } from '../ai/ModelRouter';
import { ConfigManager } from '../config/ConfigManager';
import { IssuePresenter } from '../ui/IssuePresenter';
import { ExportManager } from '../ui/ExportManager';
import { openInBrowser } from '../utils/openBrowser';
import { logger } from '../utils/logger';
import { getVersion } from '../utils/version';
import { decodeJwt } from '../active/jwt';
import { buildActiveRequests } from '../active/requestPlan';
import { createActiveHttpAdapter } from '../active/httpAdapter';
import { runActiveScan } from '../active/runner';
import type { CodeGraph, DynamicResults, Finding, ScanReport } from '../types';

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
}

export class Orchestrator {
  static async analyze(target: string, opts: AnalyzeOptions = {}): Promise<ScanReport> {
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

    // ---- 2. Dynamic (live) testing, with consent ----
    let dynamic: DynamicResults | undefined;
    if (!opts.noDynamic) {
      dynamic = await Orchestrator.runDynamic(graph.routes, opts);
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

  private static async runDynamic(
    routes: ScanReport['graph']['routes'],
    opts: AnalyzeOptions,
  ): Promise<DynamicResults | undefined> {
    const config = await ConfigManager.load();
    const detectSpinner = ora('Looking for a running app on localhost…').start();
    const app = await LocalhostDetector.find(config.defaultPorts);
    if (!app) {
      detectSpinner.info('No running app found on common ports — skipping live tests.');
      return undefined;
    }
    detectSpinner.succeed(`Found a running app at ${app.baseUrl}.`);

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
    try {
      const results = await DynamicTester.run(app.baseUrl, routes, { aggressive });
      spinner.succeed(`Live tests done — ${results.findings.length} runtime findings.`);
      return results;
    } catch (err) {
      spinner.fail(`Live testing failed: ${(err as Error).message}`);
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

    const config = await ConfigManager.load();
    const detect = ora('Active scan: looking for a running app on localhost…').start();
    const app = await LocalhostDetector.find(config.defaultPorts);
    if (!app) {
      detect.info('Active scan: no running app found — start your app, then re-run. Skipping.');
      return [];
    }
    detect.succeed(`Active scan target: ${app.baseUrl}`);

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

    const requests = buildActiveRequests(graph.routes, claims);
    if (requests.length === 0) {
      logger.info('Active scan: no testable GET routes resolved from your token — skipping.');
      return [];
    }

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
      logger.warn('AI model selected but not fully configured (missing API key) — skipping AI analysis.');
      return report;
    }

    // Consent before any external send.
    if (router.sendsExternally && config.warnBeforeExternalSend && !opts.yes) {
      logger.warn(`This will send a STRUCTURED findings report (no source code, secrets redacted) to the ${config.model} API.`);
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
      const merged = IssueAggregator.process(report.findings, analysis.findings as Finding[]);
      spinner.succeed('AI analysis complete.');
      return {
        ...report,
        aiSummary: analysis.summary || undefined,
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

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
import { logger } from '../utils/logger';
import type { DynamicResults, Finding, ScanReport } from '../types';

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
  /** Suppress the pretty terminal report (caller emits machine-readable JSON). */
  json?: boolean;
}

const VERSION = '0.1.0';

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

    // ---- 3. Aggregate ----
    let agg = IssueAggregator.process(staticFindings, dynamicFindings);

    // ---- 4. Build report ----
    let report: ScanReport = {
      target: projectPath,
      startedAt,
      finishedAt: new Date().toISOString(),
      version: VERSION,
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
      logger.success(`Report saved to ${file}`);
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

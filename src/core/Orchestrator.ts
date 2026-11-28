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
import { VulnerabilityDetector, type StaticScanIssues } from '../analysis/VulnerabilityDetector';
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
import { supabaseStep, type SupabaseOptions } from '../supabase';
import { firebaseStep } from '../firebase';
import { assertActiveTarget, parseOwnedHosts } from '../active/scope';
import { planMutationProbes, runMutationProbes } from '../active/mutationProbe';
import { assertLoopback } from '../dynamic/httpClient';
import { runEngines, dedupeAgainstNative, type EngineStepOptions } from '../adapters';
import { allowsMutationProbes, assertSafetyAllowed, resolveActivePolicy, type ActivePolicy } from '../active/safety';
import { previewActivePlan } from '../active/dryRun';
import type { CodeGraph, CommonPathReport, DynamicResults, Finding, ReleasePolicy, ScanReport } from '../types';
import { CoverageRecorder, buildCoverage, recordEngineCoverage } from './coverage';
import { parseReleasePolicy, withRelease } from './releaseState';

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
  /** Base URL for the active scan; default = the local server found on localhost. */
  activeUrl?: string;
  /** Non-loopback hosts the user explicitly confirmed they own (--i-own-this-target). */
  ownedHosts?: string[];
  /** Active-scan safety level (passive | read-only | controlled-active | stateful); default read-only. */
  safetyLevel?: string;
  /** List the active requests that would be sent, without sending any. */
  dryRun?: boolean;
  /**
   * Opt-in common-path probe. Tri-state: `true`/`false` = given on the command line,
   * `undefined` = not given (then the config key applies, in interactive runs only).
   */
  probeCommonPaths?: boolean;
  /** Pause between probe requests in ms (default 250). Tests set 0. */
  commonPathDelayMs?: number;
  /** Supabase module: static checks always run; `live` enables the ownership-gated probes. */
  supabase?: SupabaseOptions;
  /** `--active` was asked for (even if the CLI then dropped it for want of a token): a skip then matters. */
  activeRequested?: boolean;
  /** Release policy override; default: config `releasePolicy`, then the built-in policy. */
  releasePolicy?: Partial<ReleasePolicy>;
  /** External engine adapters (npm audit, OSV-Scanner, pip-audit, Semgrep); see docs/ENGINES.md. */
  engines?: EngineStepOptions;
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
    const cov = new CoverageRecorder();

    // ---- 1. Static parse + vulnerability scan ----
    const spinner = ora('Parsing codebase…').start();
    const graph = await CodeParser.analyze(projectPath);
    spinner.text = 'Scanning for static vulnerabilities…';
    const staticIssues: StaticScanIssues = { unreadable: [] };
    const staticFindings = await VulnerabilityDetector.scan(projectPath, staticIssues);
    Orchestrator.recordStaticIssues(cov, staticIssues);
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
      dynamic = await Orchestrator.runDynamic(graph.routes, opts, probe, projectPath, cov);
      if (probe.hint && !opts.json) logger.info(PROBE_HINT);
    } else {
      cov.set('dynamic', 'untested', 'Disabled (--no-dynamic).');
    }
    const dynamicFindings = dynamic?.findings ?? [];

    // ---- 2b. Active (authenticated) authorization testing, opt-in + consent ----
    let activeFindings: Finding[] = [];
    if (opts.active) {
      activeFindings = await Orchestrator.runActive(graph, opts, cov);
    } else if (opts.activeRequested) {
      cov.set('active', 'untested', '--active was given without a --token; nothing was tested.', { requested: true });
    }

    // ---- 2c. Supabase (static always; live only when owned + opted in) ----
    const sb = await supabaseStep(projectPath, opts);
    const fb = await firebaseStep(projectPath, opts);
    if (sb.coverage) {
      const rls = staticIssues.rlsFiles && sb.coverage.static.state === 'passed' ? ` RLS replayed over ${staticIssues.rlsFiles} SQL migration file(s).` : '';
      cov.set('supabase-static', sb.coverage.static.state, sb.coverage.static.reason + rls);
      cov.set('supabase-live', sb.coverage.live.state, sb.coverage.live.reason, { requested: sb.coverage.live.requested });
    }
    if (fb.coverage) cov.set('firebase', fb.coverage.state, fb.coverage.reason);

    // ---- 2d. External engines (installed + applicable only; failures are reported, never silent) ----
    const eng = await runEngines(projectPath, opts.engines ?? {});
    const deduped = dedupeAgainstNative([...staticFindings, ...sb.staticFindings, ...fb.staticFindings], eng.findings);
    if (!opts.json) for (const r of eng.runs) if (r.status === 'error') logger.warn(`Engine ${r.id} incomplete: ${r.reason}`);
    recordEngineCoverage(cov, eng.runs, opts.engines);

    // ---- 3. Aggregate (active findings are dynamic-sourced) ----
    let agg = IssueAggregator.process(
      [...deduped.native, ...deduped.engine],
      [...dynamicFindings, ...activeFindings, ...sb.liveFindings],
    );

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
      engineRuns: eng.runs,
    };

    // ---- 5. Optional AI analysis ----
    if (!opts.noAi) {
      report = await Orchestrator.runAi(report, opts, cov);
    } else {
      cov.set('ai', 'untested', 'Disabled (--no-ai).');
    }

    // ---- 5b. Coverage + release state (separate from the score) ----
    report = withRelease({ ...report, coverage: buildCoverage(report, cov) }, await Orchestrator.releaseContext(opts));

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

  /** Unreadable files or a failed route discovery make the static area (and secrets, for files) partial. */
  private static recordStaticIssues(cov: CoverageRecorder, issues: StaticScanIssues): void {
    const parts: string[] = [];
    if (issues.unreadable.length) {
      const list = issues.unreadable.slice(0, 5).join(', ') + (issues.unreadable.length > 5 ? ', …' : '');
      parts.push(`${issues.unreadable.length} file(s) could not be read (${list})`);
      cov.set('secrets', 'inconclusive', `Secret detection skipped ${issues.unreadable.length} unreadable file(s) (${list}).`);
    }
    if (issues.routeAuthError) parts.push(`route discovery failed, so route-auth/IDOR checks did not run (${issues.routeAuthError})`);
    if (parts.length) cov.set('static', 'inconclusive', `Static scan partial: ${parts.join('; ')}.`);
  }

  /** Release policy: the option wins, then config `releasePolicy`, then the defaults. Never throws. */
  private static async releaseContext(opts: AnalyzeOptions): Promise<{ policy: ReleasePolicy; policyWarnings: string[] }> {
    let raw: unknown = opts.releasePolicy;
    if (raw === undefined) {
      try {
        raw = (await ConfigManager.load())?.releasePolicy;
      } catch {
        raw = undefined; // a broken config already fails elsewhere; the default policy applies here
      }
    }
    const { policy, warnings } = parseReleasePolicy(raw);
    for (const w of warnings) logger.warn(w);
    return { policy, policyWarnings: warnings };
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
    cov: CoverageRecorder = new CoverageRecorder(),
  ): Promise<DynamicResults | undefined> {
    if (routes.length === 0) {
      logger.info('No routes discovered; dynamic checks skipped.');
      cov.set('dynamic', 'untested', 'No routes discovered, so no route was requested.');
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
      cov.set('dynamic', 'untested', 'No local server found listening on the configured ports.');
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
        cov.set('dynamic', 'untested', 'Declined at the prompt.');
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
      cov.set('dynamic', 'failed', `Live testing errored: ${(err as Error).message}`, { requested: true });
      return undefined;
    }
    const requestedCount = results.probed?.length ?? 0;
    if (requestedCount === 0) cov.set('dynamic', 'inconclusive', 'A local server answered, but no discovered route could be requested safely.');
    else cov.set('dynamic', 'passed', `Requested ${requestedCount} discovered route(s) on ${app.baseUrl}.`);

    if (probe.enabled) {
      const outcome = await Orchestrator.runProbe(
        app.baseUrl,
        results.probed.map((p) => p.path),
        opts,
        probe,
      );
      if (outcome) {
        results = { ...results, findings: [...results.findings, ...outcome.findings], commonPaths: outcome.report };
      } else if (probe.nonInteractive) {
        cov.degrade('dynamic', 'inconclusive', 'The common-path probe was enabled but did not complete.');
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
   * (`--active --token …`), consented, loopback-only unless an owned host is
   * declared, and bounded by the safety level (default read-only: GET only,
   * side-effect-looking and denylisted routes skipped) and a request budget.
   */
  private static async runActive(graph: CodeGraph, opts: AnalyzeOptions, cov: CoverageRecorder = new CoverageRecorder()): Promise<Finding[]> {
    const skip = (reason: string): void => cov.set('active', 'untested', reason, { requested: true });
    if (!opts.token) {
      skip('--active was given without a --token; nothing was tested.');
      return []; // CLI shows token instructions; nothing to do here.
    }
    const claims = decodeJwt(opts.token)?.payload;
    if (!claims) {
      logger.warn('Active scan: --token is not a valid JWT — skipping.');
      skip('--token is not a valid JWT.');
      return [];
    }
    if (graph.routes.length === 0) {
      logger.info('No routes discovered; active checks skipped.');
      skip('No routes discovered.');
      return [skippedScanNote('active-skipped', 0, [])];
    }

    const config = await ConfigManager.load();
    let policy: ActivePolicy;
    try {
      policy = resolveActivePolicy(config, { safetyLevel: opts.safetyLevel });
    } catch (err) {
      logger.warn(`Active scan: ${(err as Error).message} Skipping.`);
      skip(`Active safety settings rejected: ${(err as Error).message}`);
      return [];
    }

    const plan = planActiveRequests(graph.routes, claims, {
      safetyLevel: policy.safetyLevel === 'passive' ? 'read-only' : policy.safetyLevel, // passive still previews the read-only plan
      unsafeRoutes: policy.unsafeRoutes,
    });
    for (const line of plan.log) logger.debug(line);
    if (plan.requests.length === 0) {
      logger.info('Active scan: no discovered route can be requested with your token — skipping.');
      skip('No discovered route can be requested with the token given.');
      return [skippedScanNote('active-skipped', graph.routes.length, plan.skipped)];
    }

    // Ownership guard: loopback only, unless the user named the host they own.
    let owned: string[];
    try {
      owned = parseOwnedHosts([...(opts.ownedHosts ?? []), ...(Array.isArray(config.ownedTargets) ? config.ownedTargets : [])]);
    } catch (err) {
      logger.warn(`Active scan: ${(err as Error).message} Skipping.`);
      skip(`Owned-target list rejected: ${(err as Error).message}`);
      return [];
    }
    const preview = opts.dryRun || policy.safetyLevel === 'passive';
    let app: { baseUrl: string } | undefined;
    if (opts.activeUrl) {
      try {
        assertActiveTarget(opts.activeUrl, owned);
      } catch (err) {
        logger.warn(`Active scan: ${(err as Error).message} Skipping.`);
        skip(`Target refused: ${(err as Error).message}`);
        return [];
      }
      app = { baseUrl: opts.activeUrl };
      logger.info(`Active scan target: ${app.baseUrl}`);
    } else if (!preview) {
      const detect = ora('Active scan: looking for a local server on localhost…').start();
      const local = await LocalhostDetector.find(config.defaultPorts);
      if (!local) {
        detect.info('Active scan: no local server found listening — start your app, then re-run. Skipping.');
        skip('No local server found listening.');
        return [];
      }
      detect.succeed(`Active scan target: local server listening on port ${local.port} (${local.baseUrl})`);
      app = local;
    }
    let loopback = true;
    try {
      assertLoopback(app?.baseUrl ?? 'http://localhost');
    } catch {
      loopback = false;
    }
    if (app) {
      try {
        assertSafetyAllowed(policy, app.baseUrl, owned);
      } catch (err) {
        logger.warn(`Active scan: ${(err as Error).message} Skipping.`);
        skip(`Safety level "${policy.safetyLevel}" not allowed here: ${(err as Error).message}`);
        return [];
      }
    }
    // Write-route probe: controlled-active or higher, loopback only, never on an owned remote host.
    const mutation =
      loopback && allowsMutationProbes(policy.safetyLevel)
        ? planMutationProbes(graph.routes, undefined, { unsafeRoutes: policy.unsafeRoutes })
        : { targets: [], skipped: [] };
    for (const s of mutation.skipped) logger.debug(`[active] skip ${s.method} ${s.path}: ${s.reason}`);

    if (preview) {
      const dry = previewActivePlan({
        baseUrl: app?.baseUrl,
        safetyLevel: policy.safetyLevel,
        requests: plan.requests,
        tokenBClaims: opts.tokenB ? decodeJwt(opts.tokenB)?.payload ?? null : null,
        mutationTargets: mutation.targets,
        skipped: [...plan.skipped, ...mutation.skipped],
        maxRequests: policy.maxRequests,
      });
      for (const line of dry.lines) logger.info(line);
      // A preview sends nothing: chosen on purpose, so untested but not a requested area that went missing.
      cov.set(
        'active',
        'untested',
        opts.dryRun
          ? `Dry run (--dry-run): ${plan.requests.length} request(s) planned at safety level "${policy.safetyLevel}", none sent.`
          : `Safety level "passive": the plan was previewed, no request was sent.`,
        { requested: false },
      );
      return [];
    }
    const target = app!;

    if (!opts.yes) {
      const { ok } = await inquirer.prompt<{ ok: boolean }>([
        {
          type: 'confirm',
          name: 'ok',
          message: `Run ACTIVE authenticated tests (safety level "${policy.safetyLevel}", at most ${policy.maxRequests} requests) against ${target.baseUrl}? Sends real GET requests as your token, including identity-tampered variants${
            mutation.targets.length
              ? `, plus ${mutation.targets.length} unauthenticated DELETE/PATCH request(s) aimed at a record id that cannot exist (no body; no real data is addressed)`
              : ' (no writes)'
          }. Preview them first with --dry-run.`,
          default: false,
        },
      ]);
      if (!ok) {
        logger.info('Skipping active scan by your choice.');
        cov.set('active', 'untested', 'Declined at the prompt.', { requested: false });
        return [];
      }
    }

    const { requests } = plan;
    const adapter = createActiveHttpAdapter({ baseUrl: target.baseUrl, ownedHosts: owned, maxRequests: policy.maxRequests });
    const spinner = ora(`Active scan: probing ${requests.length} endpoint(s)…`).start();
    try {
      const verdicts = new Map<string, number>();
      const findings = await runActiveScan(
        {
          token: opts.token,
          tokenB: opts.tokenB,
          requests,
          baseUrl: target.baseUrl,
          maxRequests: policy.maxRequests,
          ignoredFields: policy.ignoredFields,
          publicRoutes: policy.publicRoutes,
          onObserve: (o) => {
            if (o.kind === 'cross') verdicts.set(o.verdict, (verdicts.get(o.verdict) ?? 0) + 1);
            if (o.kind === 'untested') verdicts.set('untested', (verdicts.get('untested') ?? 0) + 1);
            if (o.kind === 'cross' || o.kind === 'untested') {
              logger.debug(`[active] ${o.kind === 'cross' ? `${o.verdict} ${o.tamperedPath}` : `untested ${o.endpoint}`}: ${o.reason}`);
            }
          },
        },
        adapter,
      );
      if (mutation.targets.length) findings.push(...(await runMutationProbes(mutation.targets, adapter, { baseUrl: target.baseUrl })));
      const summary = [...verdicts].map(([v, c]) => `${c} ${v}`).join(', ');
      spinner.succeed(`Active scan done — ${findings.length} access-control finding(s)${summary ? ` (cross-identity checks: ${summary})` : ''}.`);
      cov.set('active', 'passed', `Probed ${requests.length} endpoint(s) on ${target.baseUrl} with the test identity at safety level "${policy.safetyLevel}"${summary ? ` (cross-identity checks: ${summary})` : ''}.`, { requested: true });
      return findings;
    } catch (err) {
      spinner.fail(`Active scan failed: ${(err as Error).message}`);
      cov.set('active', 'failed', `Active scan errored: ${(err as Error).message}`, { requested: true });
      return [];
    }
  }

  private static async runAi(report: ScanReport, opts: AnalyzeOptions, cov: CoverageRecorder = new CoverageRecorder()): Promise<ScanReport> {
    if (!(await ConfigManager.exists()) && !process.env.ANTHROPIC_API_KEY && !process.env.OPENAI_API_KEY) {
      logger.info('No AI model configured — showing local results only. Run `deployready init` to enable AI analysis.');
      cov.set('ai', 'untested', 'No AI model configured.');
      return report;
    }

    const config = await ConfigManager.load();
    const router = new ModelRouter(config);
    if (!router.isConfigured()) {
      logger.warn('AI model selected but not fully configured (missing API key or CLI) — skipping AI analysis.');
      cov.set('ai', 'untested', 'AI model not fully configured (missing API key or CLI).');
      return report;
    }
    const ready = await router.checkReady();
    if (ready.state !== 'ready') {
      logger.warn(`AI provider not ready: ${ready.message} Skipping AI analysis.`);
      cov.set('ai', 'untested', `AI provider not ready: ${ready.message}`);
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
        cov.set('ai', 'untested', 'Declined at the prompt.');
        return report;
      }
    }

    const spinner = ora(`Analyzing with ${config.model}…`).start();
    try {
      const analysis = await router.analyze(report);
      const verified = await verifyAiFindings(analysis.findings as Finding[], report.target);
      const merged = IssueAggregator.process(report.findings, verified.findings);
      spinner.succeed('AI analysis complete.');
      cov.set('ai', 'passed', `AI analysis ran (${config.model}); its findings are unverified and never scored.`);
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
      cov.set('ai', 'failed', `AI analysis errored: ${(err as Error).message}`);
      return report; // degrade gracefully — local results still stand
    }
  }
}

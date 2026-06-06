/**
 * Interactive terminal session for EnterpriseReady. Stays open and accepts one
 * command per step (scan, parse, dynamic, ai, issues, fix, ...) until the user
 * exits. Holds the scan state in memory and updates the score live as issues
 * are fixed or ignored.
 *
 * All "ask before acting" gates live here: live probing, external AI sends, and
 * writing any fix to disk all require an explicit confirmation.
 */
import * as path from 'path';
import * as readline from 'readline';
import chalk from 'chalk';
import ora from 'ora';
import { CodeParser } from '../parser/CodeParser';
import { VulnerabilityDetector } from '../analysis/VulnerabilityDetector';
import { IssueAggregator } from '../analysis/IssueAggregator';
import { LocalhostDetector } from '../dynamic/LocalhostDetector';
import { DynamicTester } from '../dynamic/DynamicTester';
import { ModelRouter } from '../ai/ModelRouter';
import { ConfigManager } from '../config/ConfigManager';
import { ExportManager } from '../ui/ExportManager';
import { DeploymentGuide, type Platform } from '../ui/DeploymentGuide';
import { ScoreTracker } from '../tracker/ScoreTracker';
import { ChecklistManager } from '../tracker/ChecklistManager';
import { FileEditor } from '../agent/FileEditor';
import { FixManager } from '../agent/FixManager';
import { logger } from '../utils/logger';
import type { AppConfig, CodeGraph, DynamicResults, Finding, ScanReport, Severity } from '../types';

const VERSION = '0.1.0';

interface SessionState {
  target: string;
  graph: CodeGraph | null;
  staticFindings: Finding[];
  dynamic: DynamicResults | null;
  aiFindings: Finding[];
  aiSummary?: string;
}

export class InteractiveShell {
  private state: SessionState;
  private config!: AppConfig;
  private checklist: ChecklistManager | null = null;
  private ordered: Finding[] = [];
  private running = true;
  private rl: readline.Interface;
  // Buffered async line reader: lines are queued so none are dropped while a
  // command is running, and the same primitive serves nested prompts (confirm).
  private lineBuffer: string[] = [];
  private lineWaiters: ((line: string | null) => void)[] = [];
  private closed = false;

  constructor(target: string) {
    this.state = { target: path.resolve(target), graph: null, staticFindings: [], dynamic: null, aiFindings: [] };
    this.rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    this.rl.on('line', (line) => {
      const waiter = this.lineWaiters.shift();
      if (waiter) waiter(line);
      else this.lineBuffer.push(line);
    });
    // EOF (piped input ends) or Ctrl+C. Don't stop the loop here — let any
    // buffered commands drain first; ask() returns null once they're consumed.
    this.rl.on('close', () => {
      this.closed = true;
      while (this.lineWaiters.length) this.lineWaiters.shift()!(null);
    });
  }

  async start(): Promise<void> {
    this.config = await ConfigManager.load();
    this.banner();

    while (this.running) {
      const line = await this.ask(chalk.cyan('enterpriseready › '));
      if (line === null) break; // stream closed
      const trimmed = line.trim();
      if (!trimmed) continue;

      const [cmd, ...args] = trimmed.split(/\s+/);
      try {
        await this.dispatch(cmd!.toLowerCase(), args);
      } catch (err) {
        logger.error((err as Error).message || 'Command failed.');
      }
    }
    this.rl.close();
    console.log(chalk.gray('\nBye — stay enterprise ready. 👋\n'));
  }

  /** Write a prompt and read the next buffered line. Resolves null when closed. */
  private ask(prompt: string): Promise<string | null> {
    process.stdout.write(prompt);
    if (this.lineBuffer.length) return Promise.resolve(this.lineBuffer.shift()!);
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => this.lineWaiters.push(resolve));
  }

  private async dispatch(cmd: string, args: string[]): Promise<void> {
    switch (cmd) {
      case 'help': case '?': return this.help();
      case 'scan': return this.scan();
      case 'parse': return this.parse();
      case 'dynamic': case 'live': return this.dynamic();
      case 'ai': case 'analyze': return this.ai();
      case 'issues': case 'list': case 'ls': return this.issues(args[0]);
      case 'show': return this.show(args[0]);
      case 'fix': return this.fix(args[0]);
      case 'done': case 'resolve': return this.mark(args[0], 'fixed');
      case 'ignore': return this.mark(args[0], 'ignored');
      case 'score': return this.printScore();
      case 'status': return this.status();
      case 'deploy': return this.deploy(args[0]);
      case 'export': return this.export();
      case 'config': return this.showConfig();
      case 'clear': case 'cls': console.clear(); return;
      case 'exit': case 'quit': case 'q': this.running = false; return;
      default:
        logger.warn(`Unknown command "${cmd}". Type "help" for the list.`);
    }
  }

  // ---------------------------------------------------------------- steps

  private async parse(): Promise<void> {
    const spinner = ora('Parsing codebase + static scan…').start();
    this.state.graph = await CodeParser.analyze(this.state.target);
    this.state.staticFindings = await VulnerabilityDetector.scan(this.state.target);
    this.recompute();
    spinner.succeed(
      `Parsed ${this.state.graph.fileCount} files, ${this.state.graph.routes.length} routes — ${this.state.staticFindings.length} static findings.`,
    );
    this.printScore();
  }

  private async dynamic(): Promise<void> {
    const detect = ora('Looking for a running app on localhost…').start();
    const app = await LocalhostDetector.find(this.config.defaultPorts);
    if (!app) {
      detect.info('No running app found on common ports. Start your app, then run `dynamic` again.');
      return;
    }
    detect.succeed(`Found a running app at ${app.baseUrl}.`);

    if (!(await this.confirm(`Run live security/performance tests against ${app.baseUrl}? (GET only)`, true))) {
      logger.info('Skipped live tests.');
      return;
    }
    const aggressive = await this.confirm('Also run aggressive tests (small burst to probe rate limiting)?', false);

    const spinner = ora('Running live tests…').start();
    const routes = this.state.graph?.routes ?? [];
    this.state.dynamic = await DynamicTester.run(app.baseUrl, routes, { aggressive });
    this.recompute();
    spinner.succeed(`Live tests done — ${this.state.dynamic.findings.length} runtime findings.`);
    this.printScore();
  }

  private async ai(): Promise<void> {
    if (!this.hasFindings()) return logger.warn('Nothing to analyze yet. Run `parse` or `scan` first.');

    const router = new ModelRouter(this.config);
    if (!router.isConfigured()) {
      return logger.warn('No AI model configured. Run `enterpriseready init` (or set an API key) first.');
    }
    if (router.sendsExternally && this.config.warnBeforeExternalSend) {
      logger.warn(`This sends a STRUCTURED findings report (no source code, secrets redacted) to the ${this.config.model} API.`);
      if (!(await this.confirm('Continue with AI analysis?', true))) return logger.info('Skipped AI analysis.');
    }

    const spinner = ora(`Analyzing with ${this.config.model}…`).start();
    try {
      const analysis = await router.analyze(this.buildReport());
      this.state.aiFindings = analysis.findings;
      this.state.aiSummary = analysis.summary || undefined;
      this.recompute();
      spinner.succeed('AI analysis complete.');
      if (this.state.aiSummary) console.log('\n' + chalk.cyan('🤖 ') + this.state.aiSummary + '\n');
      this.printScore();
    } catch (err) {
      spinner.fail(`AI analysis failed: ${(err as Error).message}`);
    }
  }

  private async scan(): Promise<void> {
    await this.parse();
    await this.dynamic();
    if (new ModelRouter(this.config).isConfigured() && (await this.confirm('Run AI analysis on the findings?', false))) {
      await this.ai();
    }
    this.issues();
  }

  // ---------------------------------------------------------------- views

  private issues(filter?: string): void {
    if (!this.hasFindings()) return logger.warn('No findings yet. Run `scan` or `parse`.');
    const sev = this.parseSeverity(filter);
    let shown = 0;
    this.ordered.forEach((f, i) => {
      if (sev && f.severity !== sev) return;
      console.log(`  ${chalk.gray(String(i + 1).padStart(2))}. ${this.statusMark(f)} ${this.sevBadge(f.severity)} ${f.title}${this.locText(f)}`);
      shown++;
    });
    if (!shown) logger.info('No findings match that filter.');
    else console.log('');
    this.printScore();
  }

  private show(arg?: string): void {
    const f = this.findingAt(arg);
    if (!f) return;
    const refs = [f.owasp, f.cwe].filter(Boolean).join('  ');
    console.log('\n' + chalk.bold(f.title));
    console.log(`  ${this.sevBadge(f.severity)}  ${chalk.gray(`[${f.source}]`)}  ${chalk.gray(refs)}`);
    if (f.file || f.endpoint) console.log(`  ${chalk.gray('where:')} ${f.endpoint ?? `${f.file}:${f.line ?? '?'}`}`);
    if (f.evidence) console.log(`  ${chalk.gray('evidence:')} ${f.evidence}`);
    console.log(`  ${chalk.gray('what:')} ${f.description}`);
    console.log(`  ${chalk.gray('fix:')} ${f.recommendation}\n`);
  }

  private status(): void {
    console.log('');
    console.log(`  target:  ${this.state.target}`);
    console.log(`  parsed:  ${this.state.graph ? `yes (${this.state.graph.stack.stack})` : chalk.gray('no')}`);
    console.log(`  dynamic: ${this.state.dynamic ? `yes (${this.state.dynamic.baseUrl})` : chalk.gray('no')}`);
    console.log(`  ai:      ${this.state.aiFindings.length ? 'yes' : chalk.gray('no')}`);
    console.log(`  model:   ${this.config.model}`);
    console.log('');
    this.printScore();
  }

  // ---------------------------------------------------------------- fix flow

  private async fix(arg?: string): Promise<void> {
    const f = this.findingAt(arg);
    if (!f) return;
    this.show(arg);

    const editor = new FileEditor(this.state.target);

    // 1. Safe deterministic auto-fix.
    if (FixManager.autoFixable(f)) {
      if (await this.confirm('Apply the automatic fix for this issue?', true)) {
        const res = await FixManager.autoFix(f, editor);
        logger.success(res.message);
        if (res.backup) logger.info(`Backup: ${res.backup}`);
        this.markFinding(f, 'fixed');
        this.printScore();
      }
      return;
    }

    // 2. AI-proposed fix (needs file+line and a configured model).
    const router = new ModelRouter(this.config);
    if (FixManager.aiFixable(f) && router.isConfigured()) {
      if (!(await this.confirm('Ask the AI model to propose a code fix for this snippet?', true))) {
        return this.offerManualMark(f);
      }
      if (router.sendsExternally) {
        logger.warn('To fix code, the relevant snippet (secrets redacted) is sent to the AI model.');
        if (!(await this.confirm('Send the snippet and get a proposed fix?', true))) return this.offerManualMark(f);
      }
      await this.aiFixFlow(f, editor, router);
      return;
    }

    // 3. No automated path — show guidance and let the user mark it.
    logger.info('No automated fix available for this issue. Apply the recommendation above manually.');
    await this.offerManualMark(f);
  }

  private async aiFixFlow(f: Finding, editor: FileEditor, router: ModelRouter): Promise<void> {
    const spinner = ora('Asking the model for a fix…').start();
    let snippet, suggestion;
    try {
      snippet = await FixManager.snippetFor(f, editor);
      suggestion = await FixManager.aiSuggest(f, snippet, router);
      spinner.succeed('Proposed fix:');
    } catch (err) {
      spinner.fail(`Could not get a fix: ${(err as Error).message}`);
      return this.offerManualMark(f);
    }

    this.printDiff(f.file!, snippet.startLine, snippet.endLine, snippet.text, suggestion.newCode);
    if (suggestion.explanation) console.log(chalk.gray(`  why: ${suggestion.explanation}\n`));

    if (await this.confirm('Apply this fix to the file? (a backup is created first)', false)) {
      const backup = await FixManager.applySuggestion(f, snippet, suggestion.newCode, editor);
      logger.success(`Applied. Backup saved to ${backup}`);
      this.markFinding(f, 'fixed');
      this.printScore();
    } else {
      logger.info('Fix not applied.');
    }
  }

  private async offerManualMark(f: Finding): Promise<void> {
    const ans = (await this.ask('Mark as [o]pen / [f]ixed / [i]gnored (default open): ')) ?? '';
    const a = ans.trim().toLowerCase();
    if (a === 'f' || a === 'fixed') {
      this.markFinding(f, 'fixed');
      this.printScore();
    } else if (a === 'i' || a === 'ignored') {
      this.markFinding(f, 'ignored');
      this.printScore();
    }
  }

  private printDiff(file: string, start: number, end: number, oldText: string, newText: string): void {
    console.log(chalk.gray(`  ── ${file}:${start}-${end} ──`));
    for (const l of oldText.split('\n')) console.log(chalk.red(`  - ${l}`));
    for (const l of newText.split('\n')) console.log(chalk.green(`  + ${l}`));
    console.log('');
  }

  // ---------------------------------------------------------------- marking

  private mark(arg: string | undefined, status: 'fixed' | 'ignored'): void {
    const f = this.findingAt(arg);
    if (!f) return;
    this.markFinding(f, status);
    logger.success(`Marked "${f.title}" as ${status}.`);
    this.printScore();
  }

  private markFinding(f: Finding, status: 'fixed' | 'ignored'): void {
    this.checklist?.setStatus(f.id, status);
  }

  // ---------------------------------------------------------------- deploy/export/config

  private deploy(arg?: string): void {
    if (!this.state.graph) return logger.warn('Run `parse` or `scan` first so I know your stack.');
    const platform: Platform = arg === 'do' || arg === 'digitalocean' ? 'digitalocean' : 'aws';
    const steps = DeploymentGuide.generate(this.state.graph.stack.stack, platform);
    console.log('\n' + chalk.bold(`📦 Deployment guide — ${platform.toUpperCase()} (stack: ${this.state.graph.stack.stack})`));
    steps.forEach((s, i) => {
      console.log(`  ${i + 1}. ${s.title}`);
      if (s.command) console.log(chalk.gray(`     $ ${s.command}`));
    });
    console.log('');
  }

  private async export(): Promise<void> {
    if (!this.hasFindings()) return logger.warn('Nothing to export yet.');
    const file = await ExportManager.saveMarkdown(this.buildReport(), this.state.target);
    logger.success(`Report saved to ${file}`);
  }

  private showConfig(): void {
    const c = this.config;
    console.log(
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
  }

  // ---------------------------------------------------------------- helpers

  private recompute(): void {
    const prev = this.checklist?.toState();
    const agg = IssueAggregator.process(this.state.staticFindings, this.state.dynamic?.findings ?? [], this.state.aiFindings);
    this.ordered = agg.findings;
    this.checklist = new ChecklistManager(agg.findings);
    if (prev) this.checklist.applyState(prev);
  }

  private buildReport(): ScanReport {
    const open = this.checklist?.openFindings() ?? this.ordered;
    const agg = IssueAggregator.process(open);
    const graph: CodeGraph =
      this.state.graph ??
      { root: this.state.target, stack: { stack: 'unknown', language: 'unknown', evidence: [] }, entryPoints: [], modules: [], routes: [], fileCount: 0 };
    const now = new Date().toISOString();
    return {
      target: this.state.target,
      startedAt: now,
      finishedAt: now,
      version: VERSION,
      stack: graph.stack,
      graph,
      dynamic: this.state.dynamic ?? undefined,
      findings: this.ordered,
      score: agg.score,
      summary: agg.summary,
      aiSummary: this.state.aiSummary,
    };
  }

  private currentScore(): number {
    return ScoreTracker.current(this.checklist?.openFindings() ?? this.ordered);
  }

  private printScore(): void {
    if (!this.hasFindings()) return;
    const open = this.checklist?.openFindings() ?? this.ordered;
    const crit = open.filter((f) => f.severity === 'critical').length;
    const warn = open.filter((f) => f.severity === 'warning').length;
    const info = open.filter((f) => f.severity === 'info').length;
    const score = this.currentScore();
    const colored = score >= 80 ? chalk.green : score >= 50 ? chalk.yellow : chalk.red;
    console.log(
      `  ${chalk.bold('Score')} ${colored.bold(`${score}/100`)}  ${chalk.gray('· open:')} ${chalk.red(crit + ' crit')} ${chalk.yellow(warn + ' warn')} ${chalk.blue(info + ' info')}`,
    );
  }

  private hasFindings(): boolean {
    return this.ordered.length > 0;
  }

  private findingAt(arg?: string): Finding | null {
    const n = Number(arg);
    if (!arg || !Number.isInteger(n) || n < 1 || n > this.ordered.length) {
      logger.warn(`Give a finding number from the list (1–${this.ordered.length || 0}). Try "issues".`);
      return null;
    }
    return this.ordered[n - 1]!;
  }

  private parseSeverity(s?: string): Severity | null {
    if (s === 'critical' || s === 'crit') return 'critical';
    if (s === 'warning' || s === 'warn') return 'warning';
    if (s === 'info') return 'info';
    return null;
  }

  private statusMark(f: Finding): string {
    const st = this.checklist?.list().find((i) => i.finding.id === f.id)?.status ?? 'open';
    if (st === 'fixed') return chalk.green('✓');
    if (st === 'ignored') return chalk.gray('−');
    return chalk.red('✗');
  }

  private sevBadge(s: Severity): string {
    if (s === 'critical') return chalk.red.bold('CRIT');
    if (s === 'warning') return chalk.yellow.bold('WARN');
    return chalk.blue.bold('INFO');
  }

  private locText(f: Finding): string {
    const loc = f.endpoint ?? (f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '');
    return loc ? chalk.gray(`  — ${loc}`) : '';
  }

  private async confirm(message: string, def: boolean): Promise<boolean> {
    const ans = await this.ask(`${message} ${def ? '(Y/n)' : '(y/N)'} `);
    if (ans === null) return def;
    const a = ans.trim().toLowerCase();
    if (a === '') return def;
    return a === 'y' || a === 'yes';
  }

  private help(): void {
    const rows: [string, string][] = [
      ['scan', 'run the full pipeline (parse → live tests → optional AI)'],
      ['parse', 'static parse + vulnerability scan'],
      ['dynamic', 'live tests against your running localhost app'],
      ['ai', 'send the findings report to your AI model for deeper analysis'],
      ['issues [crit|warn|info]', 'list findings (optionally filter by severity)'],
      ['show <n>', 'full detail of finding n'],
      ['fix <n>', 'interactive fix: auto-fix, AI-proposed diff, or guidance'],
      ['done <n> / ignore <n>', 'mark finding fixed / ignored (score updates live)'],
      ['score / status', 'show the current score / session state'],
      ['deploy [aws|do]', 'print a deployment guide for the detected stack'],
      ['export', 'write enterpriseready-report.md'],
      ['config / clear / help', 'show config / clear screen / this help'],
      ['exit', 'leave the session'],
    ];
    console.log('\n' + chalk.bold('  Commands'));
    for (const [c, d] of rows) console.log(`  ${chalk.cyan(c.padEnd(24))} ${chalk.gray(d)}`);
    console.log('');
  }

  private banner(): void {
    console.log(chalk.bold('\n  EnterpriseReady ') + chalk.gray(`v${VERSION} — interactive session`));
    console.log(chalk.gray(`  target: ${this.state.target}`));
    console.log(chalk.gray('  Type ') + chalk.cyan('scan') + chalk.gray(' to begin, or ') + chalk.cyan('help') + chalk.gray(' for commands. ') + chalk.cyan('exit') + chalk.gray(' to quit.\n'));
  }
}

/**
 * Corpus benchmark runner: holdout vs development, never merged.
 *
 *   npx tsx benchmark/bench.ts --suite holdout [--tools deployready,semgrep,llm] [--run] [--semgrep-rules <clone>]
 *   npx tsx benchmark/bench.ts --suite dev     [--tools deployready] [--run]
 *
 * --suite holdout  benchmark/holdout/cases/* with labels from benchmark/holdout/labels.json (class-level ground truth).
 *                  NEVER USE FOR RULE TUNING. See benchmark/holdout/README.md.
 * --suite dev      the development corpus (benchmark/corpus/{static,vibe,idor,rls,firebase,...}/<case>/expect.json);
 *                  labels are DeployReady rule ids, so only the deployready tool is meaningful there.
 *
 * Without --run the saved raw outputs are re-scored (reproducible offline, mapping changes are cheap).
 * With --run each selected tool is executed once per case, in a fresh temp copy of the case, and the raw output
 * plus duration/peak-RSS metadata is saved under benchmark/results/<suite>/raw/<tool>/ (dev: OS temp dir).
 *
 * deployready : `node dist/index.js analyze --json --no-dynamic --no-ai --no-deps --offline <case>` (run `npm run build` first)
 * semgrep     : semgrep OSS, community rules clone (--semgrep-rules), `--metrics=off --no-git-ignore`
 * llm         : `claude -p --model haiku --tools "" --setting-sources ""`, same neutral prompt as compare.ts, one run per case
 *
 * Scoring unit = (case, file, issue class). TP: labelled issue has an alert of the same class in the same file.
 * FN: it has none (an inconclusive case counts all its labels as FN). FP: an alert of a mapped class on a negative case,
 * or one that matches an explicit present:false label (dev: or any rule not mentioned in a `strict` case).
 * TN: (negative case x taxonomy class) pairs and explicit present:false labels with no alert.
 * "extra" = mapped alert on a positive case matching no label (not penalised: labels are not exhaustive there).
 * "other" = alert outside the taxonomy (not penalised). Severity-weighted recall weights labels critical 4 / high 3 / medium 2 / low 1.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { CLASSES, DR_CLASS, LLM_RULES, SEMGREP_RULES, SEVERITY_WEIGHT } from './holdoutMapping';

type Suite = 'holdout' | 'dev';
type Tool = 'deployready' | 'semgrep' | 'llm';
const ALL_TOOLS: Tool[] = ['deployready', 'semgrep', 'llm'];

const ROOT = path.join(__dirname, '..');
const LLM_PROMPT = 'Review this project for security vulnerabilities. List each issue as JSON lines {file, line, issue}.';

interface Label { cls: string; file: string; present: boolean; severity?: string }
interface BCase { id: string; dir: string; negative: boolean; strict: boolean; labels: Label[] }
interface Alert { file: string; line?: number; cls: string; raw: string }
interface Meta { status: 'ok' | 'inconclusive'; note?: string; durationMs: number | null; peakKb: number | null; exit?: number | null }
interface Tally { tp: number; fp: number; fn: number; tn: number; extra: number; other: number }
const zero = (): Tally => ({ tp: 0, fp: 0, fn: 0, tn: 0, extra: 0, other: 0 });

// ---------- suites ----------

function walk(dir: string, rel = ''): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const r = path.join(rel, e.name);
    if (e.isDirectory()) out.push(...walk(dir, r));
    else out.push(r.split(path.sep).join('/'));
  }
  return out.sort();
}

function loadHoldout(): BCase[] {
  const base = path.join(__dirname, 'holdout');
  const labels = JSON.parse(fs.readFileSync(path.join(base, 'labels.json'), 'utf8')) as {
    cases: Record<string, { negative: boolean; labels: Array<{ class: string; file: string; present: boolean; severity?: string }> }>;
  };
  const dirs = fs.readdirSync(path.join(base, 'cases'), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
  for (const d of dirs) if (!labels.cases[d]) throw new Error(`holdout case ${d} has no entry in labels.json`);
  for (const id of Object.keys(labels.cases)) if (!dirs.includes(id)) throw new Error(`labels.json entry ${id} has no case directory`);
  return dirs.map((id) => {
    const l = labels.cases[id]!;
    return { id, dir: path.join(base, 'cases', id), negative: l.negative, strict: false, labels: l.labels.map((x) => ({ cls: x.class, file: x.file, present: x.present, severity: x.severity })) };
  });
}

function loadDev(): BCase[] {
  const corpus = path.join(__dirname, 'corpus');
  const out: BCase[] = [];
  for (const group of fs.readdirSync(corpus, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort()) {
    if (group === 'parser') continue; // route-guard parser matrix: scored by run.ts, not a finding benchmark
    for (const d of fs.readdirSync(path.join(corpus, group), { withFileTypes: true }).filter((x) => x.isDirectory()).map((x) => x.name).sort()) {
      const dir = path.join(corpus, group, d);
      const ef = path.join(dir, 'expect.json');
      if (!fs.existsSync(ef)) continue;
      const exp = JSON.parse(fs.readFileSync(ef, 'utf8')) as { strict?: boolean; expected?: Array<Record<string, any>> };
      if (!Array.isArray(exp.expected)) continue;
      const labels: Label[] = [];
      for (const e of exp.expected) {
        if (e.route) continue;
        if (e.unsupported) labels.push({ cls: `unsupported:${e.unsupported}`, file: e.file ?? '', present: true });
        else labels.push({ cls: e.rule, file: e.file ?? '', present: !!e.present, severity: e.severity });
      }
      out.push({ id: `${group}/${d}`, dir, negative: false, strict: !!exp.strict, labels });
    }
  }
  return out;
}

// ---------- running tools ----------

const WRAP = path.join(__dirname, 'tools', 'rss-wrap.py');

/** Run a command (stdio captured), measuring wall time and peak RSS of it and its descendants (python3 wrapper; Linux/macOS). */
function timed(cmd: string, args: string[], opts: { cwd: string; input?: string; timeout: number }): { stdout: string; stderr: string; status: number | null; durationMs: number; peakKb: number | null } {
  const rssFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bench-rss-')), 'rss');
  const t0 = Date.now();
  const r = spawnSync('python3', [WRAP, rssFile, cmd, ...args], { cwd: opts.cwd, input: opts.input, encoding: 'utf8', timeout: opts.timeout, maxBuffer: 1 << 28 });
  let peakKb: number | null = null;
  try { peakKb = parseInt(fs.readFileSync(rssFile, 'utf8').split(' ')[0] ?? '', 10) || null; } catch { /* wrapper unavailable */ }
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.error ? null : r.status, durationMs: Date.now() - t0, peakKb };
}

function copyCase(c: BCase): string {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `bench-${c.id.replace(/\//g, '_')}-`));
  const dst = path.join(tmp, 'project');
  fs.cpSync(c.dir, dst, { recursive: true });
  fs.rmSync(path.join(dst, 'expect.json'), { force: true }); // labels never reach a tool
  return dst;
}

function rawPath(rawDir: string, tool: Tool, id: string, ext: string): string {
  return path.join(rawDir, tool, `${id.replace(/\//g, '__')}.${ext}`);
}

function saveRaw(rawDir: string, tool: Tool, id: string, ext: string, body: string, meta: Meta): void {
  fs.mkdirSync(path.join(rawDir, tool), { recursive: true });
  fs.writeFileSync(rawPath(rawDir, tool, id, ext), body);
  fs.writeFileSync(rawPath(rawDir, tool, id, 'meta.json'), `${JSON.stringify(meta)}\n`);
}

function runTool(tool: Tool, c: BCase, rawDir: string, semgrepRules: string): void {
  const dst = copyCase(c);
  try {
    if (tool === 'deployready') {
      const r = timed('node', [path.join(ROOT, 'dist', 'index.js'), 'analyze', '--json', '--no-dynamic', '--no-ai', '--no-deps', '--offline', dst], { cwd: path.dirname(dst), timeout: 300000 });
      const ok = r.stdout.trim().startsWith('{');
      saveRaw(rawDir, tool, c.id, 'json', r.stdout, { status: ok ? 'ok' : 'inconclusive', note: ok ? undefined : `no JSON on stdout (exit ${r.status}): ${r.stderr.slice(0, 200)}`, durationMs: r.durationMs, peakKb: r.peakKb, exit: r.status });
    } else if (tool === 'semgrep') {
      const r = timed('semgrep', ['--metrics=off', '--disable-version-check', '--no-git-ignore', '--config', semgrepRules, '--json', '-q', '.'], { cwd: dst, timeout: 600000 });
      const ok = r.stdout.trim().startsWith('{');
      saveRaw(rawDir, tool, c.id, 'json', r.stdout, { status: ok ? 'ok' : 'inconclusive', note: ok ? undefined : `semgrep failed (exit ${r.status}): ${r.stderr.slice(0, 200)}`, durationMs: r.durationMs, peakKb: r.peakKb, exit: r.status });
    } else {
      const files = walk(dst);
      const body = `Project files: ${files.join(', ')}\n\n` + files.map((f) => `=== ${f} ===\n${fs.readFileSync(path.join(dst, f), 'utf8')}`).join('\n\n');
      const r = timed('claude', ['-p', '--model', 'haiku', '--tools', '', '--setting-sources', '', '--disable-slash-commands', LLM_PROMPT], { cwd: path.dirname(dst), input: body, timeout: 240000 });
      const ok = r.status === 0 && r.stdout.trim().length > 0;
      saveRaw(rawDir, tool, c.id, 'txt', ok ? r.stdout : `ERROR (exit ${r.status}): ${r.stderr}\n${r.stdout}`, { status: ok ? 'ok' : 'inconclusive', note: ok ? undefined : `claude failed (exit ${r.status})`, durationMs: r.durationMs, peakKb: r.peakKb, exit: r.status });
    }
  } finally {
    fs.rmSync(path.dirname(dst), { recursive: true, force: true });
  }
}

function prepareSemgrepRules(clone: string): string {
  const dst = fs.mkdtempSync(path.join(os.tmpdir(), 'semgrep-rules-'));
  const copy = (src: string, rel: string) => {
    for (const e of fs.readdirSync(src, { withFileTypes: true })) {
      const s = path.join(src, e.name);
      if (e.isDirectory()) copy(s, path.join(rel, e.name));
      else if (/\.ya?ml$/.test(e.name) && !/\.(test|fixed)\./.test(e.name)) {
        fs.mkdirSync(path.join(dst, rel), { recursive: true });
        fs.copyFileSync(s, path.join(dst, rel, e.name));
      }
    }
  };
  for (const d of ['javascript', 'typescript', 'python', 'generic']) copy(path.join(clone, d), d);
  return dst;
}

// ---------- reading raw outputs -> alerts ----------

function readMeta(rawDir: string, tool: Tool, id: string): Meta {
  try { return JSON.parse(fs.readFileSync(rawPath(rawDir, tool, id, 'meta.json'), 'utf8')) as Meta; } catch {
    return { status: 'inconclusive', note: 'no saved raw output (tool not run)', durationMs: null, peakKb: null };
  }
}

function alertsFor(tool: Tool, suite: Suite, c: BCase, rawDir: string): Alert[] {
  const norm = (f: string) => f.replace(/^\.\//, '');
  if (tool === 'deployready') {
    const j = JSON.parse(fs.readFileSync(rawPath(rawDir, tool, c.id, 'json'), 'utf8')) as { findings: Array<{ rule: string; file?: string; line?: number; note?: boolean; endpoint?: string }> };
    return j.findings.filter((f) => f.note !== true).map((f) => ({ file: norm(f.file ?? ''), line: f.line, cls: suite === 'dev' ? f.rule : (DR_CLASS[f.rule] ?? 'other'), raw: f.rule }));
  }
  if (tool === 'semgrep') {
    const j = JSON.parse(fs.readFileSync(rawPath(rawDir, tool, c.id, 'json'), 'utf8')) as { results: any[] };
    return j.results.map((r) => {
      const hay = `${r.check_id} ${r.extra?.message ?? ''} ${JSON.stringify(r.extra?.metadata?.cwe ?? '')}`;
      const hit = SEMGREP_RULES.find(([, re]) => re.test(hay));
      return { file: norm(String(r.path)), line: r.start?.line, cls: hit ? hit[0] : 'other', raw: String(r.check_id).split('.').slice(-1)[0] as string };
    });
  }
  const alerts: Alert[] = [];
  const files = walk(c.dir).filter((f) => f !== 'expect.json');
  for (const line of fs.readFileSync(rawPath(rawDir, tool, c.id, 'txt'), 'utf8').split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    let o: { file?: string; line?: number | string; issue?: string };
    try { o = JSON.parse(t.replace(/,$/, '')); } catch { continue; }
    const issue = String(o.issue ?? '');
    if (/^\W*(no issue|informational|not an issue|no vulnerabilit)/i.test(issue)) continue;
    const lf = norm(String(o.file ?? ''));
    const file = files.find((x) => x === lf) ?? files.find((x) => lf.endsWith(x) || x.endsWith(lf)) ?? lf;
    const ln = typeof o.line === 'number' ? o.line : parseInt(String(o.line), 10) || undefined;
    const classes = LLM_RULES.filter(([, re]) => re.test(issue)).map(([k]) => k);
    if (classes.length === 0) alerts.push({ file, line: ln, cls: 'other', raw: issue.slice(0, 80) });
    for (const k of classes) alerts.push({ file, line: ln, cls: k, raw: issue.slice(0, 80) });
  }
  return alerts;
}

// ---------- scoring ----------

interface CaseScore {
  id: string; negative: boolean; status: 'ok' | 'inconclusive'; note?: string; tally: Tally; durationMs: number | null; peakKb: number | null;
  alerts: number; missed: string[]; falsePositives: string[]; weightCaught: number; weightTotal: number;
}

const weight = (l: Label) => SEVERITY_WEIGHT[l.severity ?? 'high'] ?? 3;
const fileOk = (labelFile: string, alertFile: string) => labelFile === '' || alertFile === '' || labelFile === alertFile || alertFile.endsWith(`/${labelFile}`) || labelFile.endsWith(`/${alertFile}`);

function scoreCase(suite: Suite, c: BCase, meta: Meta, alerts: Alert[], byClass: Map<string, Tally>): CaseScore {
  const t = zero();
  const bump = (cls: string, k: keyof Tally, n = 1) => {
    const ct = byClass.get(cls) ?? zero(); ct[k] += n; byClass.set(cls, ct); t[k] += n;
  };
  const positives = c.labels.filter((l) => l.present);
  const res: CaseScore = { id: c.id, negative: c.negative, status: meta.status, note: meta.note, tally: t, durationMs: meta.durationMs, peakKb: meta.peakKb, alerts: alerts.length, missed: [], falsePositives: [], weightCaught: 0, weightTotal: positives.reduce((s, l) => s + weight(l), 0) };
  for (const l of positives) {
    if (meta.status === 'ok' && alerts.some((a) => a.cls === l.cls && fileOk(l.file, a.file))) { bump(l.cls, 'tp'); res.weightCaught += weight(l); }
    else { bump(l.cls, 'fn'); res.missed.push(`${l.cls} (${l.file || '*'})`); }
  }
  if (meta.status !== 'ok') return res; // inconclusive: labels count as FN, no TN credit, no alerts to judge
  const seen = new Set<string>();
  const fpClasses = new Set<string>();
  for (const a of alerts) {
    const key = `${a.file}|${a.cls}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (a.cls === 'other') { bump('other', 'other'); continue; }
    if (c.labels.some((l) => l.present && l.cls === a.cls && fileOk(l.file, a.file))) continue;
    const negHit = c.labels.some((l) => !l.present && l.cls === a.cls && fileOk(l.file, a.file));
    const strictHit = c.strict && !c.labels.some((l) => l.cls === a.cls);
    if (c.negative || negHit || strictHit) { bump(a.cls, 'fp'); fpClasses.add(a.cls); res.falsePositives.push(`${a.cls} ${a.file}${a.line ? `:${a.line}` : ''} [${a.raw}]`); }
    else bump(a.cls, 'extra');
  }
  for (const l of c.labels.filter((x) => !x.present)) if (!alerts.some((a) => a.cls === l.cls && fileOk(l.file, a.file))) bump(l.cls, 'tn');
  if (suite === 'holdout' && c.negative) for (const k of CLASSES) if (!fpClasses.has(k)) bump(k, 'tn');
  return res;
}

const ratio = (n: number, d: number): number | null => (d === 0 ? null : n / d);
const f2 = (v: number | null) => (v === null ? '-' : v.toFixed(2));

interface ToolResult {
  tool: Tool; suite: Suite; total: Tally; byClass: Record<string, Tally>; cases: CaseScore[]; positiveLabels: number; negativeCases: number;
  inconclusive: number; sevWeightedRecall: number | null; negativesClean: number;
  durationMs: { total: number; mean: number; max: number } | null; peakMb: { max: number; mean: number } | null;
}

function runScoring(tool: Tool, suite: Suite, cases: BCase[], rawDir: string): ToolResult {
  const byClass = new Map<string, Tally>();
  const scores: CaseScore[] = [];
  for (const c of cases) {
    const meta = readMeta(rawDir, tool, c.id);
    let alerts: Alert[] = [];
    if (meta.status === 'ok') {
      try { alerts = alertsFor(tool, suite, c, rawDir); } catch (e) { meta.status = 'inconclusive'; meta.note = `unparseable output: ${(e as Error).message}`; }
    }
    scores.push(scoreCase(suite, c, meta, alerts, byClass));
  }
  const total = zero();
  for (const s of scores) for (const k of Object.keys(total) as Array<keyof Tally>) total[k] += s.tally[k];
  const wt = scores.reduce((s, x) => s + x.weightTotal, 0);
  const wc = scores.reduce((s, x) => s + x.weightCaught, 0);
  const durs = scores.map((s) => s.durationMs).filter((x): x is number => x !== null);
  const mems = scores.map((s) => s.peakKb).filter((x): x is number => x !== null);
  const negs = scores.filter((s) => s.negative);
  return {
    tool, suite, total, byClass: Object.fromEntries(byClass), cases: scores,
    positiveLabels: total.tp + total.fn, negativeCases: negs.length,
    inconclusive: scores.filter((s) => s.status === 'inconclusive').length,
    sevWeightedRecall: ratio(wc, wt),
    negativesClean: negs.filter((s) => s.status === 'ok' && s.tally.fp === 0).length,
    durationMs: durs.length ? { total: durs.reduce((a, b) => a + b, 0), mean: durs.reduce((a, b) => a + b, 0) / durs.length, max: Math.max(...durs) } : null,
    peakMb: mems.length ? { max: Math.max(...mems) / 1024, mean: mems.reduce((a, b) => a + b, 0) / mems.length / 1024 } : null,
  };
}

// ---------- reporting ----------

const metrics = (t: Tally) => {
  const p = ratio(t.tp, t.tp + t.fp);
  const r = ratio(t.tp, t.tp + t.fn);
  const f1 = p !== null && r !== null && p + r > 0 ? (2 * p * r) / (p + r) : null;
  return { p, r, f1, pStrict: ratio(t.tp, t.tp + t.fp + t.extra) };
};

function render(suite: Suite, results: ToolResult[], cases: BCase[]): string {
  const L: string[] = [];
  const title = suite === 'holdout' ? 'HOLDOUT corpus (never used for tuning)' : 'DEVELOPMENT corpus (used while building rules; optimistic by construction)';
  const negNote = suite === 'holdout' ? `${cases.filter((c) => c.negative).length} negative cases` : `${cases.filter((c) => c.strict).length} strict cases (any unlisted rule is a FP) and explicit present:false labels`;
  L.push(`## ${title}`, '', `${cases.length} cases, ${results[0]?.positiveLabels ?? 0} positive labels, ${negNote}.`, '');
  L.push('| Tool | TP | FP | TN | FN | Precision | Recall | F1 | Sev-weighted recall | Precision incl. extras | Extra | Other | Inconclusive | Neg. cases clean | Scan time total / mean / max (s) | Peak RSS mean / max (MB) |');
  L.push('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|');
  for (const r of results) {
    const m = metrics(r.total);
    const d = r.durationMs; const mem = r.peakMb;
    L.push(`| ${r.tool} | ${r.total.tp} | ${r.total.fp} | ${r.total.tn} | ${r.total.fn} | ${f2(m.p)} | ${f2(m.r)} | ${f2(m.f1)} | ${f2(r.sevWeightedRecall)} | ${f2(m.pStrict)} | ${r.total.extra} | ${r.total.other} | ${r.inconclusive} | ${suite === 'holdout' ? `${r.negativesClean}/${r.negativeCases}` : '-'} | ${d ? `${(d.total / 1000).toFixed(1)} / ${(d.mean / 1000).toFixed(2)} / ${(d.max / 1000).toFixed(1)}` : '-'} | ${mem ? `${mem.mean.toFixed(0)} / ${mem.max.toFixed(0)}` : '-'} |`);
  }
  const classes = [...new Set(cases.flatMap((c) => c.labels.map((l) => l.cls)))].sort();
  L.push('', `### Per ${suite === 'holdout' ? 'class' : 'rule'} (TP/FP/FN; TN omitted)`, '', `| ${suite === 'holdout' ? 'Class' : 'Rule'} | Labels | ${results.map((r) => r.tool).join(' | ')} |`, `|---|---|${results.map(() => '---').join('|')}|`);
  for (const k of classes) {
    const cells = results.map((r) => { const t = r.byClass[k] ?? zero(); return `${t.tp}/${t.fp}/${t.fn}`; });
    const n = cases.reduce((s, c) => s + c.labels.filter((l) => l.cls === k && l.present).length, 0);
    L.push(`| ${k} | ${n} | ${cells.join(' | ')} |`);
  }
  for (const r of results) {
    L.push('', `### Per case: ${r.tool}`, '', '| Case | Kind | TP | FP | FN | Extra | Alerts | Status | Scan (s) | Peak RSS (MB) | Missed | False positives |', '|---|---|---|---|---|---|---|---|---|---|---|---|');
    for (const s of r.cases) {
      L.push(`| ${s.id} | ${s.negative ? 'neg' : 'pos'} | ${s.tally.tp} | ${s.tally.fp} | ${s.tally.fn} | ${s.tally.extra} | ${s.alerts} | ${s.status}${s.note ? ` (${s.note.replace(/\|/g, '/').slice(0, 60)})` : ''} | ${s.durationMs === null ? '-' : (s.durationMs / 1000).toFixed(2)} | ${s.peakKb === null ? '-' : (s.peakKb / 1024).toFixed(0)} | ${s.missed.join('; ') || '-'} | ${s.falsePositives.join('; ') || '-'} |`);
    }
  }
  return L.join('\n');
}

// ---------- main ----------

function main(): void {
  const arg = (n: string) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : undefined; };
  const suite = (arg('--suite') ?? 'holdout') as Suite;
  if (suite !== 'holdout' && suite !== 'dev') throw new Error('--suite must be holdout or dev');
  const tools = (arg('--tools') ?? (suite === 'holdout' ? ALL_TOOLS.join(',') : 'deployready')).split(',') as Tool[];
  for (const t of tools) if (!ALL_TOOLS.includes(t)) throw new Error(`unknown tool ${t}`);
  const cases = suite === 'holdout' ? loadHoldout() : loadDev();
  const resultsDir = path.join(__dirname, 'results', suite);
  const rawDir = suite === 'holdout' ? path.join(resultsDir, 'raw') : (arg('--raw-dir') ?? path.join(os.tmpdir(), 'deployready-dev-bench-raw'));
  const only = arg('--only');

  if (process.argv.includes('--run')) {
    if (tools.includes('deployready') && !fs.existsSync(path.join(ROOT, 'dist', 'index.js'))) throw new Error('dist/index.js missing: run `npm run build` first');
    const clone = arg('--semgrep-rules');
    if (tools.includes('semgrep') && !clone) throw new Error('--semgrep-rules <clone of semgrep/semgrep-rules> is required with --run and the semgrep tool');
    const rules = tools.includes('semgrep') ? prepareSemgrepRules(clone!) : '';
    for (const tool of tools) {
      for (const c of cases) {
        if (only && !c.id.includes(only)) continue;
        process.stderr.write(`[${tool}] ${c.id}\n`);
        runTool(tool, c, rawDir, rules);
      }
    }
  }

  const results = tools.map((t) => runScoring(t, suite, cases, rawDir));
  const md = render(suite, results, cases);
  fs.mkdirSync(resultsDir, { recursive: true });
  fs.writeFileSync(path.join(resultsDir, 'summary.md'), `${md}\n`);
  fs.writeFileSync(path.join(resultsDir, 'results.json'), `${JSON.stringify(results, null, 1)}\n`);
  console.log(md);
}

main();

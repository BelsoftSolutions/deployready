/**
 * Three-way comparison on corpus/vibe: DeployReady vs Semgrep OSS vs a plain LLM review.
 *
 *   npx tsx benchmark/compare.ts [--semgrep-rules <dir>] [--llm] [--llm-model haiku] [--out benchmark/compare/results.json]
 *
 *   --semgrep-rules <dir>  a clone of github.com/semgrep/semgrep-rules. The javascript, typescript, python and
 *                          generic dirs are copied (rule yamls only, no *.test.* / *.fixed.*) into a temp dir and
 *                          semgrep is run once over corpus/vibe. Raw output -> compare/raw/semgrep.json.
 *                          Without the flag, the saved raw/semgrep.json is re-scored.
 *   --llm                  (re)run `claude -p` once per case. Without the flag, saved raw/llm/<case>.txt is re-scored.
 *
 * Scoring unit = (case, file, issue class). See CLASS maps below: every mapping is explicit.
 * Labels come from each case's expect.json. Line numbers are recorded but not required (labels are file-level).
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';

const VIBE = path.join(__dirname, 'corpus', 'vibe');
const RAW = path.join(__dirname, 'compare', 'raw');
const PROMPT = 'Review this project for security vulnerabilities. List each issue as JSON lines {file, line, issue}.';

export type IssueClass =
  | 'sqli' | 'missing-auth' | 'idor' | 'hardcoded-secret' | 'cors' | 'tls' | 'debug'
  | 'rls-missing' | 'rls-permissive' | 'service-role-exposed' | 'client-secret' | 'env-committed';

/** DeployReady rule id -> class. Unlisted rules are "other" (never matches a label; counted as an alert). */
const DR_CLASS: Record<string, IssueClass> = {
  'sql-injection': 'sqli', 'py-sql-fstring': 'sqli',
  'missing-auth-route': 'missing-auth',
  'idor-missing-ownership-check': 'idor',
  'jwt-hardcoded-secret': 'hardcoded-secret', 'flask-hardcoded-secret-key': 'hardcoded-secret', 'possible-hardcoded-secret': 'hardcoded-secret',
  'cors-wildcard': 'cors',
  'tls-verification-disabled': 'tls', 'py-requests-noverify': 'tls',
  'py-flask-debug': 'debug',
  'rls-not-enabled': 'rls-missing', 'rls-permissive-policy': 'rls-permissive',
  'supabase-service-role': 'service-role-exposed', 'next-public-secret': 'client-secret',
  'env-not-ignored': 'env-committed',
};

/** Ordered keyword rules over (check_id + message + CWE tags) for Semgrep. First match wins; CWE ids listed explicitly. */
const SEMGREP_RULES: Array<[IssueClass, RegExp]> = [
  ['sqli', /\bcwe-89\b|sql-?injection|tainted-sql|sqlalchemy-execute-raw|formatted-sql|sql-string|raw-query/i],
  ['hardcoded-secret', /\bcwe-798\b|\bcwe-321\b|hardcoded-(jwt|secret|token|password)|jwt-.*(hardcode|secret)|secret-key|detected-.*(key|token|secret)|generic\.secrets|hardcoded/i],
  ['cors', /\bcwe-942\b|cors|access-control-allow-origin/i],
  ['tls', /\bcwe-295\b|\bcwe-599\b|verify-?false|disabled-cert|reject-?unauthorized|certificate-validation|ssl-verify|requests-.*verify/i],
  ['debug', /\bcwe-489\b|\bcwe-215\b|debug-enabled|flask.*debug|app-run-debug/i],
  ['idor', /\bcwe-639\b|\bidor\b|insecure-direct-object|missing-ownership/i],
  ['missing-auth', /\bcwe-306\b|\bcwe-862\b|\bcwe-285\b|missing-auth|unauthenticated|no-auth/i],
  ['service-role-exposed', /service[-_]?role/i],
];

/** Keyword rules over the free-text `issue` of an LLM JSON line. A line may map to several classes. */
const LLM_RULES: Array<[IssueClass, RegExp]> = [
  ['sqli', /sql.?inject|string concat.*(sql|quer)|(sql|quer).*(concatenat|interpolat|f-string)|raw sql/i],
  ['missing-auth', /(no|missing|lack|without|absent)[^.]{0,40}(authentication|authorization|access control)|unauthenticated|unprotected (route|endpoint)|not (protected|authenticated)/i],
  ['idor', /\bidor\b|insecure direct object|(no|missing|without|lack)[^.]{0,40}(ownership|owner check)|any (authenticated )?user can (read|view|access|modify|update|delete)[^.]{0,40}(other|any|another)|authorization.*(other users|ownership)|broken object/i],
  ['hardcoded-secret', /hard-?coded[^.]{0,40}(secret|key|jwt|token|password|credential)|(secret|key|jwt|token|password)[^.]{0,30}hard-?coded|secret[^.]{0,20}(in source|in code|literal)/i],
  ['cors', /\bcors\b|access-control-allow-origin|cross-origin resource/i],
  ['tls', /(certificate|cert|tls|ssl)[^.]{0,40}(verification|validation)[^.]{0,30}(disabled|off|bypass|skipped)|(disabled|disables|bypass|skip)[^.]{0,30}(certificate|cert|tls|ssl)|verify\s*=\s*false|rejectunauthorized\s*:?\s*false|reject_unauthorized/i],
  ['debug', /debug[^.]{0,30}(mode|true|enabled|on)|(werkzeug|flask) debug|debug=true/i],
  ['rls-permissive', /using\s*\(\s*true\s*\)|with check\s*\(\s*true\s*\)|permissive (rls )?polic|policy[^.]{0,40}(true|allow(s)? (all|any|everyone))|(always|unconditionally) true/i],
  ['rls-missing', /(rls|row[- ]level security)[^.]{0,40}(not (been )?enabled|is disabled|never enabled|missing)|(no|without|missing|never|lack of)\s+['"`]?(rls|row[- ]level security|enable row level)|(did not|does not|doesn't|never|not) enable[^.]{0,20}(rls|row[- ]level)/i],
  ['service-role-exposed', /service[-_ ]?role[^.]{0,80}(next_public|public|browser|client|frontend|bundle|exposed)|(next_public|browser|client|frontend|exposed)[^.]{0,80}service[-_ ]?role/i],
  ['client-secret', /next_public[^.]{0,60}(openai|api|secret)|(openai|api)[^.]{0,30}key[^.]{0,60}(browser|client|frontend|bundle|public)|dangerouslyallowbrowser|exposed (to|in) (the )?(browser|client)/i],
  ['env-committed', /\.env[^.]{0,60}(committed|checked in|in version control|is tracked|not (git)?ignored)|(no|missing|without|absent)[^.]{0,20}\.git.gnore/i],
];

interface Alert { file: string; line?: number; cls: IssueClass | 'other'; raw: string }
interface Label { file: string; cls: IssueClass; present: boolean }
interface CaseSpec { id: string; tn: boolean; labels: Label[]; files: string[] }

function walk(dir: string, rel = ''): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const r = path.join(rel, e.name);
    if (e.isDirectory()) out.push(...walk(dir, r));
    else out.push(r.split(path.sep).join('/'));
  }
  return out.sort();
}

function loadCases(): CaseSpec[] {
  return fs.readdirSync(VIBE, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort().map((id) => {
    const dir = path.join(VIBE, id);
    const exp = JSON.parse(fs.readFileSync(path.join(dir, 'expect.json'), 'utf8')) as { expected: Array<Record<string, any>> };
    const files = walk(dir).filter((f) => f !== 'expect.json');
    const labels: Label[] = [];
    for (const e of exp.expected) {
      if (e.route) continue; // route-guard checks are DeployReady-internal; the matching missing-auth-route finding is the label
      if (e.unsupported) {
        labels.push({ file: e.file ?? '', cls: e.unsupported as IssueClass, present: true });
      } else {
        const cls = DR_CLASS[e.rule];
        if (!cls) throw new Error(`no class for rule ${e.rule}`);
        labels.push({ file: e.file ?? '', cls, present: !!e.present });
      }
    }
    // missing-auth-route labels without a file come only from route checks; derive from guarded:false routes
    if (exp.expected.some((e) => e.route && e.guarded === false) && !labels.some((l) => l.cls === 'missing-auth' && l.present)) {
      throw new Error(`${id}: unguarded route without missing-auth-route label`);
    }
    return { id, tn: id.endsWith('-tn'), labels, files };
  });
}

// ---------- tool runners ----------

async function runDeployReady(c: CaseSpec): Promise<Alert[]> {
  const findings = await VulnerabilityDetector.scan(path.join(VIBE, c.id));
  return findings.map((f) => ({ file: f.file ?? '', line: f.line, cls: DR_CLASS[f.rule] ?? 'other', raw: f.rule }));
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

function runSemgrep(clone: string): void {
  const rules = prepareSemgrepRules(clone);
  const r = spawnSync('semgrep', ['--metrics=off', '--disable-version-check', '--config', rules, '--json', '-q', 'vibe'], {
    cwd: path.join(__dirname, 'corpus'), encoding: 'utf8', maxBuffer: 1 << 28,
  });
  if (!r.stdout) throw new Error(`semgrep failed: ${r.stderr}`);
  fs.mkdirSync(RAW, { recursive: true });
  fs.writeFileSync(path.join(RAW, 'semgrep.json'), r.stdout);
}

function semgrepAlerts(c: CaseSpec): Alert[] {
  const data = JSON.parse(fs.readFileSync(path.join(RAW, 'semgrep.json'), 'utf8')) as { results: any[] };
  const prefix = `vibe/${c.id}/`;
  return data.results.filter((r) => r.path.startsWith(prefix)).map((r) => {
    const cwe = JSON.stringify(r.extra?.metadata?.cwe ?? '');
    const hay = `${r.check_id} ${r.extra?.message ?? ''} ${cwe}`;
    const hit = SEMGREP_RULES.find(([, re]) => re.test(hay));
    return { file: r.path.slice(prefix.length), line: r.start?.line, cls: hit ? hit[0] : 'other', raw: String(r.check_id).split('.').slice(-1)[0] as string };
  });
}

function runLlm(c: CaseSpec, model: string): void {
  const dir = path.join(VIBE, c.id);
  const body = `Project files: ${c.files.join(', ')}\n\n` + c.files.map((f) => `=== ${f} ===\n${fs.readFileSync(path.join(dir, f), 'utf8')}`).join('\n\n');
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-cwd-'));
  const r = spawnSync('claude', ['-p', '--model', model, '--tools', '', '--setting-sources', '', '--disable-slash-commands', PROMPT], {
    cwd, input: body, encoding: 'utf8', timeout: 180000, maxBuffer: 1 << 24,
  });
  fs.mkdirSync(path.join(RAW, 'llm'), { recursive: true });
  fs.writeFileSync(path.join(RAW, 'llm', `${c.id}.txt`), r.stdout || `ERROR: ${r.stderr}`);
}

function llmAlerts(c: CaseSpec): Alert[] {
  const f = path.join(RAW, 'llm', `${c.id}.txt`);
  if (!fs.existsSync(f)) return [];
  const alerts: Alert[] = [];
  for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    let o: { file?: string; line?: number | string; issue?: string };
    try { o = JSON.parse(t); } catch { continue; }
    const issue = String(o.issue ?? '');
    if (/^\W*(no issue|informational|not an issue|no vulnerabilit)/i.test(issue)) continue; // negated / informational lines are not alerts
    const lf = String(o.file ?? '').replace(/^\.?\//, '');
    const file = c.files.find((x) => x === lf) ?? c.files.find((x) => lf.endsWith(x) || x.endsWith(lf)) ?? lf;
    const classes = LLM_RULES.filter(([, re]) => re.test(issue)).map(([k]) => k);
    const ln = typeof o.line === 'number' ? o.line : parseInt(String(o.line), 10) || undefined;
    if (classes.length === 0) alerts.push({ file, line: ln, cls: 'other', raw: issue.slice(0, 80) });
    for (const k of classes) alerts.push({ file, line: ln, cls: k, raw: issue.slice(0, 80) });
  }
  return alerts;
}

// ---------- scoring ----------

interface Tally { tp: number; fp: number; fn: number; tnAlerts: number; other: number; extra: number }
const zero = (): Tally => ({ tp: 0, fp: 0, fn: 0, tnAlerts: 0, other: 0, extra: 0 });

/**
 * Label match: same class and same file (a label with no file matches any file in the case).
 * TP: positive label has a matching alert. FN: it has none.
 * FP: (tn case, mapped class, any file) or (alert matches an explicit present:false label); one per (case,file,class).
 * extra: mapped alert in a tp case that matches no label (not penalised: labels are not exhaustive, same as run.ts non-strict).
 * other: alert whose class is outside the 12-class taxonomy (not penalised).
 * tnAlerts: every alert on a tn case incl. "other" (strict view).
 */
function score(c: CaseSpec, alerts: Alert[], byClass: Map<string, Tally>, total: Tally): void {
  const bump = (cls: string, k: keyof Tally, n = 1) => {
    const t = byClass.get(cls) ?? zero(); t[k] += n; byClass.set(cls, t); total[k] += n;
  };
  const fileOk = (l: Label, a: Alert) => l.file === '' || l.file === a.file;
  for (const l of c.labels.filter((x) => x.present)) {
    if (alerts.some((a) => a.cls === l.cls && fileOk(l, a))) bump(l.cls, 'tp'); else bump(l.cls, 'fn');
  }
  const seen = new Set<string>();
  for (const a of alerts) {
    if (c.tn) bump(a.cls === 'other' ? 'other' : a.cls, 'tnAlerts');
    if (a.cls === 'other') { if (!c.tn) bump('other', 'other'); continue; }
    const key = `${a.file}|${a.cls}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const negHit = c.labels.some((l) => !l.present && l.cls === a.cls && fileOk(l, a));
    const posHit = c.labels.some((l) => l.present && l.cls === a.cls && fileOk(l, a));
    if (posHit) continue;
    if (c.tn || negHit) bump(a.cls, 'fp'); else bump(a.cls, 'extra');
  }
}

const pct = (n: number, d: number) => (d === 0 ? '-' : (n / d).toFixed(2));

async function main() {
  const arg = (n: string) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : undefined; };
  const cases = loadCases();
  const semgrepClone = arg('--semgrep-rules');
  if (semgrepClone) runSemgrep(semgrepClone);
  if (process.argv.includes('--llm')) for (const c of cases) runLlm(c, arg('--llm-model') ?? 'haiku');

  const tools: Record<string, (c: CaseSpec) => Promise<Alert[]> | Alert[]> = {
    DeployReady: runDeployReady,
    Semgrep: semgrepAlerts,
    'LLM (haiku)': llmAlerts,
  };
  const result: Record<string, { total: Tally; byClass: Record<string, Tally>; perCase: Record<string, Alert[]> }> = {};
  for (const [name, fn] of Object.entries(tools)) {
    const byClass = new Map<string, Tally>();
    const total = zero();
    const perCase: Record<string, Alert[]> = {};
    for (const c of cases) {
      const alerts = await fn(c);
      perCase[c.id] = alerts;
      score(c, alerts, byClass, total);
    }
    result[name] = { total, byClass: Object.fromEntries(byClass), perCase };
  }

  const classes = [...new Set(cases.flatMap((c) => c.labels.map((l) => l.cls)))].sort();
  console.log('| Tool | TP | FP | FN | Precision | Recall | Extra mapped | Other alerts | Alerts on -tn cases |\n|---|---|---|---|---|---|---|---|---|');
  for (const [n, r] of Object.entries(result)) {
    const t = r.total;
    console.log(`| ${n} | ${t.tp} | ${t.fp} | ${t.fn} | ${pct(t.tp, t.tp + t.fp)} | ${pct(t.tp, t.tp + t.fn)} | ${t.extra} | ${t.other} | ${t.tnAlerts} |`);
  }
  console.log('\n| Class | Labels | ' + Object.keys(result).map((n) => `${n} TP/FP/FN`).join(' | ') + ' |\n|---|---|' + Object.keys(result).map(() => '---').join('|') + '|');
  for (const k of classes) {
    const cells = Object.values(result).map((r) => { const t = r.byClass[k] ?? zero(); return `${t.tp}/${t.fp}/${t.fn}`; });
    const labels = Object.values(result)[0]!.byClass[k];
    console.log(`| ${k} | ${(labels?.tp ?? 0) + (labels?.fn ?? 0)} | ${cells.join(' | ')} |`);
  }
  const out = arg('--out');
  if (out) fs.writeFileSync(out, JSON.stringify(result, null, 1));
}

main().catch((e) => { console.error(e); process.exit(1); });

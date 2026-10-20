/**
 * Parser coverage matrix: runs CodeParser.analyze on tiny per-stack fixtures
 * (benchmark/parser-matrix/<stack>) and on single-style probes
 * (benchmark/parser-matrix/_styles/<id>), compares the discovered routes with
 * the ground truth in parser-matrix/truth.json and prints markdown tables.
 * Evidence only: it never fails and changes nothing.
 *
 *   npx tsx benchmark/parserMatrix.ts
 */
import * as fs from 'fs';
import * as path from 'path';
import { CodeParser } from '../src/parser/CodeParser';
import type { Route } from '../src/types';

const ROOT = path.join(__dirname, 'parser-matrix');
const STACK_ORDER = ['nextjs', 'express', 'fastify', 'nestjs', 'koa', 'fastapi', 'flask', 'django', 'laravel', 'unknown'];

interface TruthRoute {
  method: string;
  path: string;
  guarded: boolean;
}

interface TruthFile {
  stacks: Record<string, string[]>;
  styles: Record<string, { stack: string; style: string; routes: string[] }>;
}

interface Comparison {
  detectedStack: string;
  truth: TruthRoute[];
  matched: { truth: TruthRoute; found: Route }[];
  missed: TruthRoute[];
  extra: Route[];
  wrongGuard: { truth: TruthRoute; found: Route }[];
  methodImprecise: number;
}

function parseTruth(spec: string): TruthRoute {
  const [method, p, flag] = spec.split(' ');
  if (!method || !p) throw new Error(`bad truth entry: ${spec}`);
  return { method: method.toUpperCase(), path: p, guarded: flag === 'guarded' };
}

function normPath(p: string): string {
  const collapsed = p.replace(/\/{2,}/g, '/');
  return collapsed.length > 1 ? collapsed.replace(/\/$/, '') : collapsed;
}

function methodFits(truthMethod: string, foundMethod: string): boolean {
  return truthMethod === 'ANY' || foundMethod === 'ALL' || truthMethod === foundMethod;
}

async function compare(dir: string, truthSpecs: string[]): Promise<Comparison> {
  const graph = await CodeParser.analyze(dir);
  const truth = truthSpecs.map(parseTruth);
  const free = [...graph.routes];
  const matched: Comparison['matched'] = [];
  const missed: TruthRoute[] = [];

  for (const t of truth) {
    const samePath = (r: Route) => normPath(r.path) === normPath(t.path) && methodFits(t.method, r.method);
    const exact = free.findIndex((r) => samePath(r) && r.method === t.method);
    const idx = exact >= 0 ? exact : free.findIndex(samePath);
    if (idx < 0) {
      missed.push(t);
      continue;
    }
    matched.push({ truth: t, found: free.splice(idx, 1)[0]! });
  }

  return {
    detectedStack: graph.stack.stack,
    truth,
    matched,
    missed,
    extra: free,
    wrongGuard: matched.filter((m) => m.truth.guarded !== m.found.guarded),
    methodImprecise: matched.filter((m) => m.found.method === 'ALL' && m.truth.method !== 'ALL' && m.truth.method !== 'ANY').length,
  };
}

const code = (s: string) => `\`${s}\``;
const routeText = (r: TruthRoute) => `${r.method} ${r.path}`;
const foundText = (r: Route) => `${r.method} ${r.path} (${r.file})`;
const list = (items: string[]) => (items.length ? items.map(code).join('<br>') : '-');

async function main(): Promise<void> {
  const truth = JSON.parse(fs.readFileSync(path.join(ROOT, 'truth.json'), 'utf8')) as TruthFile;

  console.log('## Per-stack route discovery');
  console.log('');
  console.log(
    '| Stack | Detected as | Real routes | Discovered (matched) | Missed routes | Wrongly guarded flags | Discovered but not real |',
  );
  console.log('|---|---|---|---|---|---|---|');
  let real = 0;
  let found = 0;
  let wrong = 0;
  let imprecise = 0;
  for (const stack of STACK_ORDER) {
    const specs = truth.stacks[stack];
    if (!specs) throw new Error(`no truth for stack ${stack}`);
    const c = await compare(path.join(ROOT, stack), specs);
    real += c.truth.length;
    found += c.matched.length;
    wrong += c.wrongGuard.length;
    imprecise += c.methodImprecise;
    const wrongText = c.wrongGuard.map(
      (w) => `${routeText(w.truth)}: parser ${w.found.guarded ? 'guarded' : 'open'}, real ${w.truth.guarded ? 'guarded' : 'open'}`,
    );
    console.log(
      `| ${stack} | ${c.detectedStack} | ${c.truth.length} | ${c.matched.length} | ${list(c.missed.map(routeText))} | ${wrongText.length ? `${wrongText.length}: ${list(wrongText)}` : '0'} | ${list(c.extra.map(foundText))} |`,
    );
  }
  console.log('');
  console.log(
    `Total: ${real} real routes, ${found} discovered (${((found / real) * 100).toFixed(0)}%), ${real - found} missed, ${wrong} wrongly guarded flags on discovered routes, ${imprecise} discovered with method ALL where the real route is one method.`,
  );

  console.log('');
  console.log('## Route-definition styles');
  console.log('');
  console.log('Control rows (control:) show the parser handles the plain form of that framework. Every other row is one style probed in isolation.');
  console.log('');
  console.log('| Style probe | Stack | Style | Real | Discovered | Result | Missed | Wrong guard | Discovered but not real |');
  console.log('|---|---|---|---|---|---|---|---|---|');
  for (const [id, def] of Object.entries(truth.styles)) {
    const c = await compare(path.join(ROOT, '_styles', id), def.routes);
    const result =
      c.missed.length === 0 && c.wrongGuard.length === 0 && c.extra.length === 0
        ? c.methodImprecise > 0
          ? 'found, method ALL'
          : 'FOUND'
        : c.matched.length === 0
          ? 'MISSED'
          : 'PARTIAL';
    const wrongText = c.wrongGuard.map((w) => `${routeText(w.truth)}: parser ${w.found.guarded ? 'guarded' : 'open'}`);
    console.log(
      `| ${id} | ${def.stack} | ${def.style} | ${c.truth.length} | ${c.matched.length} | ${result} | ${list(c.missed.map(routeText))} | ${list(wrongText)} | ${list(c.extra.map(foundText))} |`,
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

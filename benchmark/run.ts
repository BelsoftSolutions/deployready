/**
 * Labelled false-positive / false-negative benchmark. Runs the real scanners
 * against a fixed corpus whose expectations are ground truth (what a CORRECT
 * tool reports), prints per-case results and per-rule TP/FP/FN/TN, and exits 1
 * if a case without a `knownGap` fails or a `knownGap` case unexpectedly passes.
 *
 *   npx tsx benchmark/run.ts [--json [file]]
 *
 * Bare `--json` prints the full result as JSON on stdout. `--json <file>` keeps the
 * normal text output and also writes `[{ id, kind, outcome, knownGap? }]` to <file>.
 */
import * as fs from 'fs';
import type { BenchCase, Check } from './core';
import { corpusCases } from './corpusCases';
import { dynamicCases } from './dynamicCases';
import { activeCases } from './activeCases';

type Status = 'pass' | 'fail' | 'known-gap' | 'fixed' | 'error';

interface CaseResult {
  id: string;
  kind: string;
  status: Status;
  knownGap?: string;
  mismatches: string[];
}

interface Tally {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
}

const KIND_ORDER = ['static', 'parser', 'dynamic', 'active'];

async function runCase(c: BenchCase, tallies: Map<string, Tally>): Promise<CaseResult> {
  let checks: Check[];
  try {
    checks = await c.evaluate();
  } catch (err) {
    return { id: c.id, kind: c.kind, status: 'error', knownGap: c.knownGap, mismatches: [`error: ${(err as Error).message}`] };
  }

  for (const k of checks) {
    const t = tallies.get(k.rule) ?? { tp: 0, fp: 0, fn: 0, tn: 0 };
    if (k.expected && k.actual) t.tp++;
    else if (!k.expected && k.actual) t.fp++;
    else if (k.expected && !k.actual) t.fn++;
    else t.tn++;
    tallies.set(k.rule, t);
  }

  const mismatches = checks
    .filter((k) => k.expected !== k.actual)
    .map((k) => `${k.expected ? 'MISSED' : 'UNEXPECTED'}: ${k.label} -> ${k.detail}`);
  const ok = mismatches.length === 0;
  const status: Status = ok ? (c.knownGap ? 'fixed' : 'pass') : c.knownGap ? 'known-gap' : 'fail';
  return { id: c.id, kind: c.kind, status, knownGap: c.knownGap, mismatches };
}

function ratio(num: number, den: number): number | null {
  return den === 0 ? null : num / den;
}

function fmt(v: number | null): string {
  return v === null ? '-' : v.toFixed(2);
}

function summarize(t: Tally) {
  return { ...t, precision: ratio(t.tp, t.tp + t.fp), recall: ratio(t.tp, t.tp + t.fn) };
}

const STATUS_LABEL: Record<Status, string> = {
  pass: 'PASS',
  fail: 'FAIL',
  'known-gap': 'GAP',
  fixed: 'FIXED',
  error: 'ERROR',
};

async function main(): Promise<number> {
  const jsonIdx = process.argv.indexOf('--json');
  const jsonArg = jsonIdx >= 0 ? process.argv[jsonIdx + 1] : undefined;
  const jsonFile = jsonArg !== undefined && !jsonArg.startsWith('--') ? jsonArg : undefined;
  const json = jsonIdx >= 0 && jsonFile === undefined;
  const cases = [...corpusCases(), ...dynamicCases(), ...activeCases()];
  const ids = new Set<string>();
  for (const c of cases) {
    if (ids.has(c.id)) throw new Error(`duplicate case id: ${c.id}`);
    ids.add(c.id);
  }
  cases.sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const tallies = new Map<string, Tally>();
  const results: CaseResult[] = [];
  for (const c of cases) results.push(await runCase(c, tallies));

  const rules = [...tallies.keys()].sort();
  const total: Tally = { tp: 0, fp: 0, fn: 0, tn: 0 };
  for (const t of tallies.values()) {
    total.tp += t.tp;
    total.fp += t.fp;
    total.fn += t.fn;
    total.tn += t.tn;
  }
  const count = (s: Status) => results.filter((r) => r.status === s).length;
  const failed = count('fail') + count('error') + count('fixed');

  if (jsonFile !== undefined) {
    const dump = results.map((r) => ({
      id: r.id,
      kind: r.kind,
      outcome: STATUS_LABEL[r.status],
      ...(r.knownGap ? { knownGap: r.knownGap } : {}),
    }));
    fs.writeFileSync(jsonFile, `${JSON.stringify(dump, null, 2)}\n`);
  }

  if (json) {
    const out = {
      cases: results,
      rules: Object.fromEntries(rules.map((r) => [r, summarize(tallies.get(r)!)])),
      total: summarize(total),
      counts: {
        cases: results.length,
        pass: count('pass'),
        fail: count('fail'),
        error: count('error'),
        knownGap: count('known-gap'),
        fixed: count('fixed'),
      },
    };
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    return failed > 0 ? 1 : 0;
  }

  const idWidth = Math.max(...results.map((r) => r.id.length));
  console.log('DeployReady benchmark');
  console.log('');
  for (const r of results) {
    const gap = r.knownGap ? `  [${r.knownGap}]` : '';
    console.log(`${STATUS_LABEL[r.status].padEnd(5)} ${r.kind.padEnd(7)} ${r.id.padEnd(idWidth)}${gap}`.trimEnd());
    if (r.status !== 'pass') for (const m of r.mismatches) console.log(`        ${m}`);
    if (r.status === 'fixed') console.log('        FIXED - remove knownGap');
  }

  console.log('');
  const w = Math.max(4, ...rules.map((r) => r.length));
  const header = `${'Rule'.padEnd(w)}  ${'TP'.padStart(3)} ${'FP'.padStart(3)} ${'FN'.padStart(3)} ${'TN'.padStart(3)}  Precision  Recall`;
  console.log(header);
  console.log('-'.repeat(header.length));
  const row = (name: string, t: Tally) => {
    const s = summarize(t);
    return `${name.padEnd(w)}  ${String(t.tp).padStart(3)} ${String(t.fp).padStart(3)} ${String(t.fn).padStart(3)} ${String(t.tn).padStart(3)}  ${fmt(s.precision).padStart(9)}  ${fmt(s.recall).padStart(6)}`;
  };
  for (const r of rules) console.log(row(r, tallies.get(r)!));
  console.log('-'.repeat(header.length));
  console.log(row('TOTAL', total));

  console.log('');
  console.log(
    `Cases: ${results.length}  pass: ${count('pass')}  fail: ${count('fail')}  error: ${count('error')}  known gap: ${count('known-gap')}  fixed (remove knownGap): ${count('fixed')}`,
  );
  console.log(
    failed === 0
      ? 'RESULT: OK'
      : count('fail') + count('error') > 0
        ? 'RESULT: FAIL (regression in a case without knownGap)'
        : 'RESULT: FAIL (knownGap case now passes: remove its knownGap)',
  );
  return failed > 0 ? 1 : 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error(err);
    process.exitCode = 1;
  },
);

/**
 * CI guard: the holdout corpus exists to measure rules that were NOT tuned against it, so nothing under src/
 * may reference it. Fails (exit 1) if any file under src/ mentions "holdout", the holdout directory, or a holdout case id.
 *
 *   npx tsx benchmark/checkHoldoutIsolation.ts
 */
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.join(__dirname, '..');
const caseIds = fs.readdirSync(path.join(__dirname, 'holdout', 'cases'), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
const needles: RegExp[] = [/holdout/i, ...caseIds.map((id) => new RegExp(id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))];

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

const hits: string[] = [];
for (const f of walk(path.join(ROOT, 'src'))) {
  const lines = fs.readFileSync(f, 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (needles.some((n) => n.test(line))) hits.push(`${path.relative(ROOT, f).split(path.sep).join('/')}:${i + 1}: ${line.trim().slice(0, 120)}`);
  });
}
if (hits.length > 0) {
  console.error('holdout isolation violated: files under src/ must not reference the holdout corpus:');
  for (const h of hits) console.error(`  ${h}`);
  process.exit(1);
}
console.log(`holdout isolation OK (${caseIds.length} case ids + "holdout" not referenced anywhere under src/)`);

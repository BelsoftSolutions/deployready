import * as fs from 'fs';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { scanFirebaseStatic } from '../src/firebase';
import { checkFindings, type BenchCase, type Check, type FindingExpectation } from './core';

const ROOT = path.join(__dirname, 'corpus', 'firebase');

interface ExpectFile {
  description: string;
  knownGap?: string;
  /** Any finding whose rule is not mentioned in `expected` counts as a false positive. */
  strict?: boolean;
  expected: FindingExpectation[];
}

/** Firebase security-rules cases: Firebase scanner + the general static detector, on one project. */
export function firebaseCases(): BenchCase[] {
  if (!fs.existsSync(ROOT)) return [];
  return fs
    .readdirSync(ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort()
    .map((id) => {
      const dir = path.join(ROOT, id);
      const spec = JSON.parse(fs.readFileSync(path.join(dir, 'expect.json'), 'utf8')) as ExpectFile;
      return {
        id: `firebase/${id}`,
        kind: 'static' as const,
        description: spec.description,
        knownGap: spec.knownGap,
        async evaluate(): Promise<Check[]> {
          const findings = [...(await scanFirebaseStatic(dir)).findings, ...(await VulnerabilityDetector.scan(dir))];
          const checks = checkFindings(findings, spec.expected);
          if (spec.strict) {
            const mentioned = new Set(spec.expected.map((e) => e.rule));
            const seen = new Set<string>();
            for (const f of findings) {
              const key = `${f.rule}|${f.file ?? ''}`;
              if (mentioned.has(f.rule) || f.note || seen.has(key)) continue;
              seen.add(key);
              checks.push({
                rule: f.rule,
                label: `${f.rule} absent (${f.file ?? '?'}${f.line ? `:${f.line}` : ''}, strict)`,
                expected: false,
                actual: true,
                detail: `found: ${f.file ?? '?'}${f.line ? `:${f.line}` : ''} ${f.severity}`,
              });
            }
          }
          return checks;
        },
      };
    });
}

import * as fs from 'fs';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { CodeParser } from '../src/parser/CodeParser';
import {
  checkFindings,
  checkRoutes,
  checkUnsupported,
  isRouteExpectation,
  isUnsupportedExpectation,
  type BenchCase,
  type CaseKind,
  type Expectation,
  type FindingExpectation,
  type RouteExpectation,
  type UnsupportedExpectation,
} from './core';

const CORPUS_ROOT = path.join(__dirname, 'corpus');

interface ExpectFile {
  description: string;
  knownGap?: string;
  /** vibe cases: any finding whose rule is not mentioned in `expected` counts as a false positive. */
  strict?: boolean;
  expected: Expectation[];
}

function loadExpect(dir: string): ExpectFile {
  const raw = JSON.parse(fs.readFileSync(path.join(dir, 'expect.json'), 'utf8')) as Partial<ExpectFile>;
  if (typeof raw.description !== 'string' || !Array.isArray(raw.expected) || raw.expected.length === 0) {
    throw new Error(`${dir}: expect.json needs "description" and a non-empty "expected" array`);
  }
  return raw as ExpectFile;
}

function loadDirCases(kind: Extract<CaseKind, 'static' | 'parser'>): BenchCase[] {
  const base = path.join(CORPUS_ROOT, kind);
  if (!fs.existsSync(base)) return [];
  const ids = fs
    .readdirSync(base, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

  return ids.map((id) => {
    const dir = path.join(base, id);
    const spec = loadExpect(dir);
    return {
      id,
      kind,
      description: spec.description,
      knownGap: spec.knownGap,
      async evaluate() {
        if (kind === 'static') {
          if (spec.expected.some(isRouteExpectation)) throw new Error(`${id}: route expectations belong in corpus/parser`);
          const findings = await VulnerabilityDetector.scan(dir);
          return checkFindings(findings, spec.expected as FindingExpectation[]);
        }
        if (!spec.expected.every(isRouteExpectation)) throw new Error(`${id}: parser cases take route expectations only`);
        const graph = await CodeParser.analyze(dir);
        return checkRoutes(graph.routes, spec.expected as RouteExpectation[]);
      },
    };
  });
}

/**
 * Vibe-coded app cases: findings + route guards + unsupported labels in one project, optional strict mode.
 * `corpus/vibe` ids are bare; other folders with the same format (`corpus/idor`) are prefixed `<folder>/`.
 */
function loadVibeCases(folder = 'vibe'): BenchCase[] {
  const base = path.join(CORPUS_ROOT, folder);
  if (!fs.existsSync(base)) return [];
  const ids = fs
    .readdirSync(base, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

  return ids.map((id) => {
    const dir = path.join(base, id);
    const spec = loadExpect(dir);
    return {
      id: folder === 'vibe' ? id : `${folder}/${id}`,
      kind: 'vibe' as const,
      description: spec.description,
      knownGap: spec.knownGap,
      async evaluate() {
        const findingExp = spec.expected.filter(
          (e): e is FindingExpectation => !isRouteExpectation(e) && !isUnsupportedExpectation(e),
        );
        const routeExp = spec.expected.filter(isRouteExpectation) as RouteExpectation[];
        const unsupportedExp = spec.expected.filter(isUnsupportedExpectation) as UnsupportedExpectation[];
        const findings = await VulnerabilityDetector.scan(dir);
        const checks = checkFindings(findings, findingExp);
        if (routeExp.length > 0) {
          const graph = await CodeParser.analyze(dir);
          checks.push(...checkRoutes(graph.routes, routeExp));
        }
        checks.push(...checkUnsupported(unsupportedExp));
        if (spec.strict) {
          const mentioned = new Set(findingExp.map((e) => e.rule));
          const seen = new Set<string>();
          for (const f of findings) {
            const key = `${f.rule}|${f.file ?? ''}`;
            if (mentioned.has(f.rule) || seen.has(key)) continue;
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

export function corpusCases(): BenchCase[] {
  return [...loadDirCases('static'), ...loadDirCases('parser'), ...loadVibeCases(), ...loadVibeCases('idor')];
}

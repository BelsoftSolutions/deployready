import * as fs from 'fs';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { CodeParser } from '../src/parser/CodeParser';
import {
  checkFindings,
  checkRoutes,
  isRouteExpectation,
  type BenchCase,
  type CaseKind,
  type Expectation,
  type FindingExpectation,
  type RouteExpectation,
} from './core';

const CORPUS_ROOT = path.join(__dirname, 'corpus');

interface ExpectFile {
  description: string;
  knownGap?: string;
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

export function corpusCases(): BenchCase[] {
  return [...loadDirCases('static'), ...loadDirCases('parser')];
}

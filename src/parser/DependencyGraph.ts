/**
 * Build a module dependency graph from per-file parse results.
 * Resolves relative imports to project files where possible so the AI layer
 * can reason about how routes connect to auth/db modules.
 */
import * as path from 'path';
import type { ModuleNode } from '../types';
import type { ParseResult } from './adapters/ParserAdapter';

export interface FileParse {
  relPath: string;
  result: ParseResult;
}

export class DependencyGraph {
  /** Assemble module nodes; resolve relative imports to known files. */
  static build(parses: FileParse[]): ModuleNode[] {
    const known = new Set(parses.map((p) => p.relPath));

    return parses.map(({ relPath, result }) => {
      const resolved = result.imports
        .map((imp) => DependencyGraph.resolveImport(relPath, imp, known))
        .filter((x): x is string => x !== null);

      return {
        file: relPath,
        imports: [...new Set(resolved.length ? resolved : result.imports)],
        exports: result.exports,
        isRoute: result.routes.length > 0,
      };
    });
  }

  /**
   * Resolve a relative import to a real project file, trying common extensions
   * and index files. Returns the original specifier for bare (package) imports.
   */
  private static resolveImport(
    fromFile: string,
    spec: string,
    known: Set<string>,
  ): string | null {
    if (!spec.startsWith('.')) return spec; // node_modules / bare package

    const baseDir = path.posix.dirname(fromFile.split(path.sep).join('/'));
    const target = path.posix.normalize(path.posix.join(baseDir, spec));
    const candidates = [
      target,
      `${target}.js`,
      `${target}.ts`,
      `${target}.jsx`,
      `${target}.tsx`,
      `${target}/index.js`,
      `${target}/index.ts`,
    ];
    for (const c of candidates) {
      if (known.has(c)) return c;
    }
    return spec; // unresolved relative import — keep as-is for visibility
  }
}

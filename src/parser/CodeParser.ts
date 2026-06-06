/**
 * Static analysis orchestrator. Walks the project, picks the right parser
 * adapter per file, builds the dependency graph, detects stack + entry points,
 * and assembles a CodeGraph.
 *
 * Interface contract (from spec):
 *   const graph = await CodeParser.analyze('/path/to/project');
 */
import * as path from 'path';
import { FileWalker } from '../utils/FileWalker';
import type { WalkedFile } from '../utils/FileWalker';
import { StackDetector } from './StackDetector';
import { EntryPointDetector } from './EntryPointDetector';
import { DependencyGraph } from './DependencyGraph';
import type { FileParse } from './DependencyGraph';
import { BabelAdapter } from './adapters/BabelAdapter';
import { PythonAdapter } from './adapters/PythonAdapter';
import type { ParserAdapter } from './adapters/ParserAdapter';
import type { CodeGraph, Route } from '../types';

export class CodeParser {
  private static adapters: ParserAdapter[] = [new BabelAdapter(), new PythonAdapter()];

  private static adapterFor(relPath: string): ParserAdapter | null {
    const ext = path.extname(relPath).toLowerCase();
    return CodeParser.adapters.find((a) => a.extensions.has(ext)) ?? null;
  }

  static async analyze(projectPath: string): Promise<CodeGraph> {
    const files = await FileWalker.walk(projectPath);

    const parses: FileParse[] = [];
    const routes: Route[] = [];

    for (const file of files) {
      const adapter = CodeParser.adapterFor(file.relPath);
      if (!adapter) continue;

      const source = await CodeParser.safeRead(file);
      if (source === null) continue;

      const result = adapter.parse(file.relPath, source);
      parses.push({ relPath: file.relPath, result });

      for (const r of result.routes) {
        routes.push({
          method: r.method,
          path: r.path,
          file: file.relPath,
          line: r.line,
          guarded: r.guarded,
        });
      }
    }

    const stack = await StackDetector.detect(projectPath, files);
    const modules = DependencyGraph.build(parses);
    const entryPoints = EntryPointDetector.detect(files);

    return {
      root: path.resolve(projectPath),
      stack,
      entryPoints,
      modules,
      routes,
      fileCount: parses.length,
    };
  }

  private static async safeRead(file: WalkedFile): Promise<string | null> {
    try {
      return await FileWalker.read(file);
    } catch {
      return null;
    }
  }
}

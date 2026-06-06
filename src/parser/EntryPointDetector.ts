/**
 * Identify likely application entry points (server bootstrap, route roots).
 * Used to orient the dependency graph and the AI's architectural summary.
 */
import * as path from 'path';
import type { WalkedFile } from '../utils/FileWalker';

const ENTRY_BASENAMES = new Set([
  'server.js',
  'server.ts',
  'app.js',
  'app.ts',
  'index.js',
  'index.ts',
  'main.js',
  'main.ts',
  'main.py',
  'app.py',
  'wsgi.py',
  'asgi.py',
  'manage.py',
]);

/** Directory names that strongly imply route handlers live inside. */
const ROUTE_DIRS = ['routes', 'api', 'controllers', 'pages/api', 'app/api'];

export class EntryPointDetector {
  static detect(files: WalkedFile[]): string[] {
    const found = new Set<string>();

    for (const f of files) {
      const base = path.basename(f.relPath);
      // Prefer shallow files — an index.js 6 levels deep is rarely the entry.
      const depth = f.relPath.split('/').length;
      if (ENTRY_BASENAMES.has(base) && depth <= 3) {
        found.add(f.relPath);
      }
      if (ROUTE_DIRS.some((d) => f.relPath.includes(`${d}/`))) {
        found.add(f.relPath);
      }
    }

    return [...found].sort();
  }
}

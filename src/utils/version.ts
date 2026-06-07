/**
 * Single source of truth for the tool version: read from package.json at runtime
 * so the banner, `--version`, and report headers can never drift apart again.
 *
 * Resolves the same whether running from `src/` (tsx) or `dist/` (built) — both
 * sit two levels under the package root.
 */
import { join } from 'path';

let cached: string | null = null;

export function getVersion(): string {
  if (cached) return cached;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const pkg = require(join(__dirname, '..', '..', 'package.json')) as { version?: string };
    cached = pkg.version ?? '0.0.0';
  } catch {
    cached = '0.0.0';
  }
  return cached;
}

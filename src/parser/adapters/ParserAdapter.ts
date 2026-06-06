/**
 * Parser adapter contract. Decouples the rest of the tool from any specific
 * parsing engine so we can swap Babel (default, pure-JS) for tree-sitter in
 * Phase 2 without touching call sites.
 */

export interface RouteHit {
  method: string;
  path: string;
  line?: number;
  /** Heuristic: extra middleware args present between path and handler. */
  guarded: boolean;
}

/**
 * A sub-router mount, e.g. `app.use('/api/auth', authRoutes)`. `source` is the
 * module specifier the mounted router was imported from (e.g. './routes/auth'),
 * resolved from the local binding. Used to compose full route paths across files.
 */
export interface MountHit {
  prefix: string;
  source: string;
}

export interface ParseResult {
  imports: string[];
  exports: string[];
  routes: RouteHit[];
  mounts: MountHit[];
}

export interface ParserAdapter {
  /** Languages this adapter handles, by file extension (".js", ".py", ...). */
  readonly extensions: ReadonlySet<string>;
  /** Parse a single file's source. Must never throw — return empty on failure. */
  parse(relPath: string, source: string): ParseResult;
}

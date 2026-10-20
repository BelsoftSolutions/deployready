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
  /** Names of the guard middleware seen protecting this route (evidence only). */
  guardNames?: string[];
  /** The path already contains a Flask Blueprint `url_prefix` that a registration with its own `url_prefix` would replace. */
  ownPrefix?: boolean;
  /** Declared by a NestJS controller: dropped when the project changes every controller path globally (setGlobalPrefix, RouterModule, versioning). */
  nest?: boolean;
}

/**
 * A sub-router mount, e.g. `app.use('/api/auth', authRoutes)`. `source` is the
 * module specifier the mounted router was imported from (e.g. './routes/auth'),
 * resolved from the local binding. Used to compose full route paths across files.
 */
export interface MountHit {
  prefix: string;
  source: string;
  /** True if auth middleware is applied to this mount, so every route of the mounted router is guarded. */
  guarded?: boolean;
  /** Names of the guard middleware applied to this mount (evidence only). */
  guardNames?: string[];
  /** The prefix is not a string literal or same-file constant: routes reachable only through this mount are skipped, never guessed. */
  unresolved?: boolean;
  /** Flask `register_blueprint(bp, url_prefix=...)`: replaces the blueprint's own `url_prefix` instead of adding to it. */
  overridesPrefix?: boolean;
}

export interface ParseResult {
  imports: string[];
  exports: string[];
  routes: RouteHit[];
  mounts: MountHit[];
  /** NestJS calls seen in this file that change the final path of every controller (`setGlobalPrefix`, `RouterModule`, `enableVersioning`). */
  nestGlobalConfig?: string[];
}

export interface ParserAdapter {
  /** Languages this adapter handles, by file extension (".js", ".py", ...). */
  readonly extensions: ReadonlySet<string>;
  /** Parse a single file's source. Must never throw — return empty on failure. */
  parse(relPath: string, source: string): ParseResult;
}

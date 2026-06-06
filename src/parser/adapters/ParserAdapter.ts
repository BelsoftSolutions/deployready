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

export interface ParseResult {
  imports: string[];
  exports: string[];
  routes: RouteHit[];
}

export interface ParserAdapter {
  /** Languages this adapter handles, by file extension (".js", ".py", ...). */
  readonly extensions: ReadonlySet<string>;
  /** Parse a single file's source. Must never throw — return empty on failure. */
  parse(relPath: string, source: string): ParseResult;
}

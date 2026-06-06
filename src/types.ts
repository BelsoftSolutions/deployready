/**
 * Shared type contracts for DeployReady.
 * Every module imports from here so findings, reports, and config stay consistent.
 */

export type Severity = 'critical' | 'warning' | 'info';

export type Category = 'security' | 'performance' | 'architecture' | 'config';

/** Where a finding originated. Used for dedup precedence and reporting. */
export type FindingSource = 'static' | 'dynamic' | 'ai';

/** A single issue surfaced by any analyzer. The atomic unit of a report. */
export interface Finding {
  /** Stable id used for dedup + checklist tracking (hash of category+location+rule). */
  id: string;
  /** Short rule key, e.g. "hardcoded-secret", "cors-wildcard". */
  rule: string;
  title: string;
  severity: Severity;
  category: Category;
  source: FindingSource;
  description: string;
  /** Actionable fix guidance. Maps to the spec's "fix suggestion". */
  recommendation: string;
  /** File path relative to the scanned project root, if applicable. */
  file?: string;
  line?: number;
  /** HTTP endpoint, if this is a dynamic finding. */
  endpoint?: string;
  /** OWASP Top 10 (2025) category reference, e.g. "A01:2025". */
  owasp?: string;
  /** CWE id, e.g. "CWE-798". */
  cwe?: string;
  /** Short redacted evidence snippet. MUST be passed through redact() before set. */
  evidence?: string;
}

/** A module/file node in the dependency graph. */
export interface ModuleNode {
  /** Path relative to project root. */
  file: string;
  imports: string[];
  exports: string[];
  /** True if this looks like a route/controller file. */
  isRoute: boolean;
}

/** A discovered HTTP route from static analysis. */
export interface Route {
  method: string;
  path: string;
  file: string;
  line?: number;
  /** Heuristic: does this route appear to require auth (middleware detected)? */
  guarded: boolean;
}

export type Stack =
  | 'nextjs'
  | 'express'
  | 'fastify'
  | 'nestjs'
  | 'koa'
  | 'fastapi'
  | 'flask'
  | 'django'
  | 'laravel'
  | 'unknown';

export interface StackInfo {
  stack: Stack;
  language: 'javascript' | 'typescript' | 'python' | 'php' | 'unknown';
  /** Evidence used to detect the stack (dependency names, files). */
  evidence: string[];
}

/** Output of the static parsing pipeline. */
export interface CodeGraph {
  root: string;
  stack: StackInfo;
  entryPoints: string[];
  modules: ModuleNode[];
  routes: Route[];
  /** Files scanned, for reporting. */
  fileCount: number;
}

/** A live endpoint discovered/confirmed during dynamic testing. */
export interface LiveEndpoint {
  method: string;
  path: string;
  status?: number;
  responseTimeMs?: number;
}

export interface DynamicResults {
  baseUrl: string;
  reachable: boolean;
  endpoints: LiveEndpoint[];
  /** Findings produced by dynamic testers (already typed as Finding). */
  findings: Finding[];
}

/** The complete scan result handed to UI, export, and the AI layer. */
export interface ScanReport {
  target: string;
  startedAt: string;
  finishedAt: string;
  version: string;
  stack: StackInfo;
  graph: CodeGraph;
  dynamic?: DynamicResults;
  findings: Finding[];
  score: number;
  summary: {
    critical: number;
    warning: number;
    info: number;
    total: number;
  };
  /** Optional narrative analysis from the AI layer. */
  aiSummary?: string;
}

export type AiModel = 'claude' | 'openai' | 'ollama';

export interface AppConfig {
  model: AiModel;
  /** Stored only if env var not present. Never logged. */
  claudeApiKey: string | null;
  openaiApiKey: string | null;
  ollamaPort: number;
  ollamaModel: string;
  warnBeforeExternalSend: boolean;
  defaultPorts: number[];
}

/** A single tool result returned by an AI handler. */
export interface AiAnalysis {
  /** Human-readable summary the agent shows the user. */
  summary: string;
  /** Additional findings the model inferred from the structured report. */
  findings: Finding[];
}

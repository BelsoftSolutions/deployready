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
  /** True for model-suggested findings: never scored, never counted by the CI gate. */
  unverified?: boolean;
  /** Informational note, not a vulnerability: shown in reports, never scored, never counted by the CI gate or the baseline. */
  note?: boolean;
  /** Found by the opt-in common-path probe (a guessed path), so lower confidence than a discovered-route finding. */
  guessed?: boolean;
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

/** Where a route came from: parsed source code (default) or the project's own OpenAPI/Swagger file on disk. */
export type RouteSource = 'code' | 'openapi';

/** A discovered HTTP route from static analysis. */
export interface Route {
  method: string;
  path: string;
  file: string;
  line?: number;
  /** Heuristic: does this route appear to require auth (middleware detected)? */
  guarded: boolean;
  /** Names of the guard middleware seen on the route, when the parser records them. */
  guardNames?: string[];
  /** Absent means 'code'. 'openapi' routes are declared in an OpenAPI/Swagger file on disk. */
  source?: RouteSource;
  /** OpenAPI/Swagger files (relative) that also declare this route; extra evidence on a code route. */
  specFiles?: string[];
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
  /** Files/directories not scanned because a .gitignore rule matched them. */
  gitignoreSkipped?: number;
  /** OpenAPI/Swagger files read from disk for route discovery (relative paths). */
  specFiles?: string[];
  /** Visible info lines from route discovery (e.g. a spec that was skipped and why). */
  discoveryNotes?: string[];
}

/** A live endpoint discovered/confirmed during dynamic testing. */
export interface LiveEndpoint {
  method: string;
  path: string;
  status?: number;
  responseTimeMs?: number;
}

/** A discovered route the dynamic scan requested, with the evidence for doing so. */
export interface ProbedRoute {
  method: string;
  path: string;
  why: string[];
}

/** A discovered route the scan did not request, and why. */
export interface SkippedRoute {
  method: string;
  path: string;
  reason: string;
}

/** Outcome of one path in the opt-in common-path probe. Everything except `found` is "probed, not found". */
export type CommonPathOutcome = 'found' | 'not-found' | 'protected' | 'not-proven' | 'error';

export interface CommonPathProbed {
  path: string;
  status?: number;
  outcome: CommonPathOutcome;
  reason: string;
}

/** What the opt-in common-path probe requested and what it concluded. */
export interface CommonPathReport {
  target: string;
  /** Hard cap on requests, including the control. */
  cap: number;
  control: { path: string; status?: number };
  probed: CommonPathProbed[];
  /** Table paths not requested because the normal scan already covers them. */
  covered?: string[];
  aborted?: string;
}

export interface DynamicResults {
  baseUrl: string;
  reachable: boolean;
  endpoints: LiveEndpoint[];
  /** Exactly the routes requested (all discovered by static analysis). */
  probed: ProbedRoute[];
  /** Discovered routes that were not requested, with reasons. */
  skipped: SkippedRoute[];
  /** Findings produced by dynamic testers (already typed as Finding). */
  findings: Finding[];
  /** Present only when the opt-in common-path probe ran. */
  commonPaths?: CommonPathReport;
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
    /** Scored findings only (excludes unverified AI suggestions). */
    total: number;
    /** AI suggestions: shown, but not scored and not counted above. */
    unverified?: number;
    /** Informational notes: shown, but not scored and not counted above. */
    notes?: number;
  };
  /** Optional narrative analysis from the AI layer. */
  aiSummary?: string;
}

export type AiModel = 'claude' | 'openai' | 'ollama' | 'claude-cli' | 'codex-cli';

export interface AppConfig {
  model: AiModel;
  /** Stored only if env var not present. Never logged. */
  claudeApiKey: string | null;
  openaiApiKey: string | null;
  ollamaPort: number;
  ollamaModel: string;
  /** Optional absolute path to the claude/codex executable for the CLI providers. User-level config only. */
  cliCommand?: string | null;
  /** Optional model name passed to the CLI providers (validated before use). */
  cliModel?: string | null;
  /** codex-cli is a normal provider; set to false to switch it off. User-level config only. */
  codexEnabled?: boolean;
  warnBeforeExternalSend: boolean;
  defaultPorts: number[];
  /** Opt-in common-path probe (see docs/COMMON-PATH-PROBE.md). Off by default; never written as true by init. */
  probeCommonPaths: boolean;
}

/** A single tool result returned by an AI handler. */
export interface AiAnalysis {
  /** Human-readable summary the agent shows the user. */
  summary: string;
  /** Additional findings the model inferred from the structured report. */
  findings: Finding[];
}

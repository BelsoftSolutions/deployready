/**
 * Shared type contracts for DeployReady.
 * Every module imports from here so findings, reports, and config stay consistent.
 */

export type Severity = 'critical' | 'warning' | 'info';

export type Category = 'security' | 'performance' | 'architecture' | 'config';

/** Where a finding originated. Used for dedup precedence and reporting. */
export type FindingSource = 'static' | 'dynamic' | 'ai' | `engine:${string}`;

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
  /** Reproducible proof for a live finding. Every string MUST be passed through redact() before set. */
  proof?: Proof;
  /** Severity the source suggested before it was demoted (unverified/AI findings are scored as info). */
  suggestedSeverity?: Severity;
}

/** What was sent and what came back, so a user (or their agent) can reproduce a live finding. */
export interface Proof {
  /** Reproducible request, e.g. a curl command (secrets redacted). */
  request: string;
  status?: number;
  /** Truncated, redacted response body. */
  response?: string;
  /** The control request that shows the endpoint otherwise works (e.g. the owner's own request). */
  control?: string;
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
  /** What was actually tested, per check area (see src/core/coverage.ts). */
  coverage?: CoverageArea[];
  /** Policy-driven release verdict, separate from the numeric score (see src/core/releaseState.ts). */
  release?: ReleaseAssessment;
  /** Outcome of each external engine adapter (ran / skipped / error) with coverage. */
  engineRuns?: import('./adapters/types').EngineRunSummary[];
}

// ---- Coverage + release state ---------------------------------------------------

/**
 * Did a check area run? `passed` = it ran to completion (its findings are counted in the findings
 * dimension, not here); `failed` = the scanner errored, which is never a pass; `untested` = it did
 * not run (opt-in, disabled, no server/token); `inconclusive` = it ran but could not cover its
 * target (e.g. no route could be requested); `not-applicable` = nothing for it to check.
 */
export type CoverageState = 'passed' | 'failed' | 'untested' | 'inconclusive' | 'not-applicable';

export type CoverageKind =
  | 'static'
  | 'secrets'
  | 'dependencies'
  | 'engines'
  | 'supabase-static'
  | 'supabase-live'
  | 'firebase'
  | 'firebase-emulator'
  | 'dynamic'
  | 'active'
  | 'ai';

export interface CoverageArea {
  /** `kind` for most areas; static areas are per language, e.g. "static-python". */
  id: string;
  kind: CoverageKind;
  label: string;
  state: CoverageState;
  reason: string;
  /** The user explicitly asked for this area in this run (a flag): an error or skip then matters. */
  requested?: boolean;
  /** Required by the release policy (requireAreas) or requested in this run. */
  mandatory?: boolean;
  /** Exercises the running app or a live backend (dynamic, active, supabase-live). */
  live?: boolean;
}

export type ReleaseState = 'ready' | 'ready-with-accepted-risks' | 'review-required' | 'not-ready' | 'insufficient-evidence';

export interface ReleasePolicy {
  /** Confirmed findings at these severities make the release not-ready. Default ["critical"]. */
  blockOn: Severity[];
  /** Areas (id or kind) that must pass; failed/untested means insufficient-evidence. Default ["static","secrets"]. */
  requireAreas: string[];
  /** Unverified/AI or suspected findings at a blockOn severity. Never "ready". Default "review-required". */
  treatUnverifiedCriticalAs: 'review-required' | 'not-ready';
}

export interface ReleaseAssessment {
  state: ReleaseState;
  /** True when no live area (dynamic, active, supabase-live) passed: "ready" then means static evidence only. */
  limitedCoverage: boolean;
  /** Why the state is what it is, most important first. */
  reasons: string[];
  /** Confirmed (scored, not guessed, not accepted) findings by severity. */
  findings: { critical: number; warning: number; info: number };
  confidence: {
    confirmed: number;
    /** All unverified findings (AI included). */
    unverified: number;
    ai: number;
    /** Scored but lower confidence (guessed common-path probe hits). */
    suspected: number;
    /** Unverified or suspected findings whose suggested severity is in blockOn. */
    unconfirmedBlocking: number;
  };
  verification: { fixedVerified: number; fixedUnverified: number; open: number };
  /** Findings accepted by the baseline (grandfathered risks). */
  accepted: number;
  policy: ReleasePolicy;
  /** One-line headline, e.g. "Release: NOT READY — 2 confirmed critical · Coverage: static ✓ · ...". */
  line: string;
  policyWarnings?: string[];
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
  /**
   * Pre-approve sending the redacted report/snippet to an external AI provider (API or claude/codex
   * CLI) without a prompt, including non-interactive runs. Off by default; `--yes` never implies it.
   */
  allowExternalAi?: boolean;
  defaultPorts: number[];
  /** Opt-in common-path probe (see docs/COMMON-PATH-PROBE.md). Off by default; never written as true by init. */
  probeCommonPaths: boolean;
  /** Non-loopback hosts the user owns; active probes may target them (like --i-own-this-target). */
  ownedTargets?: string[];
  /** Release-state policy (see README "Score and release state"); missing keys use the defaults. */
  releasePolicy?: Partial<ReleasePolicy>;
  /** Active-scan safety and verdict settings (see README, "Active testing"). */
  active?: ActiveConfigSection;
  /** Alias of `active.unsafeRoutes`. */
  unsafeRoutes?: string[];
  /** Alias of `active.disposableEnvironment`. */
  disposableEnvironment?: boolean;
}

/** Active-scan safety levels, least to most invasive. */
export type SafetyLevel = 'passive' | 'read-only' | 'controlled-active' | 'stateful';

/** The `"active"` section of the config file. */
export interface ActiveConfigSection {
  safetyLevel?: SafetyLevel;
  /** Route denylist: exact paths or globs (`*` = any characters), optionally prefixed by a method (`GET /api/export*`). */
  unsafeRoutes?: string[];
  /** Fields the verdict engine ignores (key names or dotted paths), on top of the volatile ones it learns. */
  ignoredFields?: string[];
  /** Routes that are public by design: cross-identity reads there are reported as intentionally-public. */
  publicRoutes?: string[];
  /** Hard cap on active requests per run (default 200). */
  maxRequests?: number;
  /** Required for the stateful level: the target holds only disposable test data. */
  disposableEnvironment?: boolean;
}

/** A single tool result returned by an AI handler. */
export interface AiAnalysis {
  /** Human-readable summary the agent shows the user. */
  summary: string;
  /** Additional findings the model inferred from the structured report. */
  findings: Finding[];
}

# DeployReady roadmap audit (baseline 0.4.0, commit 44a168e)

Scope: read-only audit of `/home/user/deployready` at 0.4.0 (branch `claude/determined-hypatia-s6susw`). Every statement cites a file. Items marked **[reproduced]** were run against `dist/` during this audit. Items marked **[unverified]** come from memory or were not run. Nothing here is a benchmark result; the only numbers quoted are ones present in the repo or produced by commands listed in section 5.

Measured during the audit: `npx jest` = 83 suites, 1309 passed, 2 skipped (1311 total) on Node v22.23.5. `package-lock.json` lists 444 packages (180 non-dev); `package.json` declares 10 direct runtime dependencies (`@babel/*` x3, `@modelcontextprotocol/sdk`, `axios`, `chalk`, `commander`, `inquirer`, `ora`, `zod`).

Contents: 1 Architecture, 2 Features, 3 Coverage matrix, 4 Threat model, 5 Audit status, 6 Backlog, 7 Free/Pro, 8 Test and release strategy.

---

## 1. Architecture inventory

### 1.1 Modules (src/, ~13.5k lines of TypeScript)

| Module | Files | Responsibility |
|---|---|---|
| CLI | `src/cli/Commands.ts`, `InteractiveShell.ts` (854 lines), `Onboarding.ts`, `cliSetup.ts`; `bin/deployready.js` | Commander commands, interactive REPL, first-run wizard |
| Core | `src/core/Orchestrator.ts`, `CiGate.ts`, `Verifier.ts` | Pipeline wiring, consent gates, CI exit codes/baseline/JSON, re-check of one finding |
| Walker | `src/utils/FileWalker.ts`, `GitIgnore.ts` | Bounded, root-confined file discovery (2 MB/file, 20 000 files) |
| Parser | `src/parser/*` (`CodeParser`, `StackDetector`, `adapters/BabelAdapter.ts`, `PythonAdapter.ts`, `nest.ts`, `nextRoutes.ts`, `openapi.ts`, `miniYaml.ts`) | Stack detection, route + guard discovery (JS/TS via Babel, Python by adapter), OpenAPI route import |
| Static rules | `src/analysis/rules.ts` (line regex rules), `VulnerabilityDetector.ts`, `rls.ts`, `idor.ts`, `routeAuth.ts`, `SeverityScorer.ts` | Single-line regex rules, secret detection, project checks (.env, workflows), SQL RLS, static IDOR, missing-auth routes |
| Supabase | `src/supabase/{static,live,guard,http,keys,index}.ts` | Static key checks; ownership-gated read-only live probes |
| Firebase | `src/firebase/*` | Static parse of `firestore.rules`, `storage.rules`, RTDB rules; service-account detection |
| Dynamic | `src/dynamic/*` (`DynamicTester`, `EndpointMapper`, `SecurityTester`, `PerformanceTester`, `APIAnalyzer`, `advertised.ts`, `commonPaths/*`, `httpClient.ts`, `LocalhostDetector.ts`) | GET-only probing of a loopback app using discovered routes only |
| Active | `src/active/*` (`runner`, `requestPlan`, `tamper`, `jwt`, `accessControl`, `mutationProbe`, `scope`, `httpAdapter`) | Token-based identity tampering, tenant/IDOR checks, unauthenticated DELETE/PATCH probe |
| Aggregation | `src/analysis/IssueAggregator.ts`, `ScoreCalculator.ts` | Dedup (dynamic > static > ai), severity policy, score `100*K/(K+penalty)` with K=30, weights 10/3/1 |
| AI | `src/ai/*` (`ModelRouter`, `Claude/OpenAI/Ollama/CliHandler`, `PromptBuilder`, `verifyAiFindings`, `cli/*`) | Optional model analysis and fix suggestions; CLI providers run `claude`/`codex` as child processes |
| Fix | `src/agent/*` (`FileEditor`, `FixManager`, `lineFixers`, `context`, `SessionManager`) | Backed-up, root-confined edits; deterministic line fixers |
| Reports | `src/ui/*` (`IssuePresenter`, `ExportManager`, `HtmlReporter`, `Sarif`, `badge`, `DeploymentGuide`), `action/summary.js`, `action/comment.js` | Terminal, markdown, HTML, SARIF 2.1.0, badge, PR comment |
| MCP | `src/mcp/{server,tools,readiness,fixes,analyzeFix,supabase}.ts` | stdio MCP server (6 tools) reusing Orchestrator and FixManager |
| Config/State | `src/config/ConfigManager.ts`, `src/tracker/*` | `~/.deployready/config.json`, checklist/score state |
| Distribution | `action.yml`, `.github/workflows/{ci,publish}.yml`, `skills/deployready/SKILL.md`, `docs/` | Composite GitHub Action, npm trusted publishing, Claude Code skill |

### 1.2 Data flow

```
target dir
  -> FileWalker.walkWithStats (realpath confinement, gitignore, size/count caps)
  -> CodeParser.analyze  -> CodeGraph {stack, routes+guards, modules, specFiles}      [src/core/Orchestrator.ts:96-101]
  -> VulnerabilityDetector.scan -> static findings (regex rules, secrets, RLS, IDOR, route auth, env/git state)
  -> [dynamic]  LocalhostDetector -> consent -> DynamicTester (GET) [-> common-path probe, opt-in]
  -> [active]   --active --token: requestPlan -> runActiveScan [+ mutationProbe on loopback]
  -> supabaseStep (static always; live only with --supabase) , firebaseStep (static only)
  -> IssueAggregator.process (SeverityScorer -> dedupe -> sort -> ScoreCalculator.summarize/calculate)
  -> ScanReport
  -> [AI] ModelRouter.analyze(report) -> verifyAiFindings (file must exist; severity forced to info; unverified) -> re-aggregate
  -> IssuePresenter | ExportManager (md/html) | CiGate.toCiJson | Sarif | MCP result | badge
```

Step order and gates are in `src/core/Orchestrator.ts` (analyze at lines 85-175; consent prompts inside `runDynamic`, `runProbe`, `runActive`, `runAi`).

### 1.3 External process execution points

| Where | What runs | Controls found in code |
|---|---|---|
| `src/ai/cli/runCli.ts` (`spawn`) | `claude` / `codex` for AI analysis, status, login | `shell:false` except `.cmd` shims via `cmd.exe /d /s /c` with arg allowlist (`SAFE_SHIM_ARG`); fresh empty temp cwd; deny-by-default env (`src/ai/cli/env.ts`); prompt on stdin; stdout cap 256 KB; 120 s timeout; process-tree kill; fixed argv with tools off (`src/ai/cli/argv.ts`, `FORBIDDEN_ARGV` guard) |
| `src/ai/cli/resolve.ts`, `ready.ts` | Resolve executable path, run `auth status` / `login status` | via `runCli` |
| `src/analysis/VulnerabilityDetector.ts:400` | `git rev-parse / ls-files / log` (`execFileSync`, 5 s timeout, `core.fsmonitor=false`) | argv array, no shell; `rel` is a repo-relative path passed after `--` |
| `src/utils/openBrowser.ts:19` | `open` / `xdg-open` / `start` | **`spawn(cmd, {shell:true})` with the report path interpolated in double quotes** (see 4.3, T-09) |
| No other `child_process` use in `src/` | | grep confirmed |

No scanner binaries (Semgrep, Gitleaks, Trivy, OSV) are executed today.

### 1.4 Network egress points

| Where | Destination | Trigger / gate |
|---|---|---|
| `src/dynamic/httpClient.ts` (`createClient`) | loopback only (string allowlist `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, `*.localhost`); `maxRedirects:0`, 8 s timeout, 5 MB cap | dynamic scan after prompt or `--yes` |
| `src/active/httpAdapter.ts` | loopback, or exact hosts named by `--i-own-this-target` / config `ownedTargets` (`src/active/scope.ts`); re-checked per request | `--active --token` |
| `src/supabase/http.ts`, `live.ts` | the project's `*.supabase.co` URL (or loopback); `api.supabase.com` when an access token proves ownership | `--supabase` plus ownership proof (`guard.ts`) |
| `src/ai/ClaudeHandler.ts`, `OpenAIHandler.ts` | Anthropic / OpenAI APIs, redacted structured report | AI enabled, consent unless `--yes` |
| `src/ai/OllamaHandler.ts`, `Onboarding.ts:78` | `127.0.0.1:<ollamaPort>` | Ollama model |
| `claude`/`codex` child processes | whatever those CLIs contact | CLI providers |
| `npx deployready@<version>` in `action.yml` | npm registry | GitHub Action |
| Reports | none (HTML has zero external resources; only an `<a>` to deployready.dev, `src/ui/HtmlReporter.ts`) | |

---

## 2. Feature inventory with maturity

Maturity legend: **E2E** = exercised through `Orchestrator`/`VulnerabilityDetector`/`DynamicTester` against a fixture project or a real local HTTP server in tests; **Unit** = unit tests of the module only; **Mocked** = only exercised with injected fakes (fake CLI, mock transport, stub HTTP function); **Docs** = described in docs/README but no test found. No test spawns `bin/deployready.js` as a process (grep of `tests/` for `deployready.js`/`dist/index` returned nothing), and no test connects to the MCP server over stdio (tests call `DeployReadyTools` and `buildMcpServer` handlers directly). So "E2E" here never means the packaged CLI.

### 2.1 CLI commands and flags (`src/cli/Commands.ts`)

| Command / flag | Purpose | Maturity | Evidence |
|---|---|---|---|
| `deployready [path]` / `interactive` / `shell` | Interactive REPL (default) | Unit | `tests/shell*.test.ts` drive the shell class, not a TTY |
| `analyze [path]` | One-shot scan | E2E (library level) | `tests/orchestratorFlow.test.ts`, `regression-e2e.test.ts` |
| `-y/--yes` | Auto-approve all prompts | Unit | `tests/aiOrchestrator.test.ts` |
| `--fix` | Safe deterministic fixes then re-scan | Unit | `tests/analyze-fix.test.ts` |
| `--no-dynamic`, `--no-ai`, `--aggressive` | Skip/enable stages | E2E | `tests/dynamic.test.ts`, `orchestrator-no-routes.test.ts` |
| `--export`, `--html`, `--open` | md / HTML report; open browser | Unit (`exporters`, `htmlReporter`); `--open` untested (spawns OS opener) | `tests/exporters.test.ts` |
| `--json` | Machine-readable report, implies `--yes` | Unit | `tests/ciGate.test.ts` |
| `--sarif <file>` | SARIF 2.1.0 | Unit | `tests/sarif.test.ts` |
| `--fail-on critical\|warning\|info\|none` | Exit 2 on gate | Unit | `tests/ciGate.test.ts` |
| `--baseline`, `--write-baseline` | Grandfather findings | Unit | `tests/ciGate.test.ts` (P0 area, being changed) |
| `--probe-common-paths` / `--no-probe-common-paths` | Opt-in guessed-path probe | E2E (real local server) | `tests/common-path-probe-*.test.ts`, `tests/helpers/probeServer.ts` |
| `--active`, `--token`, `--token-b`, `--active-url`, `--i-own-this-target` | Authenticated authorization tests | Unit + Mocked (stub `HttpFn`; real adapter in `active-httpAdapter.test.ts` against local server) | `tests/active-*.test.ts` |
| `--supabase`, `--supabase-url/-anon-key/-service-key/-access-token`, `--supabase-cross-user` | Live Supabase checks | Mocked (`tests/helpers/supabaseMock.ts`) | `tests/supabase-live.test.ts`, `supabase-guard.test.ts` |
| `init` | Setup wizard | Unit | `tests/onboardingCli.test.ts` |
| `report [path]` | Re-scan, write markdown | Unit | `tests/exporters.test.ts` |
| `config` | Show config, secrets masked | Unit-light | `Commands.ts` prints `«set»` |
| `badge [path] [--write-svg]` | README badge | Unit | `tests/badge.test.ts` |
| `mcp [path]` | stdio MCP server | Unit (tool handlers); stdio transport untested | `tests/mcp-tools.test.ts`, `supabase-mcp.test.ts` |
| Shell commands `scan parse dynamic ai issues show fix prompt verify done ignore score status deploy export open config` | Interactive workflow | Unit | `tests/shell.test.ts`, `shell-verify-status.test.ts` |

### 2.2 MCP tools (`src/mcp/server.ts`)

| Tool | Reads | Modifies | Network | Maturity |
|---|---|---|---|---|
| `scan` | project files | no (writes cache in memory only) | `dynamic:true` sends GET requests to localhost; with `DEPLOYREADY_TOKEN` in env also runs the active scan incl. DELETE/PATCH mutation probe | Unit |
| `get_finding` | whole file of the finding (up to 256 KB) | no | none | Unit |
| `apply_safe_fixes` | project files | **yes**: edits source and `.gitignore` (backups under `.deployready/backups`) | none | Unit |
| `verify` | files; re-probes live app | no | loopback / owned host per env tokens | Unit |
| `score` | re-scan | no | as `scan` | Unit |
| `supabase_check` | project files | no | `live:true` contacts Supabase project | Mocked |

### 2.3 Report formats

| Format | Producer | Maturity |
|---|---|---|
| Terminal | `IssuePresenter.ts` | Unit |
| Markdown | `ExportManager.saveMarkdown` | Unit |
| HTML dashboard | `HtmlReporter.ts` (all values pass `esc()`) | Unit (`tests/htmlReporter.test.ts`) |
| JSON for CI | `CiGate.toCiJson` | Unit |
| SARIF 2.1.0 | `ui/Sarif.ts` | Unit |
| PR job summary + sticky comment | `action/summary.js`, `action/comment.js` | Unit for summary (`tests/actionSummary.test.ts`); comment script Docs-only; `action.yml` as a whole never run in CI of this repo |
| Badge (markdown, SVG) | `ui/badge.ts` | Unit |

### 2.4 Providers and integrations

| Provider | Direction | Maturity |
|---|---|---|
| Claude API, OpenAI API, Ollama | AI analysis + fix suggestions | Mocked (`tests/aiHandlers.test.ts` with stubbed axios) |
| `claude` CLI, `codex` CLI | AI via subscription login | Mocked with a fake CLI executable (`tests/helpers/fakeCli.ts`, `cliProviderRun.test.ts`); never run against the real CLIs in CI |
| Supabase | static + live | static Unit/E2E (`supabase-static.test.ts`), live Mocked |
| Firebase | static rules only (no emulator, no live) | Unit with corpus (`tests/firebase-static.test.ts`, `benchmark/corpus/firebase`) |
| OpenAPI/Swagger on disk | route discovery | E2E (`tests/openapi-e2e.test.ts`) |
| GitHub Action | PR summary, SARIF, comment | Docs-only for the composite flow (third-party actions pinned by SHA in `action.yml`) |
| Claude Code skill | `skills/deployready/SKILL.md` | Docs-only |

### 2.5 Parser / language support (from `src/parser/*`, `src/types.ts`)

Stack enum: nextjs, express, fastify, nestjs, koa, fastapi, flask, django, laravel. Route + guard extraction exists for JS/TS (Babel), Next.js file routes, NestJS decorators, Python (FastAPI/Flask via `PythonAdapter`). Django and Laravel are detected as stacks; no evidence of route extraction for them in `src/parser/` (not verified beyond file listing). PHP files are walked (`SOURCE_EXTS`) and have no dedicated rules in `rules.ts`.

---

## 3. Security coverage matrix

Status: **Implemented** = rule exists with test or benchmark case; **Partial** = narrow pattern only; **Missing** = nothing found in `src/`. Rule ids from `src/analysis/rules.ts`, `VulnerabilityDetector.ts`, `src/dynamic/*`, `src/active/*`, `src/supabase/*`, `src/firebase/*`. The OWASP tag in code is the repo's own mapping (`owasp:` field); I report it as written and flag where it looks off against the 2025 list.

### 3.1 OWASP Top 10 2025

| Category | Status | Rule ids | Gap |
|---|---|---|---|
| A01 Broken Access Control | Partial | `missing-auth-route`, `idor-missing-ownership-check`, `rls-disabled`, `rls-not-enabled`, `rls-no-policy`, `rls-permissive-policy` (static); `auth-bypass`, `exposed-admin-route`, `bola-idor`, `privilege-escalation`, `unauthenticated-mutation` (active/dynamic); `supabase-anon-read`, `supabase-rpc-anon-executable`, `supabase-storage-anon-list`, `supabase-cross-user-read`; Firebase rules rules | RLS is not migration-aware (P0, in progress); no role/permission matrix testing; IDOR regex-based; CSRF absent |
| A02 Security Misconfiguration | Partial | `cors-wildcard`, `cors-wildcard-live`, `debug-enabled`, `py-flask-debug`, `insecure-cookie`, `missing-security-headers`, `insecure-http-url`, `next-public-secret`, `flask-hardcoded-secret-key`, `env-not-ignored` | No Dockerfile/K8s/Terraform/IaC checks (walker only reads `Dockerfile` as an extra file, no rules for it found); CORS rule tagged A02 in code |
| A03 Software Supply Chain Failures | Missing | none | No dependency CVE lookup, no lockfile parsing, no install-script / typosquat / provenance checks, no GitHub Actions pinning check. Only `npm audit` on DeployReady itself in `.github/workflows/ci.yml` |
| A04 Cryptographic Failures | Partial | `weak-hash`, `py-weak-hash`, `insecure-random`, `py-insecure-random`, `tls-verification-disabled`, `py-requests-noverify`, `py-mktemp` | No password-hashing policy, no TLS config review, no secrets-at-rest checks |
| A05 Injection | Partial | `sql-injection`, `py-sql-fstring`, `command-injection`, `py-shell-injection`, `py-os-system`, `eval-usage`, `py-eval-exec`, `xss-sink` | Single-line regexes (`rules.ts` header says so); no taint tracking; NoSQL/template/SSRF/path-traversal sinks absent |
| A06 Insecure Design | Missing | none | Rate-limit presence only (`missing-rate-limit`, aggressive dynamic) |
| A07 Authentication Failures | Partial | `jwt-none-alg`, `py-jwt-none`, `jwt-hardcoded-secret`, `jwt-not-verified`, `supabase-open-signups`, `supabase-email-confirm-off`, `missing-rate-limit` | No session fixation, password policy, MFA, or OAuth state checks |
| A08 Software/Data Integrity Failures | Partial | `py-yaml-load`, `py-pickle-loads` | No CI integrity (unpinned actions), no unsafe deserialization for JS |
| A09 Logging & Alerting Failures | Partial | `log-injection` | Presence/absence of audit logging not assessed |
| A10 Mishandling of Exceptional Conditions (2025 new) | Partial | `stack-trace-leak` (dynamic), `version-banner` | No static check for swallowed errors / fail-open handlers |

OWASP 2025 category names: taken from the list as I know it (A03 Software Supply Chain Failures, A10 Mishandling of Exceptional Conditions). **[unverified against the official page in this session]**; `docs/` does not contain the list.

### 3.2 Key CWEs

| CWE | Status | Rule |
|---|---|---|
| CWE-79 XSS | Partial (sink regex) | `xss-sink` |
| CWE-89 SQLi | Partial | `sql-injection`, `py-sql-fstring` |
| CWE-78 / 77 command injection | Partial | `command-injection`, `py-shell-injection`, `py-os-system` |
| CWE-22 path traversal | Missing | none |
| CWE-918 SSRF | Missing (app code); DeployReady's own SSRF guard exists | none |
| CWE-352 CSRF | Missing | none |
| CWE-798 hardcoded credentials | Implemented, being rewritten (P0) | `hardcoded-secret`, `possible-hardcoded-secret`, `jwt-hardcoded-secret`, `flask-hardcoded-secret-key` |
| CWE-306 missing auth | Partial | `missing-auth-route`, `unauthenticated-mutation` |
| CWE-285 / 862 / 863 authorization | Partial | `rls-*`, `idor-missing-ownership-check`, `bola-idor`, `privilege-escalation` |
| CWE-639 IDOR | Partial | `idor-missing-ownership-check`, `bola-idor` |
| CWE-502 deserialization | Partial (Python only) | `py-yaml-load`, `py-pickle-loads` |
| CWE-295 TLS validation | Implemented | `tls-verification-disabled`, `py-requests-noverify` |
| CWE-327 / 338 weak crypto / PRNG | Implemented | `weak-hash`, `insecure-random` |
| CWE-1321 prototype pollution, CWE-434 upload, CWE-601 open redirect | Missing | none |
| CWE-1104 / 1395 vulnerable components | Missing | none |

### 3.3 Directive categories

| Category | Status | Rule ids / notes |
|---|---|---|
| Application security (static) | Partial | see 3.1; JS/TS and Python only |
| Application security (dynamic/active) | Partial | `secret-in-response`, `missing-security-headers`, `cors-wildcard-live`, `stack-trace-leak`, `common-path-exposure`, `slow-endpoint`, `missing-cache-headers`; active: `auth-bypass`, `bola-idor`, `privilege-escalation`, `unauthenticated-mutation`; GET-only except mutation probe; no authenticated crawling, no role matrix |
| Supply chain | Missing | see A03 |
| Infrastructure (Docker, IaC, headers, TLS, deploy config) | Missing / minimal | `PlatformRecommender` suggests hosts, it does not audit them; `insecure-http-url` only |
| AI-app security (prompt injection, tool permissions, LLM key exposure, output handling) | Missing | Only generic secret patterns (`sk-ant-`, `sk-`) in `redact.ts` / secret detector. No rule for user input concatenated into prompts, agent tools with shell/file/network, unbounded tool loops, RAG data leakage, or client-side LLM keys beyond `next-public-secret` pattern |
| Supabase | Implemented (best-covered area) | static: `supabase-service-role`, `rls-*`; live (read-only): `supabase-anon-read`, `supabase-rpc-anon-executable`, `supabase-storage-anon-list`, `supabase-storage-public-bucket`, `supabase-open-signups`, `supabase-email-confirm-off`, `supabase-cross-user-read`. Gap: RLS migration awareness (P0), storage policy SQL, edge function auth |
| Firebase | Partial (static only) | `firebase-no-rules-file`, `firebase-service-account-committed`, plus rules findings (`src/firebase/rules.ts`). No emulator-backed rule tests, no App Check, no Cloud Functions auth, no live probe (`docs/FIREBASE.md`: static only) |
| Payments (Stripe etc.) | Missing | Stripe secret key shape only appears in `redact.ts` (`sk_live_`, `rk_`). No webhook-signature check, no client-trusted price/amount, no idempotency, no `pk_`/`sk_` misuse, no Checkout/redirect validation |

---

## 4. Threat model of DeployReady itself

DeployReady reads untrusted repositories, executes code paths that send network requests, spawns two CLIs, can write into the project, and is driven by an AI agent through MCP. Priority: **P0** blocks trust claims, **P1** next release, **P2** hardening.

### 4.1 Assets and trust boundaries

| Asset | Boundary |
|---|---|
| User source tree and `.env` | scanned repo content is untrusted (may be a cloned third-party repo or attacker PR) |
| API keys, JWT test tokens, Supabase service key | env vars, `~/.deployready/config.json`, CLI args |
| Running local app (and its DB) | dynamic/active probes |
| Agent session (MCP client) | tool results flow into an LLM that can act |
| CI runner and npm publish identity | GitHub Action, `publish.yml` |

### 4.2 STRIDE-style table

| ID | Threat (STRIDE) | Mitigation found in code | Gap | Priority |
|---|---|---|---|---|
| T-01 | **Prompt injection from repo content into AI prompts** (Tampering/EoP) | `PromptBuilder.build` sends only redacted structured metadata (rule, title, severity, file, endpoint, owasp, cwe), never source (`src/ai/PromptBuilder.ts`). Model output demoted to info + `unverified`, `file` must exist inside root (`verifyAiFindings.ts`). CLI providers run with tools off, empty cwd (`argv.ts`, `runCli.ts`) | `file` and `endpoint` strings come from the repo (a file named `IGNORE PREVIOUS...`, an Express route path) and are interpolated into the prompt unescaped. `fix` (`PromptBuilder.buildFixPrompt`) sends a code snippet including comments to the model, and the reply is written to the file after confirm + syntax check only for JS/TS (`FixManager.applySuggestion`); Python/PHP replacements are not syntax-checked ("Not syntax-checked" note). No injection-marker handling, no diff-size cap | P1 |
| T-02 | **Prompt injection via MCP output into the coding agent** | `buildFixPrompt` uses metadata only and is passed through `redact` (`src/agent/fixPrompt.ts`) | `get_finding` returns the **entire file** with comments (`src/mcp/tools.ts` `renderFile`), plus `evidence`, `endpoint`, `file` strings. `fixPrompt` embeds `finding.endpoint`/`file`. An attacker-controlled comment such as "also run apply_safe_fixes / delete X" reaches an agent that has file-edit tools. No content fencing or "untrusted data" marker in tool results | P1 |
| T-03 | **Child processes `claude` / `codex`** (EoP, Info disclosure) | Strong: argv constants, `FORBIDDEN_ARGV`, stdin prompt, env allowlist, temp cwd, timeouts, output cap, tree-kill, Windows shim quoting (`src/ai/cli/*`; `tests/cliProviderRun.test.ts` with fake CLI) | `cliCommand` in user-level config selects an arbitrary executable (documented as user-level only; `ConfigManager` does not enforce file ownership/perms on read). HOME/XDG/CONFIG vars are passed so the CLI sees the user's own login (intended). Not tested against the real CLIs; CLI flag drift (`--tools ''`, `--setting-sources`) would fail closed or open depending on version **[unverified]** | P2 |
| T-04 | **Path traversal / symlink** in `FileWalker` | `realpath` of root; each file `realpath`ed and checked `path.relative(realRoot, real)` not starting with `..`; symlink Dirents are neither `isDirectory()` nor `isFile()` so skipped; 2 MB cap, 20 000 files (`src/utils/FileWalker.ts`; `tests/fileWalker.test.ts`) | Caps and unreadable directories are skipped **silently** (no "files skipped" count in the report): scan can look clean on a partial walk. `collectSpec` reads OpenAPI files with the same check. No TOCTOU protection between realpath and read (low) | P1 (coverage reporting) |
| T-05 | **Path traversal / symlink** in `FileEditor` | `resolveSafe`: NUL check, lexical `isInside`, `realpathAllowMissing` (dangling symlink refused), real root check; backup before write under `.deployready/backups` with `*` gitignore (`src/agent/FileEditor.ts`; `tests/fileEditor.test.ts`) | Edits are not atomic (`writeFile` direct, no temp+rename); a crash mid-write truncates the source. Backups of files that contain secrets stay on disk (documented). MCP `path` argument is **not** confined to the server's default project (see T-08) | P1 |
| T-06 | **HTML report XSS** | Every dynamic value passes `esc()`; zero external resources; `rel="noopener noreferrer"` links; copy-prompt text goes through `data-prompt="${esc(...)}"` (`src/ui/HtmlReporter.ts`; `tests/htmlReporter.test.ts`) | No CSP `<meta>`; inline `<script>`/`<style>` mean a future escaping slip is exploitable. The page is opened via `openInBrowser` straight from the project dir (file:// origin). Evidence/proof are redacted before storage but redaction is pattern-based | P2 |
| T-07 | **SSRF / redirects** in dynamic and active | Loopback allowlist by hostname string; redirects disabled (`maxRedirects:0`); 8 s timeout; 5 MB cap; active adapter re-validates every URL against the base host and owned-host list (`src/dynamic/httpClient.ts`, `src/active/scope.ts`, `httpAdapter.ts`); route paths must start with `/` (`EndpointMapper.unrequestable`); common-path probe capped at 20 GETs | (a) A discovered route like `//127.0.0.1/x` passes `unrequestable()` (returns null, **[reproduced]**); axios then fails with `Invalid URL` rather than switching host, so it is not exploitable on axios 1.20 but relies on library behaviour (no explicit `//` or `\` rejection). (b) "Loopback" is a hostname string check: it proves the app is local, not that it is non-production (a dev app wired to a production database is still probed). (c) `--i-own-this-target` is a self-attestation. (d) GET is assumed safe: apps with state-changing GETs (logout, `/delete?id=`) are hit; the rate-limit burst (`--aggressive`) can lock accounts or send email | P1 |
| T-08 | **MCP tool permissions: read-only vs modifying** | Tools are non-interactive and never call an AI model (`src/mcp/tools.ts` header). `apply_safe_fixes` is deterministic, backed up, scoped to fixable rules. Tokens only from env, never tool args (`Verifier.tokensFromEnv`) | **Not separable**: one server exposes `scan`/`get_finding`/`score`/`verify` (read) and `apply_safe_fixes` (writes source and `.gitignore`) with no flag, scope, or per-tool confirmation. `path` arg accepts any directory: `resolve(defaultPath, p)` (`tools.ts:resolve`) lets an agent scan or **modify** a project outside the server's configured root. `scan` with `dynamic:true` sends HTTP requests and, if `DEPLOYREADY_TOKEN` is in the server env, runs the active scan incl. DELETE/PATCH probes with `yes:true` and no prompt. No allowlist of roots | P0/P1 (see backlog B-12) |
| T-09 | **Command injection via `openInBrowser`** (EoP) | Quote characters are stripped from the path (`src/utils/openBrowser.ts`) | `spawn(cmd, {shell:true})` with the path inside double quotes: `$(...)`, backticks and `$VAR` still expand under `sh`. Path = scanned directory + `deployready-report.html`; a directory named with a command substitution (e.g. an extracted archive) executes. Requires `--open`/shell `open`. Not reproduced (not run: would execute); reading the code is sufficient | P1 |
| T-10 | **Credential storage** | `~/.deployready/config.json` written with mode 0600 and chmod; dir created 0700 only on first creation; env keys never persisted; `config` command masks keys (`src/config/ConfigManager.ts`, `Commands.ts`) | Plaintext at rest (documented in file header and SECURITY.md). Existing directory or file with looser permissions is not repaired on read. `config.json` parsed without schema validation (`ownedTargets`, `cliCommand` trusted). `--token`, `--supabase-service-key`, `--supabase-access-token` accepted as CLI args (visible in `ps`/shell history); env var is "preferred" in help text only | P1 |
| T-11 | **npm supply chain of DeployReady** | 10 direct runtime deps; lockfile committed; CI `npm ci` + `npm audit --omit=dev --audit-level=high`; publish via npm trusted publishing (OIDC) with version/tag check; MCP SDK and zod pinned exactly (`package.json`) | 444 lockfile packages (180 non-dev) means a large transitive surface (mostly `@modelcontextprotocol/sdk`, jest excluded). `axios` is a caret range. `publish.yml` does `npm install -g npm@latest` (unpinned) and `actions/*@v4` by tag (not SHA), unlike `action.yml`. No SBOM, no `npm publish --provenance` flag in the command (the comment says provenance is generated automatically; not verified here). No dependency-review or Dependabot config found. `files` allowlist is good | P1 |
| T-12 | **GitHub Action script injection** | Inputs go through `env:` not `${{ }}` in `run:`; `fail-on` and `version` validated by case/regex; extra args word-split into an array, no shell eval; third-party actions pinned to SHAs; documented permissions (`action.yml`) | `args` input is user-supplied flags appended to the CLI (e.g. `--supabase-service-key`, `--active-url`) which is fine for a workflow author but means untrusted callers of a reusable workflow could pass flags. `npx -y deployready@latest` default: the action runs whatever is latest on npm (version input defaults to `latest`, not pinned to the action tag). `DR_PATH` is passed quoted. `actions/github-script` step `require()`s a path from `github.action_path` (trusted). Fork-PR comment failure handled. No test runs `action.yml` end to end | P1 (default version), P2 |
| T-13 | **Secret leakage in outputs** (Info disclosure) | Central `redact()` for logs/exports/AI payloads/proofs; `Finding.evidence` documented as pre-redacted; AI prompt excludes evidence | Redactor is regex-based and is a P0 area under rewrite. `redactObject` drops keys by name. SARIF/HTML/JSON all rely on redaction having run at finding creation time | P0 (in progress) |
| T-14 | **Terminal escape injection** | `sanitizeText`/`sanitizeLine` for model output (`src/utils/sanitize.ts`); `hasDangerousControl` blocks control chars in AI fixes | Repo-derived strings (file names, route paths) in the terminal presenter: not checked whether they pass through `sanitizeLine` **[unverified]** | P2 |
| T-15 | **Denial of service by hostile repo** | File size/count caps; Babel `errorRecovery`; regex rules claim bounded patterns; HTTP caps | No scan wall-clock budget or memory cap; `rules.ts` header asserts no ReDoS but no ReDoS test/fuzz exists in `tests/` (grep) | P2 |
| T-16 | **Mutation probe side effects** | See 5.3 | See 5.3 | P1 |

---

## 5. Audit findings status

### 5.1 P0 areas (being fixed on other branches)

| Area | Status |
|---|---|
| Migration-aware RLS (`src/analysis/rls.ts`) | in progress, see P0 PR |
| Authorization verdict engine + active-testing safety levels (`src/active/*`) | in progress, see P0 PR |
| CI baseline fingerprinting (`src/core/CiGate.ts` `fingerprint`: `rule:file:endpoint`, line-insensitive, so two distinct issues of one rule in one file collapse) | in progress, see P0 PR |
| Secret detection / redaction (`src/utils/redact.ts`, secret rule in `VulnerabilityDetector.ts`) | in progress, see P0 PR |

### 5.2 Additional checks performed in this audit

| # | Claim to check | Result | Evidence |
|---|---|---|---|
| A-1 | Score can be 100 with an unverified AI "critical", and the critical gate passes | **Reproduces** (by design, but misleading) | `verifyAiFindings.ts` forces every AI finding to `severity:'info'`, `unverified:true`, keeping the model's severity only in the description text. `ScoreCalculator.summarize` counts it under `unverified`, not `critical`. **[reproduced]**: `summarize([{severity:'critical', source:'ai', unverified:true}])` returns `critical:0, unverified:1`; `calculate` = **100**; `CiGate.shouldFail(summary,'critical')` = **false**. `toCiJson` then reports `passed:true`. `mcp/readiness.ts` reports `READY` for the same input. There is no state between "ready" and "not ready" for "a possible critical exists and nobody verified it" |
| A-2 | Empty or unreadable project yields a perfect result | **Reproduces** | **[reproduced]** `analyze <empty dir> --json --no-dynamic --no-ai --fail-on critical` printed `score:100`, `summary` all zero, `passed:true` (0 files, 0 routes). `assess()` would say `READY: no open findings.` No coverage field exists in `ScanReport` (`src/types.ts`) |
| A-3 | Scanner failures shown as passed | **Reproduces** (partial scans are reported as clean) | Orchestrator: dynamic exception -> `spinner.fail` then `return undefined` (`Orchestrator.ts` runDynamic); active exception -> `return []`; common-path probe exception -> `undefined`; AI failure -> original report; `supabaseStep`/`firebaseStep` catch -> warn + empty findings (`src/supabase/index.ts:206`, `src/firebase/index.ts:22`); `routeAuthChecks` catch -> silently no route-auth findings (`VulnerabilityDetector.ts:86`); `BabelAdapter.ts:481` parse failure -> empty routes, no note; `safeRead` -> `''`; walker skips unreadable dirs and over-size files silently. None of these set a field on the report; `passed`, `score`, and `READY` are computed from findings only. Mitigating: dynamic/active "no routes" and "none probeable" cases do add non-scored notes (`skippedScanNote`), and failures are printed to the terminal (not to `--json` consumers beyond stderr) |
| A-4 | Dynamic skipped (no server found) counted as success | **Reproduces** | `runDynamic` returns `undefined` when no localhost server; `toCiJson` has no `dynamic` field in that case; `passed` unaffected. GitHub Action hard-codes `--no-dynamic` so the PR summary describes a static-only scan (confirm text in `action/summary.js` states this: **[unverified]**) |
| A-5 | Mutation probe safety assumptions | **Assumptions found; two do not hold in general** | see 5.3 |
| A-6 | SSRF through repo-derived route `//host/path` | **Not reproduced** (fails closed through axios) | **[reproduced]** `EndpointMapper.unrequestable('//127.0.0.1/x')` = null; request via `createClient('http://localhost:59999').get('//127.0.0.1/x')` threw `Invalid URL`, listener on 127.0.0.1:80 received nothing. Defense is accidental; add explicit rejection |
| A-7 | `--yes`/`--json` skips the external-AI consent | **Confirmed** | `runAi`: consent prompt only `if (... && !opts.yes)`. With an API key configured, `analyze --json` sends the redacted structured report to the provider without asking. The Action passes `--no-ai`; the MCP server passes `noAi:true` |
| A-8 | Tests cover the packaged CLI / MCP stdio / OS matrix | **Not covered** | No `deployready.js` or stdio transport test; CI is one job on ubuntu-latest, Node 20 (`ci.yml`); `engines` says `>=18`; `publish.yml` tests on Node 24 once |

### 5.3 Mutation probe (`src/active/mutationProbe.ts`) assumptions

| Assumption (stated in file header) | Holds? | Why it can fail |
|---|---|---|
| A probe id `__deployready_probe_<hex>__` "cannot exist", so no real data is addressed | Partly | Param may be an action/key/slug, not an id: `PATCH /api/settings/:key` (upsert creates `__deployready_probe__`), `DELETE /api/cache/:name`, `/api/:tenant/reset`; handlers using upsert or `findOneAndUpdate({upsert:true})` create a row; soft delete or audit logging writes a record |
| No body, so nothing is written | Partly | `PATCH` with empty body may null fields or touch `updatedAt`; some handlers default missing fields |
| Loopback target means a throwaway database | No | Loopback only proves the process is local; `.env` may point at a shared/staging/production database or third-party APIs (emails, webhooks, payment calls triggered by a write) |
| 401/403 means authenticated; 2xx plus failing random-path control means "route accepted anonymous write" | Partly | A 2xx can come from a public webhook-style route or a route where the handler 200s on not-found; severity is `critical` on that evidence alone |
| PUT is skipped because it may upsert | Holds, but PATCH has the same upsert risk in many ORMs | inconsistent safety rule |
| Consent prompt describes it | Holds interactively; under `--yes`/`--json` it is auto-approved (`Orchestrator.runActive`) | no separate safety level for write probes (the P0 "active-testing safety levels" item covers this) |

---

## 6. Prioritized backlog

Conventions: **Biz** = business impact, **Sec** = security impact. Effort is not estimated (no basis in the repo). "Compat" lists compatibility risks to existing CLI/JSON/SARIF consumers. Items B-01..B-04 are the P0 areas already in flight; they are listed so the dependency graph is complete and are not re-specified.

### 6.1 P0 (in flight, from the audit)

| ID | Item | Status |
|---|---|---|
| B-01 | Migration-aware RLS | in progress, see P0 PR |
| B-02 | Authorization verdict engine + active-testing safety levels | in progress, see P0 PR |
| B-03 | CI baseline fingerprinting (line-insensitive fingerprints that distinguish instances) | in progress, see P0 PR |
| B-04 | Secret detection / redaction rewrite | in progress, see P0 PR |

### 6.2 P0 candidates found by this audit (not covered by B-01..B-04)

#### B-05 Release-state model and coverage indicators (P0)

| Field | Content |
|---|---|
| Problem | Score and `ready`/`passed` are computed from findings only (`ScoreCalculator.ts`, `CiGate.shouldFail`, `mcp/readiness.ts`). An empty directory, a scan that skipped every stage, and a scan with an unverified AI critical all read 100 / passed / READY (A-1..A-4) |
| Business impact | The headline promise ("production readiness") can be false-positive for exactly the users who trust it least critically (vibe-coders, agents) |
| Security impact | Gate bypass by silence: failing or skipped checks look like passing checks |
| Affected files | `src/types.ts` (`ScanReport`), `src/core/Orchestrator.ts`, `src/analysis/ScoreCalculator.ts`, `src/core/CiGate.ts`, `src/mcp/readiness.ts`, `src/mcp/tools.ts`, `src/ui/{IssuePresenter,HtmlReporter,Sarif,badge,ExportManager}.ts`, `action/summary.js`, `src/ai/verifyAiFindings.ts` |
| Proposed solution | (1) Add `ScanReport.coverage`: per-stage records `{stage, status: ran\|skipped\|failed\|partial, reason, counts}` for walker (files seen/read/skipped by cap, unreadable, over-size), parser (files parsed/failed, routes), static, dynamic, active, supabase, firebase, ai. Every `catch` in 5.2 A-3 writes a `failed`/`partial` record instead of dropping. (2) Add `releaseState`: `ready` / `ready-with-accepted-risks` / `review-required` / `not-ready` / `insufficient-evidence`. Rules: any scored critical -> `not-ready`; no critical but any `failed` stage, zero files scanned, or required stage skipped (per policy) -> `insufficient-evidence`; unverified AI finding whose model-suggested severity was critical, or pending notes marked review -> `review-required`; accepted risks recorded in a baseline/waiver file (with owner, reason, expiry) and nothing else open -> `ready-with-accepted-risks`; otherwise `ready`. (3) Keep numeric `score` for trend, but show it beside coverage and never print "READY" from score alone. (4) Preserve the AI-severity text as a structured field (`aiSuggestedSeverity`) instead of prose in `description`. (5) New `--fail-on` companions: `--require-coverage <stages>`, `--fail-on-insufficient` (default on in `--json`/Action) |
| Dependencies | B-03 (baseline file format reused for waivers), B-02 (stage names for active), none otherwise |
| Acceptance criteria | Empty dir returns `insufficient-evidence`, exit code distinct from `0`; injected failure in each stage (parser throw, supabase throw, dynamic throw) yields `failed` in JSON, SARIF run properties, HTML, MCP `scan`, and Action summary; an AI-only critical yields `review-required` and still not `ready`; `ready` requires `coverage.walker.read > 0`; docs list every state with exit codes |
| Regression tests | `tests/releaseState.test.ts` (state truth table); extend `tests/orchestratorFlow.test.ts` with thrown stage errors; `tests/ciGate.test.ts` for new exit semantics; snapshot of JSON schema; MCP `score` test; empty-dir case from A-2 |
| Compat risks | New exit code (e.g. 3) and new JSON keys; `passed` semantics change for empty/partial scans. Ship JSON fields additively, keep `passed` for one minor with a deprecation note, gate new exit behaviour behind `--strict` first, flip default in the next minor |

#### B-06 Treat MCP as least privilege (P0/P1 boundary, ship before wider MCP promotion)

| Field | Content |
|---|---|
| Problem | Single server mixes read tools and `apply_safe_fixes`; `path` is unconfined; `scan{dynamic:true}` sends requests and may run write probes if `DEPLOYREADY_TOKEN` is in env (T-08) |
| Business impact | Agent integrations are the growth channel; a single injected comment turning into an unconfirmed edit/probe would be a trust-ending incident |
| Security impact | Confused-deputy and prompt-injection amplifier (T-02) |
| Affected files | `src/mcp/server.ts`, `src/mcp/tools.ts`, `src/mcp/fixes.ts`, `src/mcp/supabase.ts`, `src/cli/Commands.ts` (`mcp` command), `skills/deployready/SKILL.md`, `README.md` |
| Proposed solution | Two server profiles chosen at start: `deployready mcp` = **read-only by default** (`scan` static only, `get_finding`, `verify` static, `score`, `supabase_check` static); `deployready mcp --allow-fixes` registers `apply_safe_fixes`; `--allow-dynamic` registers dynamic/active variants (separate tool names: `scan_live`, never implicit via env token); `--root <dir>` plus rejection of any `path` outside it (realpath check, reuse `FileEditor.isInside`). Mark tool annotations (`readOnlyHint`, `destructiveHint`) per MCP SDK. Fence returned file content in tool results as untrusted data and cap lines returned around the finding (not whole file) unless `full:true`. Add `dryRun` default for `apply_safe_fixes` returning the diff first |
| Dependencies | none (can land before B-05); B-05 for coverage in tool output |
| Acceptance criteria | Default server lists no modifying tool (verified by listing tools over a real stdio transport); path outside root returns an error; `apply_safe_fixes` absent without flag; destructive tools carry annotations; SKILL.md updated; old behaviour available via `--allow-fixes --allow-dynamic` |
| Regression tests | New `tests/mcp-stdio.test.ts` spawning `bin/deployready.js mcp` with the SDK client; path-escape tests incl. symlink; tool-list snapshot per profile |
| Compat risks | Existing agent configs that call `apply_safe_fixes` break until `--allow-fixes` is added; document in CHANGELOG, consider one release where the old tool returns a message naming the flag instead of "unknown tool" |

#### B-07 Mutation-probe containment (P1, depends on B-02)

| Field | Content |
|---|---|
| Problem | Section 5.3: assumptions fail for upsert/action-style params and non-throwaway databases; auto-approved by `--yes` |
| Business impact | A scan that writes into a developer's shared database is a reputational risk |
| Security impact | Integrity/availability of the target |
| Affected files | `src/active/mutationProbe.ts`, `src/core/Orchestrator.ts` (`runActive`), `src/cli/Commands.ts` |
| Proposed solution | Fold into B-02 safety levels: level 0 read-only, level 1 identity tampering (GET), level 2 write probes only with explicit `--allow-write-probes` (never implied by `--yes`/`--json`), refuse when `.env`/config points the app at a non-local database host (detect obvious `DATABASE_URL`/Supabase URL host), skip routes whose param name is not id-like (`id`, `uuid`, `*Id`), also skip PATCH where upsert is plausible, print the exact request list before sending |
| Dependencies | B-02 |
| Acceptance criteria | `--yes` alone never sends DELETE/PATCH; non-id param routes skipped with reason; probe list printed; JSON records `activeLevel` |
| Regression tests | extend `tests/active-runner.test.ts`, `active-requestPlan.test.ts`; new case with `PATCH /settings/:key` fixture |
| Compat risks | Existing users of `unauthenticated-mutation` must add a flag; finding rule id unchanged |

### 6.3 P1

| ID | Item | Priority |
|---|---|---|
| B-08 | Dependency CVE detection (OSV) | P1 |
| B-09 | Adapter architecture for external scanners | P1 |
| B-10 | Stripe / payment checks | P1 |
| B-11 | AI-app security checks | P1 |
| B-12 | Guided modes (Quick / Deep / Continuous) | P1 |
| B-13 | Role/permission matrix testing | P1 |
| B-14 | `openInBrowser` shell removal and CLI secret-arg hardening | P1 |
| B-15 | Walker/parse coverage reporting (feeds B-05) | P1 (part of B-05 work) |
| B-16 | Benchmark holdout and rerun-all-competitors rule | P1 |
| B-17 | E2E validation matrix (OS x Node) and packaged-CLI tests | P1 |
| B-18 | Supply-chain hardening of DeployReady itself | P1 |
| B-19 | Firebase emulator-backed rules testing | P2 |
| B-20 | IaC / Docker / deploy config checks | P2 |
| B-21 | Parser expansion (Django, Laravel, more PHP/Go/Ruby) | P2 |
| B-22 | HTML report CSP and atomic fixer writes | P2 |

#### B-08 Dependency CVE detection (P1)

| Field | Content |
|---|---|
| Problem | No vulnerable-component detection (matrix A03, CWE-1104 missing). `package.json`, `requirements.txt`, `composer.json` are walked as "extra files" but only used for stack detection (`FileWalker.ts`, `StackDetector.ts`) |
| Business impact | Most real "is my app safe" questions include known-vulnerable packages; competitors cover it |
| Security impact | Known exploitable dependencies unreported |
| Affected files | new `src/supply/{lockfiles,osv}.ts`, `src/core/Orchestrator.ts`, `src/types.ts`, `src/utils/FileWalker.ts` (add lockfiles to EXTRA_FILES), SARIF mapping |
| Proposed solution | Parse `package-lock.json` (v1-3), `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`/`poetry.lock`, `composer.lock` locally into `{ecosystem,name,version}`. Query OSV (`https://api.osv.dev/v1/querybatch`) only after consent, sending package name+version only (no paths). Offline mode: accept a pre-downloaded OSV-Scanner JSON (B-09). Map OSV severity (CVSS) to finding severity, mark `source:'static'` with `rule:'vulnerable-dependency'`, `cwe` from advisory when present, include fix version. Reachability is **not** claimed: label "installed version is affected" |
| Dependencies | B-05 (network-failure must produce `failed`, not clean); B-09 for adapter packaging |
| Acceptance criteria | Fixture lockfile with a known-vulnerable pinned version yields a finding offline using a recorded OSV response; network failure yields `coverage.dependencies=failed` and `insufficient-evidence`; no source paths in the request body (test asserts payload) |
| Regression tests | `tests/supply-lockfiles.test.ts`, `tests/supply-osv.test.ts` (mock transport + recorded fixtures), benchmark cases with `-tp`/`-tn` lockfiles |
| Compat risks | New egress host `api.osv.dev` (update SECURITY.md "What leaves your machine"); new findings change scores/gates for existing users, so ship behind `--deps` first with baseline guidance |

#### B-09 Adapter architecture for external scanners (P1)

| Field | Content |
|---|---|
| Problem | All detection is bespoke regex/Babel. Mature tools exist for secrets, SAST, dependencies, containers, SBOM, DAST. There is no way to run them and normalize results; also no coverage for languages beyond JS/TS/Python |
| Business impact | Closes capability gaps faster than writing rules; credible "uses best-in-class engines" story |
| Security impact | More coverage; but each adapter is a new child-process and supply-chain surface |
| Affected files | new `src/adapters/{Adapter.ts,registry.ts,gitleaks.ts,osv.ts,semgrep.ts,trivy.ts,syft.ts,zap.ts}`, `src/core/Orchestrator.ts`, `src/ai/cli/runCli.ts` (reuse sandboxed spawn pattern), `src/types.ts` |
| Proposed solution | Interface: `detect(): {available, version}`, `plan(ctx): {argv, stdin?, timeout, outputFormat}`, `parse(raw): NormalizedFinding[]`, declared `egress` and `writes` capabilities. Run through a shared hardened runner derived from `runCli.ts` (shell:false, argv constants, scrubbed env, cwd = project read-only where possible, output cap, timeout, tree-kill). Adapters are **opt-in, user-installed binaries**: DeployReady never downloads or bundles them. Findings carry `source:'adapter:<name>'` and `engineVersion`; failure -> `coverage` entry (B-05). Dedup against native findings in `IssueAggregator`. Order of adoption: Gitleaks, OSV-Scanner, Semgrep CE, Trivy (fs/config), Syft (SBOM only), ZAP (baseline scan, loopback/owned only, B-02 safety levels), Firebase emulator (B-19) |
| Dependencies | B-05, B-02 (for ZAP), B-04 (secret normalization, dedupe against Gitleaks) |
| Acceptance criteria | Missing binary yields `skipped` with install hint, not a failure; each adapter has a recorded-output fixture test; argv snapshot tests per adapter; no adapter can receive a user-controlled argument except the project path; license notice printed by `deployready adapters list` |
| Regression tests | `tests/adapters-*.test.ts` with fake executables (pattern: `tests/helpers/fakeCli.ts`), parse tests on recorded outputs, dedupe tests |
| Compat risks | New optional surface only; new `source` values must be handled by SARIF/HTML/JSON consumers (`FindingSource` is a closed union in `src/types.ts`, currently `static`/`dynamic`/`ai`) |

Adapter license notes (**all [unverified] in this session unless stated**; confirm against each project's LICENSE at the pinned version before shipping or bundling anything):

| Tool | License (from memory) | Note for DeployReady |
|---|---|---|
| OSV-Scanner | Apache-2.0 | OK to invoke; data licensed by OSV sources (various, mostly CC-BY 4.0/CC0) **[unverified]** |
| Gitleaks | MIT | OK to invoke. Note: the npm package named `gitleaks` is a different project (`npm view gitleaks license` = ISC, run in this audit); install the real binary from the Gitleaks releases/package managers, not that npm package |
| Semgrep CE (engine) | LGPL-2.1 | Invoking a user-installed binary is fine. The **community rules** are under the Semgrep Rules License (restricts use in a competing commercial service) **[unverified]**: do not bundle or redistribute rules in a hosted Pro offering without legal review. `benchmark/COMPARISON.md` already used the rules repo for a local comparison only. `npm view semgrep license` returned ISC, which is an unrelated npm package, not the Semgrep tool |
| Trivy | Apache-2.0 | OK to invoke; vulnerability DB distribution terms differ **[unverified]** |
| Syft | Apache-2.0 | OK |
| OWASP ZAP | Apache-2.0 | OK; active scanning is high-risk, gate behind B-02 level and ownership attestation |
| Firebase emulator suite (`firebase-tools`) | `npm view firebase-tools license` = MIT (run in this audit); emulator jars/UI may carry separate Google terms **[unverified]** | Treat as user-installed |

#### B-10 Stripe / payment checks (P1)

| Field | Content |
|---|---|
| Problem | Nothing beyond the Stripe key shape in `redact.ts` |
| Business impact | Payments are a top reason indie apps get hurt; high-value claim |
| Security impact | Revenue loss, fraud, refund abuse |
| Affected files | `src/analysis/rules.ts` (or new `src/payments/*`), `VulnerabilityDetector.ts`, benchmark corpus |
| Proposed solution | Static, framework-aware rules: webhook handler with no `constructEvent`/signature verification or using parsed JSON body; amount/price taken from request body into `paymentIntents.create`/`checkout.sessions.create`; `sk_live_`/`rk_live_` in source or `NEXT_PUBLIC_*`; `success_url` built from unvalidated request origin; missing idempotency keys on create calls (info); entitlement granted from the client redirect rather than a webhook; Stripe secret in client bundle paths. Each finding states the exact CWE (CWE-345 for unsigned webhooks, CWE-639/602 for client-trusted price). Optional later: Paddle/LemonSqueezy equivalents |
| Dependencies | B-04 (key shapes) |
| Acceptance criteria | Benchmark corpus `payments/*-tp|-tn` with at least: Express and Next route webhook with/without signature check, price-from-body vs server price lookup; precision/recall printed by `benchmark/run.ts`; no network calls |
| Regression tests | `tests/payments-rules.test.ts`, corpus cases |
| Compat risks | New rule ids; raising FP rate on test-mode keys (`sk_test_` should be warning/info) |

#### B-11 AI-app security checks (P1)

| Field | Content |
|---|---|
| Problem | Vibe-coded apps are mostly LLM apps; nothing detects prompt injection exposure, over-privileged agent tools, or LLM key handling |
| Business impact | Differentiator aligned with the product's audience |
| Security impact | Data exfiltration, tool abuse, cost abuse |
| Affected files | new `src/aiapp/*` rules, `rules.ts`, `src/parser/*` (identify SDK imports: `openai`, `@anthropic-ai/sdk`, `ai`, `langchain`, `@modelcontextprotocol/sdk`), corpus |
| Proposed solution | Static rules: LLM provider key referenced from client code or `NEXT_PUBLIC_`/`VITE_` env; user input concatenated/templated into system prompt; model output passed to `eval`, `exec`, `dangerouslySetInnerHTML`, SQL, or `fetch` of model-chosen URL; agent tools that expose shell/file-write/network without allowlist or confirmation; MCP server code with unconfined `path` args (mirrors B-06); no max-tokens/rate limit/auth on a route that calls a paid model (cost abuse, ties to `missing-rate-limit`); RAG retrieval without tenant filter. All findings default to warning unless the sink is code execution. Never use AI to decide these |
| Dependencies | none; B-04 for key detection |
| Acceptance criteria | Corpus `aiapp/*` with tp/tn pairs; each rule documents its limits; report section "AI-app" in JSON/HTML |
| Regression tests | `tests/aiapp-rules.test.ts`, corpus |
| Compat risks | FP risk on prompt templates (strict mode tn cases required); new category value would extend `Category` union, additive |

#### B-12 Guided modes: Quick / Deep / Continuous (P1)

| Field | Content |
|---|---|
| Problem | 20+ flags; the safe combination is not obvious; the Action only does static |
| Business impact | Onboarding and CI adoption |
| Security impact | Reduces misuse of active flags; makes coverage explicit |
| Affected files | `src/cli/Commands.ts`, `Orchestrator.ts`, `action.yml`, docs |
| Proposed solution | `--mode quick` (static, no network, seconds, B-05 coverage printed); `--mode deep` (static + adapters + dynamic + active level 1 with explicit prompts, never write probes by default); `--mode continuous` (CI preset: static + deps + baseline + SARIF, fails on `insufficient-evidence`, optional scheduled deep run against a preview URL with owned-host attestation). Each mode prints what it will and will not do before running |
| Dependencies | B-05, B-02, B-08, B-09 |
| Acceptance criteria | Mode table in docs matches `--help`; modes never enable a stage the user did not consent to; Action input `mode` |
| Regression tests | `tests/modes.test.ts` asserting the resolved option set per mode |
| Compat risks | Defaults unchanged when `--mode` absent |

#### B-13 Role/permission matrix testing (P1)

| Field | Content |
|---|---|
| Problem | Active scan uses at most two tokens and infers checks from JWT claims (`requestPlan.ts`, `tamper.ts`); no explicit roles x routes expectations |
| Business impact | "Can a normal user reach admin routes / another tenant's data" is the most valuable live question |
| Security impact | Broken access control is OWASP A01 |
| Affected files | `src/active/*` (extend), new config `deployready.roles.json`, `src/core/Orchestrator.ts` |
| Proposed solution | User supplies roles and tokens (env only) and an expectation matrix (route pattern x role -> allow/deny/own-only); verdicts from the B-02 authorization verdict engine; GET-only unless level 2. Generate a starter matrix from discovered routes and guard names, to be reviewed by the user |
| Dependencies | B-02 |
| Acceptance criteria | Fixture app with admin/user/anon; matrix violations reported with proof; unexecuted cells listed as not tested (coverage) |
| Regression tests | `tests/active-matrix.test.ts` using `tests/helpers/dummyApp.ts` |
| Compat risks | New optional file only |

#### B-14 `openInBrowser` and secret-in-argv hardening (P1)

| Field | Content |
|---|---|
| Problem | T-09 shell expansion; T-10 secrets accepted on the command line |
| Business impact | Small, but a shell-injection finding in a security tool is embarrassing |
| Security impact | Local command execution via crafted directory name |
| Affected files | `src/utils/openBrowser.ts`, `src/cli/Commands.ts`, `README.md` |
| Proposed solution | Replace with `spawn('xdg-open', [file], {shell:false})`, `spawn('open', [file])`, and on Windows `spawn('cmd', ['/c','start','',file])` with the same arg allowlist used in `runCli.ts`, or `explorer.exe`; mark `--token`, `--supabase-service-key`, `--supabase-access-token` as discouraged and add `--token-env <NAME>` / read `DEPLOYREADY_TOKEN` already used by MCP |
| Dependencies | none |
| Acceptance criteria | Test creates a dir named `a$(touch pwned)b`, calls the opener with a stubbed `spawn`, asserts no shell and argv contains the literal path |
| Regression tests | `tests/openBrowser.test.ts` |
| Compat risks | None visible |

#### B-16 Benchmark holdout and rerun-all-competitors rule (P1)

| Field | Content |
|---|---|
| Problem | `benchmark/` labels and rules were developed together (`corpus/vibe` is both tuning set and reporting set; `benchmark/BASELINE.md` lists `knownGap` cases tied to audit items). `COMPARISON.md` says its saved Semgrep/LLM outputs "predate" a DeployReady rule change and "were not re-run" while the DeployReady column was updated. LLM baseline is one run on one small model. Semgrep ran with the community rules checkout, not `p/default` |
| Business impact | Any marketing claim built on these tables is not defensible as is |
| Security impact | Overfitting rules to a public corpus hides real misses |
| Affected files | `benchmark/*`, `benchmark/compare.ts`, CI |
| Proposed solution | (1) Split corpus: `tune/` (visible, used for development) and `holdout/` (cases authored by someone other than the rule author, committed as a hash manifest, contents revealed only by the release job; rotate each release). (2) Rule: whenever any tool's version, rule set, or the corpus changes, **rerun every competitor and DeployReady in the same job and write one results file with versions, commit hashes, command lines, and raw outputs**; CI fails if a published table references raw outputs older than the corpus hash. (3) Report FP/FN per issue class with counts, confidence intervals where n permits, and multiple LLM runs with variance. (4) Include tools the directive names (Semgrep with `p/default` if reachable, Gitleaks, OSV-Scanner, Trivy) once adapters exist. (5) No claims in README beyond what the committed results file shows |
| Dependencies | B-09 |
| Acceptance criteria | `npm run benchmark:compare` regenerates the table from a single manifest; CI check that table hash == results hash; holdout manifest verified |
| Regression tests | script-level tests for manifest/hash check; existing `benchmark/run.ts` exit-code behaviour kept |
| Compat risks | Existing README/CHANGELOG numbers (precision 0.88->0.96, recall 0.85->0.94, 133 cases, from `CHANGELOG.md`) must be re-derived or removed |

#### B-17 E2E validation matrix (P1)

| Field | Content |
|---|---|
| Problem | One OS, one Node version in CI; no packaged-CLI or stdio tests (A-8) |
| Business impact | Windows and Node 18/22/24 users are untested; `engines >=18` is a promise |
| Security impact | Windows `.cmd` shim handling in `runCli.ts` is only tested with fakes |
| Affected files | `.github/workflows/ci.yml`, new `tests/e2e/*` |
| Proposed solution | See section 8.2 matrix. Add `npm pack` then install the tarball in a temp dir and run `deployready analyze` against fixtures (`tests/sample-app`, `tests/guarded-app`, `tests/python-app`), run `deployready mcp` with the SDK client, run `action.yml` in a self-test workflow (`uses: ./`) |
| Dependencies | B-06 for MCP e2e |
| Acceptance criteria | Matrix green on ubuntu/macos/windows x Node 18/20/22/24 (Node 18 reached end of life; keep only if `engines` still says >=18 **[verify]**) |
| Regression tests | the e2e suite itself |
| Compat risks | Windows path/line-ending failures will surface existing bugs |

#### B-18 Supply-chain hardening of DeployReady itself (P1)

| Field | Content |
|---|---|
| Problem | T-11, T-12 |
| Affected files | `.github/workflows/*.yml`, `action.yml`, `package.json`, new `.github/dependabot.yml` |
| Proposed solution | Pin `actions/checkout`, `setup-node` in workflows by SHA like `action.yml` does; pin npm version used for publish; add Dependabot for npm + actions; `npm publish --provenance` explicitly; generate and attach an SBOM (CycloneDX) to releases; Action `version` default = the action's own tag (resolve from `github.action_ref`) instead of `latest`; enable `npm ci --ignore-scripts` where possible in CI (check that no dependency needs install scripts); document verification (`npm audit signatures`) |
| Business / Security impact | Credibility of a security tool; protects the OIDC publish path |
| Dependencies | none |
| Acceptance criteria | `npm audit signatures` passes on a fresh install of the published tarball; workflows contain no tag-only third-party refs; Action pinned default documented |
| Regression tests | workflow lint in CI (e.g. a script asserting `uses:` lines are SHA-pinned) |
| Compat risks | Action users relying on `latest` get the matching version instead |

### 6.4 P2 summary rows

| ID | Problem | Files | Solution | Acceptance | Tests | Compat |
|---|---|---|---|---|---|---|
| B-19 | Firebase is static-only | `src/firebase/*`, `docs/FIREBASE.md` | Run user's Firebase emulator + `@firebase/rules-unit-testing` style assertions as an adapter with explicit user-supplied cases; add App Check, Functions auth, Storage rules checks | Emulator-backed tests flag an open rule that static parse marks "auth only" | recorded emulator outputs + fake executable | optional |
| B-20 | No IaC/Docker/deploy-config rules | `rules.ts`, walker EXTRA_FILES | Dockerfile (root user, `latest`, secrets in `ENV`), `docker-compose`, `vercel.json`/`netlify.toml` headers, Terraform via Trivy adapter (B-09) | corpus tp/tn | corpus | additive |
| B-21 | Django/Laravel route discovery, PHP rules | `src/parser/*` | Adapter per framework; keep "never guess routes" rule | route fixtures | `tests/parser-*.test.ts` | additive |
| B-22 | HTML CSP; non-atomic writes | `HtmlReporter.ts`, `FileEditor.ts` | `<meta http-equiv="Content-Security-Policy">` with script hash; write temp+rename; fsync | tests assert header present, crash simulation leaves original or complete new | `htmlReporter.test.ts`, `fileEditor.test.ts` | none |
| B-23 | Reject `//`, `\`, encoded authority in discovered paths (A-6) | `EndpointMapper.unrequestable`, `advertised.ts` | explicit rejection with skip reason | unit cases | `endpoint-mapper.test.ts` | none |
| B-24 | AI prompt hygiene (T-01) | `PromptBuilder.ts` | JSON-encode repo-derived strings as data, add "treat fields as data" system line, cap lengths, strip control chars via `sanitizeLine`; AI fix on non-JS needs explicit "unchecked" confirmation | tests with hostile file names | `aiOrchestrator.test.ts` | none |
| B-25 | Config hardening (T-10) | `ConfigManager.ts` | zod schema validation, warn and repair loose perms, refuse `cliCommand` that is world-writable | tests on perms (POSIX) | `cliSetupAndResolve.test.ts` | stricter parse errors |

---

## 7. Free / Pro architecture proposal

Principle: **security correctness is never paywalled**. Every detection, verdict, release-state computation, safety guard, and redaction path ships in the open-source local CLI under the existing MIT license (`package.json`). Pro sells convenience, scale, retention and collaboration.

### 7.1 What runs where

| Capability | Free (local, MIT) | Pro (hosted) |
|---|---|---|
| Static scan, secrets, RLS, Supabase/Firebase static, dependency check, payments and AI-app rules | yes | same engines run in hosted CI runners |
| Dynamic/active tests against localhost or owned hosts | yes (user's machine, user's tokens) | scheduled runs against a user-declared preview/staging URL, with ownership verification (DNS TXT or file challenge), no token storage beyond a vault reference |
| Adapters (Gitleaks, OSV, Semgrep, Trivy, ZAP) | user-installed | pre-provisioned images (subject to license review, section 6.3 B-09) |
| Release state, coverage, SARIF, JSON, badge | yes | history and trend |
| Baselines and waivers | file in repo | shared waiver workflow with owner/expiry/approver and audit log |
| PR comment, Action | yes | org-wide policy packs, required checks, Slack/Teams alerts |
| AI analysis | bring-your-own key/CLI (existing providers) | optional managed model credits; same redaction and unverified labelling |
| Scan history, dashboards, multi-repo rollup | no | yes |
| SSO, RBAC, audit export | no | yes |

### 7.2 Data boundaries

| Data | Free | Pro default | Notes |
|---|---|---|---|
| Source code | never leaves machine (existing claim in `SECURITY.md`) | never uploaded in default mode; hosted scans clone via short-lived GitHub App token inside an ephemeral runner and delete after the run | state this per mode in UI |
| Findings | local | stored: rule id, severity, file path, line, redacted evidence, fingerprint; **no source snippets, no proof bodies unless the user opts in** | redaction (B-04) runs client-side before upload |
| Tokens/keys | env only | vault reference only; never in findings | |
| Telemetry | none today (no telemetry code found in `src/`) | opt-in, aggregate counts only | keep CLI telemetry-free by default |

### 7.3 Rough infra cost model (ESTIMATES, assumptions explicit, not measured)

I have no measurements of DeployReady scan time, memory, or storage in this repo. The figures below are placeholders to be replaced after profiling (B-17/benchmark job should record wall time and RSS). Cloud prices are rounded planning values from memory and **[unverified]**.

| Assumption | Value (estimate) |
|---|---|
| Avg hosted scan (static + deps) | 60 s on 1 vCPU / 1 GB runner |
| Deep scan with adapters | 5 min on 2 vCPU / 4 GB |
| Runner cost | ~$0.04 per vCPU-hour spot-equivalent, ~$0.005 per GB-hour |
| Stored per scan | ~50 KB findings JSON + 100 KB SARIF |
| Scans per active Pro repo per month | 150 quick, 10 deep |

| Line | Formula | Per repo / month |
|---|---|---|
| Quick scans | 150 x 60 s = 2.5 h x (1 vCPU x 0.04 + 1 GB x 0.005) | ~$0.11 |
| Deep scans | 10 x 300 s = 0.83 h x (2 x 0.04 + 4 x 0.005) | ~$0.08 |
| Storage | 160 x 150 KB = 24 MB | <$0.01 |
| Egress / OSV / DB queries | small, assume $0.05 | ~$0.05 |
| Control plane (API, DB, auth) | fixed, assume $100-300/month shared | amortized |
| Total variable | | ~$0.25 per repo per month |

Interpretation: variable cost is small under these assumptions; the dominant costs are fixed infrastructure, support, abuse prevention for DAST against third-party targets (ownership verification, rate limits) and any managed LLM credits (not modelled; depends on provider pricing, which I did not look up). Revisit after profiling.

---

## 8. Testing and release strategy

All gate values are **targets to adopt, not claims about the current state**. Current measured state: 83 suites / 1309 tests passing; coverage floor in `jest.config.js` is statements 78 / branches 69 / functions 82 / lines 80; `docs/COVERAGE.md` records 86.56 / 78.07 / 91.00 / 88.95 measured for 0.3.0 (not re-measured for 0.4.0 in this audit).

### 8.1 Quality gates (targets)

| Gate | Target | Where enforced |
|---|---|---|
| Type check + tests | green on full matrix | `ci.yml` |
| Coverage | no drop; raise floors toward measured values; security-critical modules (`redact`, `FileEditor`, `FileWalker`, `scope`, `httpAdapter`, `runCli`, `rls`, `CiGate`) at >= 90% lines (target) | jest `coverageThreshold` per path |
| Benchmark | tuning corpus: no regressions per rule; holdout: reported, not gating until baselined; FP on `-tn` cases = 0 for `strict` cases | `benchmark/run.ts` + B-16 |
| Release-state truth table | 100% of states covered | `tests/releaseState.test.ts` |
| Fail-closed tests | every scan stage has a "throws" test showing `failed` coverage and non-ready state | B-05 |
| Safety tests | probes never send to non-loopback/non-owned hosts, never send write methods below level 2, never exceed request caps | `active-*`, `common-path-probe-*` suites |
| Packaged e2e | `npm pack` tarball analyze + MCP stdio on all matrix cells | B-17 |
| Supply chain | `npm audit --omit=dev --audit-level=high`, `npm audit signatures`, SHA-pinned workflow actions, SBOM attached | B-18 |
| Docs truth | every flag in `Commands.ts` appears in README and every README claim maps to a test or is labelled | script check |
| Secret hygiene | gitleaks (adapter) on the repo itself in CI | B-09 |
| Fuzz/ReDoS | rule regexes run against adversarial 4 000-char lines with a time budget | new `tests/redos.test.ts` |

### 8.2 E2E validation matrix (target)

| Axis | Values |
|---|---|
| OS | ubuntu-latest, macos-latest, windows-latest |
| Node | 20, 22, 24 required; 18 only while `engines` allows it |
| Scenarios per cell | (1) packaged CLI static scan of `tests/sample-app` (expect findings + exit 2 with `--fail-on critical`); (2) empty dir -> `insufficient-evidence`; (3) dynamic scan against bundled dummy app on loopback; (4) MCP stdio: list tools, call `scan`, assert read-only profile; (5) SARIF uploaded schema validation; (6) `--open` path with a hostile dir name using a stubbed opener; (7) Windows: fake `.cmd` CLI shim through `runCli` |
| Not in matrix | real `claude`/`codex` logins (manual pre-release checklist), real Supabase/Firebase projects (nightly job with dedicated sandbox projects, secrets in OIDC-gated environment) |

### 8.3 Release process

| Step | Content |
|---|---|
| Versioning | semver; JSON/SARIF additions are minor; changed exit semantics need a `--strict` bridge release (see B-05) |
| Pre-release | publish `-beta` on `beta` dist-tag (already supported by `publish.yml`), run holdout benchmark, run full matrix, manual real-CLI checklist |
| Release | trusted publishing with explicit provenance (B-18), SBOM, changelog entry listing every behaviour change, docs update, Action tag + `@v<major>` move |
| Post-release | canary scan of three known repos, watch issue tracker; rollback = `npm deprecate` + dist-tag move |
| Claims policy | README/website numbers must link to a committed results file generated by the B-16 pipeline at the release commit; otherwise removed |

### 8.4 Suggested sequencing

1. B-01..B-04 (in flight) -> merge.
2. B-05 (release state + coverage), B-06 (MCP least privilege), B-14 (small fix).
3. B-07 after B-02; B-17 matrix in parallel; B-18.
4. B-08 (deps), B-09 (adapter runner + Gitleaks/OSV first), B-16 (benchmark discipline) before any public comparison claims.
5. B-10, B-11, B-12, B-13; then P2.

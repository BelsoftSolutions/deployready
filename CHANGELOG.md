# Changelog

## 0.5.0

This release fixes the problems found by an independent security audit of 0.4.0. Every audit finding was reproduced against the 0.4.0 code first and is now a regression test. Two of them affected DeployReady's own privacy and CI guarantees, so please upgrade.

### Security fixes in DeployReady itself
- **Secret redaction (privacy).** In 0.4.0 some credential formats could reach reports, AI prompts or MCP output unredacted: passwords inside raw JSON text, Supabase `sb_secret_` keys, GitHub fine-grained tokens (`github_pat_`), multi-line private keys, and passwords that merely start with words like "test" or "demo". Detection and redaction are now separate, many more formats are covered, and canary tests push a fake key of every type through every output channel (terminal, JSON, markdown, HTML, SARIF, fix prompts, MCP, AI prompts, logs, proof) and fail if any leaks.
- **CI baseline could let a new issue through.** A second secret in a file that already had an accepted one, or a warning escalating to critical, passed the baseline gate. Baselines (v2) now use move-stable, collision-resistant fingerprints that never contain secret values, track severity separately, and report new, escalated, reopened, expired and stale entries. v1 baselines still load with a migration warning.
- **MCP paths were not confined.** A tool call could scan or modify any directory, e.g. `apply_safe_fixes` with a path outside the project. Every path is now resolved (symlinks included) and must stay inside the server root.
- **`--yes` / `--json` sent data to external AI without consent.** External AI now needs an interactive yes, `--allow-external-ai`, or `"allowExternalAi": true`.
- **Opening the HTML report went through a shell**, so a project path containing `$(...)` could run commands. Reports now open without a shell.
- An AI-proposed fix can no longer write the `«REDACTED»` placeholder into your file in place of the real value.

### Accuracy fixes
- **Supabase RLS** is now migration-aware: migrations are replayed in order and only the final database state is judged (schemas, quoted names, renames, unlogged tables, ENABLE/DISABLE/FORCE, CREATE/ALTER/DROP POLICY, grants, always-true conditions such as `1=1`). On a reconstruction of the audit's 16 cases, 0.4.0 caught 1 of 10 insecure setups; 0.5.0 handles all 16, plus 22 more variations, with labels confirmed on a real PostgreSQL 16. Data sensitivity and `.deployready.json` settings (`publicTables`, `sensitiveTables`, `tenantColumns`, `exposedSchemas`) decide whether open reads are critical, need review, or are intended.
- **Authorization (IDOR) verdicts** compare responses field by field instead of whole bodies: changing timestamps or request ids no longer hide a leak, partial leaks are caught, a 404 that still contains another user's data is a finding, and an endpoint that merely echoes the requested id is no longer a false alarm. Verdicts: confirmed, suspected, verified-denied, inconclusive.

### Release state and coverage
- Every report now has a **release state** (ready, ready with accepted risks, review required, not ready, insufficient evidence) and **coverage per area** (passed, failed, untested, inconclusive, not applicable, each with a reason), separate from the score. A scanner step that errors can no longer look like a pass, an unverified AI critical can no longer hide behind 100/100, and an empty or unsupported project is "insufficient evidence", not "passed".
- `--fail-on-release-state <state>` gates on it (exit code 3 for insufficient evidence). Existing `--fail-on` behaviour and exit codes are unchanged.

### Safer active testing
- Safety levels: passive, read-only (default), controlled-active and stateful (only for environments you declare disposable). The DELETE/PATCH probe is now **off by default** (controlled-active).
- Request budget (200 by default), no cross-host redirects, side-effect-looking GET routes skipped, and `--dry-run` to preview planned requests.

### New: dependency vulnerabilities and engine adapters
- Dependency CVEs via npm/pnpm audit, plus OSV-Scanner and pip-audit when installed. Optional Gitleaks and Semgrep (opt-in, metrics off). Engines that fail show as coverage errors, never as clean results.
- Dependency checks contact the package registry with dependency names and versions (never source code) and say so every time; `--offline` skips them.

### Breaking: MCP server is least-privilege by default
- `deployready mcp` now registers only read-only, static tools: `scan`, `get_finding`, `verify` (static re-check), `score`, `supabase_check` (static).
- `apply_safe_fixes` needs `deployready mcp --allow-fixes` (e.g. `claude mcp add deployready -- npx -y deployready@latest mcp --allow-fixes`). Calling it without the flag returns an error naming the flag.
- Live checks need `--allow-live`: new `scan_live` and `supabase_check_live` tools; `scan(dynamic: true)` and `supabase_check(live: true)` are refused without the flag; `verify` only re-checks live findings with it.
- Every `path` argument is confined to the server root (realpath; `..`, other absolute paths and symlink escapes are refused). Previously a tool call could scan or modify any directory.
- Tool results carry `schemaVersion: 1` and a `dataNotice`; `get_finding` moved the file text from `file_content` to `untrusted_repository_content.file_content`, fenced by BEGIN/END markers. Tools carry `readOnlyHint` / `destructiveHint` annotations.

### Breaking: external AI consent
- `--yes` / `--json` no longer approve sending the redacted report to an external AI provider (API or claude/codex CLI). Use `--allow-external-ai` or `"allowExternalAi": true`; otherwise non-interactive runs skip AI and record it as untested coverage. `warnBeforeExternalSend: false` no longer skips the interactive prompt. Ollama needs no consent.

## 0.4.0

### Agent loop (MCP)
- New `deployready mcp`: a local MCP server for Claude Code, Cursor, Codex and Windsurf with `scan`, `get_finding`, `apply_safe_fixes`, `verify`, `score` and `supabase_check`. Your coding agent fixes, DeployReady verifies.
- Claude Code skill in `skills/deployready/SKILL.md`.

### Fix faster
- `fix --all` in the interactive shell and `analyze --fix` for CI/scripts: every safe deterministic fix in one pass, each re-verified.
- Backups now go to `.deployready/backups/` (gitignored) instead of next to your files.

### Proof, not guesses
- Live and active findings carry reproducible proof: a redacted curl request, status, response excerpt and a control request. Shown in the terminal, `show`, markdown, HTML and JSON.
- Proof on every live finding, including slow endpoints, cache headers, version banners and stack-trace leaks.
- `verify` from the shell and the MCP server reads `DEPLOYREADY_TOKEN` / `DEPLOYREADY_TOKEN_B`, so an agent can confirm live fixes too.
- `verify` returns `fixed`, `still-present` or `inconclusive`. A live finding only counts as fixed when the attack fails and a control request still works. (Before, verifying an active finding always reported fixed.)
- Safe detection of unauthenticated DELETE/PATCH routes on localhost (non-existent record id, no body, random-path control).
- Ownership guard: active probes only target localhost unless you pass `--active-url` with `--i-own-this-target <host>` (or `ownedTargets` in config).

### GitHub Action and SARIF
- `uses: BelsoftSolutions/deployready@v0.4.0`: scans every PR, writes a job summary, keeps one updated PR comment, uploads the report, and fails the build at your `fail-on` level. Third-party actions are pinned to commit SHAs; inputs never reach shell scripts directly. See docs/GITHUB-ACTION.md.
- `analyze --sarif <file>` writes SARIF 2.1.0, so findings show in GitHub's Security tab.

### Firebase
- Static checks of `firestore.rules`, `storage.rules` and Realtime Database rules: open rules, test-mode rules with an expiry date, "signed in is enough" rules on user-owned paths, recursive wildcards. Committed service-account keys are critical. The public web `apiKey` is (correctly) not flagged. See docs/FIREBASE.md.

### Supabase
- Static: service_role keys in client-side code or public env vars are critical.
- Live (`--supabase`), read-only and counts-only, only for a local project or one you prove you own (service key or access token): tables readable by anon, anon-callable RPC functions, public buckets, sign-up settings, and opt-in two-user cross-read. See docs/SUPABASE.md.

### Accuracy
- Static IDOR detection (`idor-missing-ownership-check`): handlers that load, update or delete a record by id from the request with no ownership or tenant check. Confirm with the live two-user test.
- New rules: hardcoded JWT signing secrets (critical), Flask `SECRET_KEY` literals, secrets in `NEXT_PUBLIC_`/`VITE_` variables, routes that change data or expose /admin with no auth check.
- RLS checks now fire when a Supabase project never enables RLS, and flag tables with RLS but no policy and `using (true)` policies.
- `.env` is critical only when it is tracked or in git history; an untracked, un-ignored `.env` is a warning.
- Fewer false positives on parameterized queries, header-derived tokens, comparisons and server-only Supabase modules.
- New labelled benchmark (133 cases: vibe-coded apps, IDOR, Firebase): precision 0.88 -> 0.96, recall 0.85 -> 0.94 on supported rules. Comparison with Semgrep and a plain LLM in benchmark/COMPARISON.md.
- `deployready badge` prints a README score badge; every finding has a copy-paste fix prompt for your coding agent.

### Security
- `follow-redirects` updated past a high-severity advisory.

## 0.3.0

### Security accuracy
- Fewer false positives in the dynamic and active checks, in SQL-injection detection and in secret-in-response detection; the scan now reports what it could not verify instead of guessing.
- Rate-limit probe no longer goes silent on POST-only login routes and skips HTML login pages.
- Fix application hardened: paths are confined to the project, a backup is written first, and the result is syntax-checked.

### No guessing of routes
- DeployReady now only requests routes it discovered (from your code, an OpenAPI/Swagger file on disk, or links advertised by responses it already fetched). It never invents paths.
- New opt-in common-path probe (`--probe-common-paths` or `probeCommonPaths` in config, off by default) with strict evidence rules and a confirmation step.
- Better route discovery: mount prefixes, more Express route styles, Next.js file routes, NestJS decorators, and FastAPI/Flask guard detection.

### AI providers
- New Claude (CLI login) and Codex (CLI login) providers: use your own installed `claude` / `codex` CLI and plan, no API key. A new provider and login step in `init` and the interactive menu shows login status and can start the CLI's own login.
- The CLIs run text-in/text-out only: tools off, empty temporary folder, minimal environment. No source files are sent and DeployReady never reads CLI credentials.
- Codex is enabled by default; turn it off with `"codexEnabled": false` in `~/.deployready/config.json`.
- AI findings stay unverified and never change the score or the CI gate.

### Tests
- Test suite grown to 1,000+ tests, with a labelled false-positive/false-negative benchmark (run in CI) and a coverage floor.

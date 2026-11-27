# Changelog

## 0.4.0

### Agent loop (MCP)
- New `deployready mcp`: a local MCP server for Claude Code, Cursor, Codex and Windsurf with `scan`, `get_finding`, `apply_safe_fixes`, `verify`, `score` and `supabase_check`. Your coding agent fixes, DeployReady verifies.
- Claude Code skill in `skills/deployready/SKILL.md`.

### Fix faster
- `fix --all` in the interactive shell and `analyze --fix` for CI/scripts: every safe deterministic fix in one pass, each re-verified.
- Backups now go to `.deployready/backups/` (gitignored) instead of next to your files.

### Proof, not guesses
- Live and active findings carry reproducible proof: a redacted curl request, status, response excerpt and a control request. Shown in the terminal, `show`, markdown, HTML and JSON.
- `verify` returns `fixed`, `still-present` or `inconclusive`. A live finding only counts as fixed when the attack fails and a control request still works. (Before, verifying an active finding always reported fixed.)
- Safe detection of unauthenticated DELETE/PATCH routes on localhost (non-existent record id, no body, random-path control).
- Ownership guard: active probes only target localhost unless you pass `--active-url` with `--i-own-this-target <host>` (or `ownedTargets` in config).

### Supabase
- Static: service_role keys in client-side code or public env vars are critical.
- Live (`--supabase`), read-only and counts-only, only for a local project or one you prove you own (service key or access token): tables readable by anon, anon-callable RPC functions, public buckets, sign-up settings, and opt-in two-user cross-read. See docs/SUPABASE.md.

### Accuracy
- New rules: hardcoded JWT signing secrets (critical), Flask `SECRET_KEY` literals, secrets in `NEXT_PUBLIC_`/`VITE_` variables, routes that change data or expose /admin with no auth check.
- RLS checks now fire when a Supabase project never enables RLS, and flag tables with RLS but no policy and `using (true)` policies.
- `.env` is critical only when it is tracked or in git history; an untracked, un-ignored `.env` is a warning.
- Fewer false positives on parameterized queries, header-derived tokens, comparisons and server-only Supabase modules.
- New labelled benchmark of vibe-coded apps (106 cases): precision 0.88 -> 0.95, recall 0.85 -> 0.92 on supported rules.

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

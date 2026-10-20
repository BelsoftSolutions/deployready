# Changelog

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

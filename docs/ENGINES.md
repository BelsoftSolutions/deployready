# External engines

DeployReady's own checks are native and offline. Engines are optional adapters that wrap
well-known scanners and normalize their output into DeployReady findings (`source: engine:<id>`).
An engine runs only when it is installed **and** applicable to your project. Nothing is downloaded or
installed for you.

| Engine id | Wraps | Runs when | License (of the tool) | Data that leaves your machine |
|---|---|---|---|---|
| `npm-audit` | `npm audit --json --omit=dev`, `pnpm audit --json --prod` | `package-lock.json` / `pnpm-lock.yaml` exists and npm/pnpm is on PATH (yarn.lock is skipped with a coverage note) | npm CLI: Artistic-2.0 (verified with `npm view npm license`); pnpm: MIT (not verified here) | Dependency names + versions go to your configured npm registry. No source code. |
| `osv-scanner` | `osv-scanner scan source --format json -r .` (v2) | `osv-scanner` is on PATH and a known manifest exists | Apache-2.0 (not verified here: not installed in the build container) | Package names + versions go to api.osv.dev. No source code. |
| `pip-audit` | `pip-audit -f json --no-deps --disable-pip -r requirements.txt` | `pip-audit` is on PATH and `requirements.txt` exists | Apache-2.0 (not verified here: not installed in the build container) | Package names + versions go to PyPI / the OSV service. No source code. |
| `semgrep` (opt-in) | `semgrep scan --config <yours> --metrics=off` | Only with `--engines semgrep` **and** `--semgrep-config` | Semgrep CE: LGPL-2.1 (not verified here; the rules you load carry their own licenses) | Local rules path: nothing. Registry id (`p/...`): rules are downloaded from semgrep.dev; your code is not uploaded. |

## Flags (`deployready analyze`)

- `--no-deps` skips all dependency engines.
- `--engines <list>` runs only the named engines (`npm-audit,osv-scanner,pip-audit,semgrep` or `all`). `semgrep` never runs unless named here.
- `--offline` skips every engine that contacts a network service, and records it as skipped. Native checks are unaffected. (Dependency engines are on by default, so use `--offline` for a fully offline run.)
- `--semgrep-config <path-or-registry>` is required for Semgrep. DeployReady ships no rules and never picks a registry for you. `auto` is refused because Semgrep requires metrics for it; DeployReady always passes `--metrics=off` and disables the version check.

## Install hints

- npm / pnpm: already present with Node.
- OSV-Scanner: `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` or a release binary from https://github.com/google/osv-scanner/releases (DeployReady does not download it).
- pip-audit: `pipx install pip-audit`.
- Semgrep CE: `pipx install semgrep`.

## Severity mapping (dependency advisories)

`critical` -> critical. `high` and `moderate` -> warning. `low` / `info` -> info. High is deliberately a
warning, not critical: advisories do not say whether the vulnerable code path is reachable from your app,
and treating every transitive "high" as release-blocking makes CI gates unusable. Lower the gate with
`--fail-on warning` if you want high advisories to fail the build. pip-audit publishes no severity, so its
findings are warnings. Semgrep `ERROR`/`WARNING` -> warning, `INFO` -> info (the rules are yours and unverified).
Findings use rule `dependency-vulnerability` with package, installed version, fixed version, advisory id/URL and an
upgrade command. Dependencies are audited as production-only (`--omit=dev`).

## Safety model

- Child processes use `execFile` with argument arrays (never a shell), a timeout (default 120 s), a 20 MB output cap, `cwd` set to the project root, and a minimal environment (PATH, HOME, locale, proxy and CA variables only; no tokens or API keys).
- Output is untrusted: it is parsed with `JSON.parse` in a try/catch, shapes are validated, and file paths outside the project are discarded.
- A failing engine (timeout, non-JSON output, registry unreachable, missing lockfile entries) is reported as an **error** in its coverage and a warning on the console. It is never treated as a clean result. Skipped items (yarn, `pyproject.toml`, `--offline`) are recorded with a reason. Per-engine results are in `report.engineRuns`.
- `pip-audit` runs with `--no-deps --disable-pip`, so nothing is installed or built; unpinned requirements produce an error. `pyproject.toml` is skipped because auditing it would run build backends.

## De-duplication

Engine findings at the same file + line + CWE as a native finding are dropped and the native finding gets
"(also reported by <engine>)". The same advisory reported by two dependency engines (matched by package and advisory id/alias) is kept once.

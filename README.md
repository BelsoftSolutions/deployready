# DeployReady

> Local-first, AI-optional production-readiness scanner. It runs 30+ structured tests against your code **and** your running localhost app, gives you a 0–100 readiness score, and **optionally** sends only the structured findings report — never your source code — to an AI model for deeper analysis.

```bash
npx deployready analyze ./my-app
```

## Install

**Run without installing** (recommended — always works, nothing to set up):

```bash
npx deployready ./my-app
```

**Or install globally** if you use it often (lets you drop the `npx` prefix):

```bash
npm install -g deployready
deployready ./my-app
```

Requires Node.js >= 18. Every command below is shown with `npx`; if you installed globally, just drop the `npx`.

## Quick start

Run it inside your project to open an interactive, guided session — no commands to memorize, just pick a number:

```bash
npx deployready ./my-app     # or just: npx deployready
```

```
  What would you like to do?
   1  Scan this project now            (recommended)
   2  Set up or change the AI model
   3  How does DeployReady work?
   4  Go to the command prompt
   5  Exit
```

After each action it suggests your next step (e.g. “type `fix 1` to fix the top issue”). Type `menu` anytime to bring the guide back.

## Interactive commands

Once a session is open, you can drive it directly:

```
deployready › scan        # full pipeline: parse → live tests → optional AI
deployready › issues      # list findings, numbered
deployready › show 3      # full detail of finding #3
deployready › fix 3       # auto-fix, or an AI-proposed diff you approve (backup created)
deployready › verify 3    # re-run the checks to confirm a fix worked
deployready › done 3      # mark fixed (score updates live)
deployready › open        # open the HTML dashboard in your browser
deployready › exit
```

| Command | What it does |
|---|---|
| `scan` · `parse` · `dynamic` · `ai` | run the whole pipeline, or one step at a time |
| `issues [crit\|warn\|info]` · `show <n>` | list findings (optionally filtered) · show one in detail |
| `fix <n>` | auto-fix where safe; otherwise an AI-proposed diff you approve (creates a backup); otherwise guidance |
| `verify <n>` | re-run the relevant checks to confirm a fix actually resolved the issue |
| `done <n>` · `ignore <n>` | mark fixed / ignored — the score recomputes immediately |
| `score` · `status` | show the current readiness score / session state |
| `deploy [aws\|do]` | deployment walkthrough for your stack |
| `export` · `open` | write `deployready-report.md` · open the HTML dashboard |
| `config` · `help` · `menu` · `clear` · `exit` | session utilities |

## One-shot (CI / scripting)

```bash
npx deployready init                              # first-time setup (pick model, store key)
npx deployready analyze ./my-app                  # single non-interactive scan, prints results
npx deployready analyze . --no-ai --no-dynamic    # static only, fully offline
npx deployready report ./my-app                   # scan and export the markdown report
npx deployready config                            # show the active config (secrets never printed)
```

**Flags for `analyze`:**

| Flag | Effect |
|---|---|
| `-y, --yes` | auto-approve all prompts (non-interactive) |
| `--no-dynamic` | skip live localhost testing |
| `--no-ai` | skip AI analysis (local results only) |
| `--aggressive` | enable aggressive tests (rate-limit burst) |
| `--export` | write `deployready-report.md` |
| `--html` / `--open` | write an HTML dashboard / and open it in your browser |
| `--json` | print a machine-readable JSON report (implies `--yes`) |
| `--fail-on <severity>` | exit non-zero if findings at/above `critical \| warning \| info \| none` exist |
| `-v, --verbose` | verbose debug output |

**CI gate:** exit codes are `0` (clean), `2` (gate failed), `1` (tool error).

```bash
npx deployready analyze . --no-ai --no-dynamic --fail-on critical
```

A ready-to-copy GitHub Action is in [`docs/github-action-example.yml`](docs/github-action-example.yml).

## What it checks

- **Static analysis** — Babel-based AST parsing (pure JS, no native build) for JavaScript/TypeScript, plus Python. Dependency graph, route-mount resolution across files, and stack detection (Express, Next.js, Fastify, NestJS, Koa, FastAPI, Flask, Django, Laravel).
- **Secrets & vulnerabilities** — hardcoded credentials, `eval`/command/SQL injection, XSS sinks, weak crypto, insecure randomness, disabled TLS verification, committed `.env`, log injection — each mapped to **OWASP Top 10 (2025)** and **CWE**.
- **Live dynamic testing** — detects your running localhost app and checks for auth bypass, exposed admin routes, secrets in responses, wildcard CORS, missing security headers, missing rate limiting, slow endpoints, missing cache headers, and version/stack-trace leaks.
- **Readiness score (0–100)** with a critical / warning / info breakdown.
- **Reports** — terminal output, markdown export, and an HTML dashboard.

## How it works

```
parse → static scan → (you approve) live localhost tests → aggregate + score
      → (you approve) AI analysis of findings JSON → terminal report → export
```

Only the **structured findings JSON** is ever sent to an AI — and only after you approve, with all secrets redacted first. With Ollama, nothing leaves your machine at all.

## AI models (optional)

DeployReady works fully offline with no AI. To enable deeper analysis, configure one via `npx deployready init`:

| Model | Notes |
|---|---|
| Claude (Anthropic) | Set `ANTHROPIC_API_KEY` or store via `init`. Default: `claude-sonnet-4-6`. |
| OpenAI | Set `OPENAI_API_KEY` or store via `init`. |
| Ollama (local) | Fully offline, no key — nothing leaves your machine. |

## Security & privacy

DeployReady reads your code, probes your ports, and holds your keys — so it's built to a high bar:

- API keys are read from environment variables first and **never logged**; the on-disk config is written with `0600` permissions.
- All terminal output and any AI payload pass through a central **secret redactor**.
- Dynamic testing is **loopback-only** and **GET-only** by default; aggressive tests require explicit consent.
- File scanning is confined to the project root, with symlink/traversal protection and size caps.

## Configuration

Config lives at `~/.deployready/config.json` — see [`docs/sample-config.json`](docs/sample-config.json). Prefer environment variables for API keys.

## Development

```bash
npm install
npm run build      # tsc -> dist/
npm test           # jest
npm run dev        # run from source via tsx
```

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

_Belal · Belsoft Solutions · MIT License_

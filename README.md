# DeployReady

> Local-first, AI-optional production-readiness scanner for your app. It runs 30+ structured tests against your code and your running localhost app, then **optionally** sends only the structured findings report — never your source code — to an AI model for deeper analysis.

```
deployready analyze ./my-app
```

> 📋 **See [STATUS.md](STATUS.md)** for the full usage guide, step-by-step npm publishing instructions, and an honest, always-current breakdown of what works today vs. what's still to be built.

## Why

Research in 2025–2026 found that **~91.5% of "vibe-coded" (AI-generated) apps ship with vulnerabilities**, only **~55%** of AI codegen tasks produce secure code, **86%** fail to defend against XSS, and AI-assisted commits leak secrets at roughly **2× the human baseline**. DeployReady catches those exact failure modes before you deploy.

- **Other tools:** send your whole repo to an AI. Expensive, slow, privacy risk.
- **DeployReady:** run the tests locally first. Send only structured findings to AI (if you want). Expert analysis without the token waste — and it works with no AI at all.

## Install

```bash
npm install -g deployready
```

## Usage

### Interactive session (default)

Run `deployready` in your project to open a persistent session. You're greeted with an animated welcome and a **guided menu** — no need to know any commands; just pick a number. It stays open and you drive it one step at a time until you `exit`:

```bash
deployready ./my-app     # or just: deployready
```

```
  What would you like to do?
   1  Scan this project now            (recommended)
   2  Set up or change the AI model
   3  How does DeployReady work?
   4  Go to the command prompt
   5  Exit
```

After any action it suggests your next step (e.g. “type `fix 1` to fix the top issue”). Type `menu` anytime to bring the guide back. Power users can ignore the menu and type commands directly:

```
deployready › scan        # parse → live tests → optional AI
deployready › issues      # list findings, numbered
deployready › show 3      # full detail of a finding
deployready › fix 3       # interactive fix: auto-fix, AI-proposed diff, or guidance
deployready › done 3      # mark fixed (score updates live)
deployready › deploy aws  # deployment walkthrough for your stack
deployready › export      # write deployready-report.md
deployready › exit
```

| Command | What it does |
|---|---|
| `scan` / `parse` / `dynamic` / `ai` | run the whole pipeline, or one step at a time |
| `issues [crit\|warn\|info]` · `show <n>` | list findings (filterable) · show one in detail |
| `fix <n>` | auto-fix where safe; else an AI-proposed diff you approve (creates a backup); else guidance |
| `done <n>` · `ignore <n>` | mark fixed/ignored — the score recomputes immediately |
| `score` · `status` · `deploy [aws\|do]` · `export` · `config` · `help` · `exit` | session utilities |

### One-shot (CI / scripting)

```bash
deployready init                 # first-time setup (pick model, store key)
deployready analyze ./my-app     # single non-interactive scan, prints results
deployready analyze . --no-ai --no-dynamic   # static only, fully offline
deployready report ./my-app      # scan and export markdown
deployready analyze . --no-ai --no-dynamic --fail-on critical   # CI gate: exit 2 on any critical
```

One-shot flags: `-y/--yes` (auto-approve prompts), `--aggressive` (rate-limit burst), `--export`, `--json` (machine-readable output), `--fail-on <critical|warning|info|none>` (CI exit code), `-v/--verbose`.

**CI:** exit codes are `0` (clean), `2` (gate failed), `1` (tool error). A ready-to-copy GitHub Action is in [`docs/github-action-example.yml`](docs/github-action-example.yml).

## Features

- **Static analysis** — Babel-based AST parsing (pure JS, no native build), dependency graph, stack detection (Express, Next.js, Fastify, NestJS, Koa, FastAPI, Flask, Django, Laravel).
- **Secret & vulnerability scanning** — hardcoded credentials, `eval`/command/SQL injection, XSS sinks, weak crypto, insecure randomness, disabled TLS verification, committed `.env`, log injection — each mapped to **OWASP Top 10 (2025)** and **CWE**.
- **Live dynamic testing** — detects your running localhost app and checks for auth bypass, exposed admin routes, secrets in responses, wildcard CORS, missing security headers, missing rate limiting, slow endpoints, missing cache headers, version-banner and stack-trace leaks.
- **Production-readiness score (0–100)** with critical/warning/info breakdown.
- **AI-optional** — works with no key; or send the structured report to Claude, OpenAI, or local Ollama.
- **Markdown export** to share with your team.

## How It Works

```
parse → static scan → (you approve) live localhost tests → aggregate + score
      → (you approve) AI analysis of findings JSON → terminal report → export
```

Only the **structured findings JSON** is ever sent to an AI — and only after you approve, with all secrets redacted first. Ollama runs fully offline.

## Supported AI Models

| Model | Notes |
|---|---|
| Claude (Anthropic) | Set `ANTHROPIC_API_KEY` or store via `init`. Default: `claude-sonnet-4-6`. |
| OpenAI | Set `OPENAI_API_KEY` or store via `init`. |
| Ollama (local) | Fully offline, no key, nothing leaves your machine. |

## Security & Privacy

DeployReady is itself built to a high security bar — it reads your code, probes your ports, and holds your keys:

- API keys are read from environment variables first and **never logged**. The on-disk config is written with `0600` permissions.
- All output and any AI payload pass through a central **secret redactor**.
- Dynamic testing is **loopback-only** and **GET-only** by default; aggressive tests require explicit consent.
- File scanning is confined to the project root with symlink/traversal protection and size caps.

## Configuration

`~/.deployready/config.json` — see [`docs/sample-config.json`](docs/sample-config.json). Prefer env vars for keys.

## Development

```bash
npm install
npm run build      # tsc -> dist/
npm test           # jest
npm run dev        # run from source via tsx
```

## Contributing

Issues and PRs welcome. Each module has a single responsibility and a documented interface contract; extend by adding new files rather than modifying existing modules (see the architecture spec).

## Roadmap (Phase 1.5 / 2)

Agentic fix application (propose → diff → approve → apply → verify), interactive deployment guides, real-time checklist sidebar, MCP database connectors, GitHub Action, and a compliance module.

---

_Belal · Belsoft Solutions · 2026 · MIT License_

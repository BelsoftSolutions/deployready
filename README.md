# EnterpriseReady

> Local-first, AI-optional production-readiness scanner for your app. It runs 30+ structured tests against your code and your running localhost app, then **optionally** sends only the structured findings report — never your source code — to an AI model for deeper analysis.

```
enterpriseready analyze ./my-app
```

## Why

Research in 2025–2026 found that **~91.5% of "vibe-coded" (AI-generated) apps ship with vulnerabilities**, only **~55%** of AI codegen tasks produce secure code, **86%** fail to defend against XSS, and AI-assisted commits leak secrets at roughly **2× the human baseline**. EnterpriseReady catches those exact failure modes before you deploy.

- **Other tools:** send your whole repo to an AI. Expensive, slow, privacy risk.
- **EnterpriseReady:** run the tests locally first. Send only structured findings to AI (if you want). Expert analysis without the token waste — and it works with no AI at all.

## Install

```bash
npm install -g enterpriseready
```

## Usage

### Interactive session (default)

Run `enterpriseready` in your project to open a persistent session. It stays open and you drive it one step at a time until you `exit`:

```bash
enterpriseready ./my-app     # or just: enterpriseready
```

```
enterpriseready › scan        # parse → live tests → optional AI
enterpriseready › issues      # list findings, numbered
enterpriseready › show 3      # full detail of a finding
enterpriseready › fix 3       # interactive fix: auto-fix, AI-proposed diff, or guidance
enterpriseready › done 3      # mark fixed (score updates live)
enterpriseready › deploy aws  # deployment walkthrough for your stack
enterpriseready › export      # write enterpriseready-report.md
enterpriseready › exit
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
enterpriseready init                 # first-time setup (pick model, store key)
enterpriseready analyze ./my-app     # single non-interactive scan, prints results
enterpriseready analyze . --no-ai --no-dynamic   # static only, fully offline
enterpriseready report ./my-app      # scan and export markdown
```

One-shot flags: `-y/--yes` (auto-approve prompts), `--aggressive` (rate-limit burst), `--export`, `-v/--verbose`.

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

EnterpriseReady is itself built to a high security bar — it reads your code, probes your ports, and holds your keys:

- API keys are read from environment variables first and **never logged**. The on-disk config is written with `0600` permissions.
- All output and any AI payload pass through a central **secret redactor**.
- Dynamic testing is **loopback-only** and **GET-only** by default; aggressive tests require explicit consent.
- File scanning is confined to the project root with symlink/traversal protection and size caps.

## Configuration

`~/.enterpriseready/config.json` — see [`docs/sample-config.json`](docs/sample-config.json). Prefer env vars for keys.

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

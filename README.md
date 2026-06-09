# DeployReady

> **Ship with confidence.** Catch security and deploy-blocking issues before you ship — run 30+ structured tests across your code **and** your running app, get a 0–100 readiness score, and apply **AI-powered fixes**, all in one command.

```bash
npx deployready@latest analyze ./my-app
```

> _Privacy:_ scanning runs locally. Only a redacted findings report is ever sent to an AI — after you approve it, never your source code — and you can use a local model (Ollama) to keep everything 100% offline.

## Install

**Run without installing** (recommended — always works, nothing to set up):

```bash
npx deployready@latest ./my-app
```

**Or install globally** if you run it often (faster, but you must update it yourself):

```bash
npm install -g deployready
deployready ./my-app
# update later with: npm i -g deployready@latest
```

Requires Node.js >= 18. The `@latest` tag ensures you always get the newest version — plain `npx deployready` can reuse a cached older copy. Every command below is shown with `npx deployready@latest`; if you installed globally, use `deployready` instead.

## Quick start

Run it inside your project to open an interactive, guided session — no commands to memorize, just pick a number:

```bash
npx deployready@latest ./my-app     # or just: npx deployready@latest
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
| `fix <n>` | deterministic auto-fix where safe (weak hashes, disabled TLS verification, `yaml.load`, `verify=False`, Flask `debug=True`, gitignore `.env`); otherwise an AI-proposed diff you approve (creates a backup); otherwise guidance |
| `verify <n>` | re-run the relevant checks to confirm a fix actually resolved the issue |
| `done <n>` · `ignore <n>` | mark fixed / ignored — the score recomputes immediately |
| `score` · `status` | show the current readiness score / session state |
| `deploy [platform]` | recommend a host for this project (no arg) or print a step-by-step guide for a chosen one (`aws`, `do`, `vercel`, `render`, `railway`, `fly`, `netlify`) |
| `export` · `open` | write `deployready-report.md` · open the HTML dashboard |
| `config` · `help` · `menu` · `clear` · `exit` | session utilities |

## One-shot (CI / scripting)

```bash
npx deployready@latest init                              # first-time setup (pick model, store key)
npx deployready@latest analyze ./my-app                  # single non-interactive scan, prints results
npx deployready@latest analyze . --no-ai --no-dynamic    # static only, fully offline
npx deployready@latest report ./my-app                   # scan and export the markdown report
npx deployready@latest config                            # show the active config (secrets never printed)
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
| `--baseline <file>` | gate only on findings **not** in the baseline file (existing issues are grandfathered) |
| `--write-baseline <file>` | write the current findings to a baseline file and exit `0` (accept current state) |
| `--active` | run **active** authenticated authorization tests (needs `--token`; consented, loopback-only, GET-only) |
| `--token <jwt>` | bearer JWT for the active scan (your logged-in test user) |
| `--token-b <jwt>` | a second user's JWT — enables tenant / IDOR isolation tests |
| `-v, --verbose` | verbose debug output |

**CI gate:** exit codes are `0` (clean), `2` (gate failed), `1` (tool error).

```bash
npx deployready@latest analyze . --no-ai --no-dynamic --fail-on critical
```

**Grandfather existing issues (baseline):** adopt the current findings once, then fail the
build only on *new* ones — so you can turn the gate on for an existing codebase without
drowning in pre-existing debt:

```bash
npx deployready@latest analyze . --no-ai --no-dynamic --write-baseline .deployready-baseline.json   # once
npx deployready@latest analyze . --no-ai --no-dynamic --baseline .deployready-baseline.json --fail-on warning  # in CI
```

A ready-to-copy GitHub Action is in [`docs/github-action-example.yml`](docs/github-action-example.yml).

### Active (authenticated) testing — "try to hack it"

With your app running locally, DeployReady can act as a logged-in user and try to break access control — the checks you'd otherwise do by hand in Burp/Postman:

```bash
npx deployready@latest analyze . --active --token "<your-JWT>" --token-b "<second-user-JWT>"
```

- **Broken object-level auth (IDOR/BOLA)** — swaps resource ids to reach another user's data.
- **Broken tenant isolation** — swaps `org_id`/tenant to reach another tenant's data.
- **Privilege escalation** — forges a `role: admin` claim and checks whether a forbidden route opens up.
- **JWT not verified** — checks whether the server accepts a forged `alg:none` token.

It is **opt-in and consented**, **loopback-only**, and **GET-only** (it never writes). Need a token? Run `--active` without one and DeployReady prints step-by-step instructions for grabbing your JWT from the browser.

## What it checks

- **Static analysis** — Babel-based AST parsing (pure JS, no native build) for JavaScript/TypeScript, plus Python. Dependency graph, route-mount resolution across files, and stack detection (Express, Next.js, Fastify, NestJS, Koa, FastAPI, Flask, Django, Laravel).
- **Secrets & vulnerabilities** — hardcoded credentials, `eval`/command/SQL injection, XSS sinks, weak crypto, insecure randomness, disabled TLS verification, JWT `none` algorithm, insecure cookies, unsafe deserialization, insecure temp files, committed `.env`, log injection — each mapped to **OWASP Top 10 (2025)** and **CWE**.
- **Access control & transport** — Row-Level Security disabled or never enabled on a table, Supabase `service_role` key used in app code (RLS bypass), and insecure cleartext `http://` endpoints.
- **Live dynamic testing** — detects your running localhost app and checks for auth bypass, exposed admin routes, secrets in responses, wildcard CORS, missing security headers, missing rate limiting, slow endpoints, missing cache headers, and version/stack-trace leaks.
- **Active authorization testing** (opt-in, `--active`) — acts as a logged-in user to find broken object-level auth (IDOR/BOLA), broken tenant isolation, privilege escalation (forged `role`), and unverified JWTs (`alg:none`).
- **Readiness score (0–100)** with a critical / warning / info breakdown.
- **Deployment recommendation** — suggests where to host based on your stack, size, and whether you're frontend / backend / full-stack, flags when to split frontend and backend across platforms, and marks suitable free tiers.
- **Reports** — terminal output, markdown export, and a branded HTML dashboard.

## How it works

```
parse → static scan → (you approve) live localhost tests → aggregate + score
      → (you approve) AI analysis of findings JSON → terminal report → export
```

Only the **structured findings JSON** is ever sent to an AI — and only after you approve, with all secrets redacted first. With Ollama, nothing leaves your machine at all.

## AI models (optional)

DeployReady works fully offline with no AI. To enable deeper analysis, configure one via `npx deployready@latest init`:

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

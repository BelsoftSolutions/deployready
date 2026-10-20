# Design: opt-in common-path probe + evidence-based route discovery

Design notes for the common-path probe and route discovery. The code comments in `src/dynamic/commonPaths/` refer to the section numbers below.

Invariants that never change (DeployReady never guesses routes):

- **Default scan** requests only paths that are *evidence about this app*: routes found in the code, routes declared in the project's own API description on disk, and links the running app itself advertised in a response the scan already fetched. Nothing else. No dictionary, no guessed name, no invented id.
- **The probe** is the only exception, off by default, requested explicitly by the user, and every path it sends is printed before it sends.
- Loopback only (`assertLoopback`), GET only, no redirects followed, no credentials/cookies sent, no AI calls anywhere.

---

## Part 1: opt-in common-path probe

### 1.1 Switch and UX

| Item | Decision |
|---|---|
| CLI flag | `--probe-common-paths` (analyze command). `--no-probe-common-paths` forces it off for one run. |
| Config key | `probeCommonPaths: boolean` in `~/.deployready/config.json`, default `false`. `init`/onboarding never sets it. |
| Default | OFF. Not enabled by interactive defaults, `-y`, `--json`, or CI. |
| Non-interactive runs (`--yes`, `--json`, env `CI` set) | Probe runs **only if `--probe-common-paths` is on the command line**. The config key alone does NOT enable it there. |
| Interactive runs | Enabled by the flag or the config key. Before any request: print target + the exact path list + the request cap, then ask a confirm prompt whose **default is No**. |
| Non-interactive with flag | Print the same target + list (to the log/stderr; must not corrupt `--json` stdout), no prompt (the flag is the consent). |
| Needs | Dynamic scan enabled (`--no-dynamic` disables the probe too) and a detected local server. Uses the same target/consent flow as the dynamic scan; the probe confirmation is a separate, second prompt. |
| Zero discovered routes | With the probe on, the dynamic phase still runs for the probe (the existing `No routes discovered; dynamic checks skipped` note stays; the probe is additional). |
| Hint when off | Interactive, non-JSON runs print one `logger.info` line after the dynamic step: the probe exists, is off, and how to enable it. Never in `--yes`/`--json`/CI. |

### 1.2 Request rules (hard, tested)

- Fixed list below (16 paths). Paths already requested as discovered/advertised targets are removed from the list and shown as "covered by the normal scan" (no duplicate request, no duplicate finding).
- Order: 1 random-404 **control** first, then the paths in table order, **sequentially**, 250 ms apart (delay injectable for tests, 0 in tests).
- **Hard cap: 20 requests total including the control** (`MAX_PROBE_REQUESTS = 20`), enforced inside the requester wrapper (it throws on the 21st), not only by list length. A test must prove it.
- Abort the rest of the probe after 3 consecutive network errors (record "aborted").
- Response body read as a Buffer, capped at 256 KB. Timeout 5 s. `maxRedirects: 0`. Only the existing `User-Agent`.
- Control request: `GET /__deployready_probe_<12 hex random>`. It is a negative control by construction (path does not exist), never reported as a finding. It is sent for the opt-in probe only (the lazy control for discovered routes is unchanged). Its fingerprint feeds rule C3.

### 1.3 Evidence rules (a status code alone is never a finding)

Applied in this order to the response of every probed path. First failing rule decides the outcome.

| Rule | Check | Outcome when it fails/applies |
|---|---|---|
| C1 status | Only `200` continues. `3xx`: if `Location` matches `/log-?in|sign-?in|auth|sso/i` -> `protected` ("redirect to login: protected, not exposed"), else `protected` ("redirect, not followed"). `401`/`403` -> `protected`. `404`/`410`/`405`/`5xx`/other -> `not-found`. | no finding |
| C2 not a catch-all | If the control returned 2xx: the response is "the same as the control" when **hash equal, or length equal, or shape equal**. Shape: JSON -> sorted top-level key set; HTML -> normalized `<title>` text plus the sequence of the first 30 tag names. Same as control -> `not-proven` ("same body/length/shape as the app's answer for a non-existent path: catch-all"). | no finding |
| C3 not a login page | Body contains `<input` with `type="password"` (any quote style) -> `not-proven` ("login page"). | no finding |
| C4 row signature | The per-path signature in 1.4 must match on the body. HTML where a data file is expected (`Content-Type: text/html`, or first non-space char `<` for rows marked "not HTML") -> `not-proven` ("HTML, not the expected content"). | no finding |
| C5 | All of the above pass -> `found`, with the severity from 1.5. | finding |

Outcomes: `found`, `not-found`, `protected`, `not-proven`, `error`. Everything except `found` is "probed, not found" in the report, with its reason.

### 1.4 Evidence signature per path (fixed table; one test file row per entry, positive and negative)

"Conclusive" = the content itself proves a real exposure (secrets, repo, database), so a critical is allowed. Everything else is capped below critical.

| # | Path(s) | Content signature (all must hold) | Not-HTML | Severity | Conclusive |
|---|---|---|---|---|---|
| 1 | `/.env`, `/.env.local`, `/.env.production` | At least 1 line `^(export\s+)?[A-Za-z_][A-Za-z0-9_]*=.+`, and at least 50% of non-empty, non-`#` lines are KEY=VALUE lines; body <= 64 KB. | yes | `critical` if any value matches `detectSecret()==='high'` or a key matching `/SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|API_?KEY|ACCESS_?KEY|DATABASE_URL|CREDENTIAL/i` has a non-empty, non-placeholder value (placeholder = empty, `changeme`, `your_*`, `xxx*`, `<...>`, `...`, `example*`, `${...}`); otherwise `warning` | secret case only |
| 2 | `/.git/config` | A `[core]` line AND one of `repositoryformatversion`, `[remote "`, `[branch "`. | yes | `critical` | yes |
| 3 | `/.npmrc` | A line `^(//\S+:)?_(authToken\|auth\|password)\s*=\s*\S+`. | yes | `critical` | yes |
| 4 | `/backup.sql`, `/dump.sql` | Within the first 4 KB: `-- MySQL dump` or `-- PostgreSQL database dump` or (`CREATE TABLE` or `INSERT INTO`, case-insensitive) with at least 2 lines ending in `;`. | yes | `critical` | yes |
| 5 | `/db.sqlite3` | Buffer starts with the 16 bytes `SQLite format 3\0`. | n/a (binary) | `critical` | yes |
| 6 | `/actuator/env` | JSON object with an array `propertySources` or an array `activeProfiles`. | JSON | `warning`; `critical` if `detectSecret(body)==='high'` (unmasked secret) | only for the critical case |
| 7 | `/actuator` | JSON object with `_links` object having `self` and at least one of `health`, `env`, `beans`, `mappings`, `info`, each value an object with a string `href`. | JSON | `info` | no |
| 8 | `/phpinfo.php` | Body contains `<title>phpinfo()</title>`, or both `PHP Version` and `phpinfo()`. | HTML expected | `warning` | no |
| 9 | `/metrics` | A line `# HELP <name> ...` and a line `# TYPE <name> (counter\|gauge\|histogram\|summary\|untyped)` for the same name. | not HTML | `info` | no |
| 10 | `/debug/pprof/` | Contains `Types of profiles available` (Go pprof index). | HTML expected | `warning` | no |
| 11 | `/server-status` | Contains `Apache Server Status for`. | HTML expected | `warning` | no |
| 12 | `/console` | Contains `Interactive Console` and (`Werkzeug` or `__debugger__`) and not `Console Locked` -> unlocked debugger. Contains `Console Locked` and `Werkzeug`/`__debugger__` -> locked. | HTML expected | unlocked `critical`; locked `warning` | unlocked only |
| 13 | `/admin` | C1-C3 pass AND the page `<title>` or first `<h1>` matches `/\badmin(istrat\w*)?\b\|dashboard\|control panel\|backoffice/i`. JSON bodies never match. | HTML expected | `warning` | no (weakest row, always lower confidence) |

Redaction rule: **never put a secret value, URL userinfo, or token in the finding, evidence, verbose log or report**. Evidence shows key names and counts only (e.g. `3 KEY=VALUE lines; keys: DATABASE_URL, STRIPE_KEY; values not shown`). Run anything stringified through `redact()`.

### 1.5 Severity and score rules

- Finding rule id: `common-path-exposure`; `source: 'dynamic'`, `category: 'security'`; new optional field `Finding.guessed?: boolean` set to `true` (generic: "found by the opt-in common-path probe, lower confidence").
- Title always carries the label: `<what> (guessed path, lower confidence)`. Description states the path was not discovered by the scan but requested by the opt-in probe, and which content proved it.
- **Ceiling:** the severity in the table above is the ceiling; non-conclusive rows can never be `critical`. Discovered-route findings are untouched.
- **Scoring/gating:** a guessed finding scores and gates at its (capped) severity, exactly like any other finding of that severity. Rationale: the cap already encodes the lower confidence; a conclusive critical (real secrets, repo, database) must fail a `--fail-on critical` gate. No guessed finding is ever `unverified`/`note`.
- Dedup: if a path is also a discovered/advertised target it is not probed at all, so the discovered finding stands alone.
- Report: guessed findings are listed in their own section in all four outputs (terminal, markdown export, HTML, `--json`), titled `Common-path probe (opt-in): guessed paths, lower confidence`. The section also lists **every path requested**, with outcome (found / not found / protected / not proven) and reason, plus the control request and the cap. `DynamicResults.commonPaths = { target, cap, control: { path, status }, probed: [{ path, status?, outcome, reason }], aborted?: string }`.
- Verbose (`-v`): one `logger.debug` line per request: `[probe-common] GET /path -> 200 not-proven: <reason>`.

### 1.6 Docs

`docs/COMMON-PATH-PROBE.md` (user-facing): what it is, how to enable, the exact list, the evidence table above, severity rules, what it will never do. `docs/sample-config.json` gains `"probeCommonPaths": false`. README: one short paragraph.

---

## Part 2: evidence-based route discovery (on by default, no guessing)

### 2.1 Static-analysis improvements chosen

Picked by gain per effort, measured against the parser matrix (18/59 routes, 13/34 probeable, 16 wrong-path routes today):

| Proposal | Chosen | Why |
|---|---|---|
| 1 Mount/prefix handling (Fastify, Koa, Flask, FastAPI `APIRouter`, Hono, Express constant prefixes) | **yes** | Largest gain: 7 of the 21 missed probeable routes and removes 14 wrong-path requests. Fallback stays "skip the route" when a prefix is not a string literal. |
| 2 Next.js file routes + stop treating `headers.get()` / `cookies.get()` as routes | **yes** | Next.js is the worst case (0/6 found, 2 phantom routes requested). Filesystem walk, no AST. |
| 4 NestJS decorators | **yes** | 0/6 found today; decorators are simple in the existing Babel adapter. |
| 6 Express route styles (`app.route()` chains, same-file constants, path arrays) | **yes** | Express is the most common stack; 6 of 8 style probes missed; low risk. |
| 7 Guard evidence for FastAPI `dependencies=[Depends(...)]` and Flask `@login_required` on the next line | **yes** | Small; fixes 2 wrongly "open" admin routes; only ever removes findings, never adds. |
| 8 OpenAPI/Swagger from disk | **yes** (required) | Works for every stack, including those with no adapter. |
| 3 Django `urls.py`/DRF | no | Medium-high effort (include() nesting, regex paths) for 4 probeable routes; report as remaining gap. |
| 5 Laravel `routes/*.php` | no | Medium-high effort, no PHP adapter exists; remaining gap. |

### 2.2 OpenAPI/Swagger from disk (no request involved)

- Find `openapi.{json,yaml,yml}` and `swagger.{json,yaml,yml}` through `FileWalker` (it already respects `.gitignore` and skips `node_modules`), at most 5 files, each <= 2 MB.
- JSON via `JSON.parse`. YAML: **no new dependency**; a small reader for block-style YAML that extracts `servers`/`basePath` and the `paths:` tree (path keys, method keys, `security`). Flow-style/anchored YAML that it cannot read is skipped with a visible info line, never guessed.
- Base path: Swagger 2 `basePath`; OpenAPI 3 `servers[0].url` only when it is a relative path or a loopback URL (a production hostname's path is not trusted as the local mount). Apply it as a prefix.
- Each `method + path` becomes a `Route` with `source: 'openapi'`, `file` = the spec file (relative), `guarded` = operation `security` (or global `security`) non-empty and not explicitly `[]`. Parameterised paths (`{id}`) and non-GET stay discovered-but-skipped, as today.
- Deduplicate against code routes by method + normalized path; if both exist keep the code route and add the spec as extra evidence.

### 2.3 Running-app advertised links (default on; nothing guessed)

Only **responses the scan already fetched from discovered/spec routes**, parsed for what the app itself advertises:

- `<a href>` and `<link href>` (same origin; relative or the exact `baseUrl`), `<form method="get" action>` actions are NOT used.
- `Link:` response headers with `rel` in `sitemap`, `service-desc`, `describedby`.
- A `Sitemap:` line or `<loc>` entries, **only if** `/robots.txt` or `/sitemap.xml` is itself evidence: a file of that name in the project's static dirs (`public/`, `static/`, `www/`, `dist/`, project root) or a discovered route, or advertised by an already fetched response. The scan never requests `/robots.txt` or `/sitemap.xml` on a hunch.
- If a discovered/advertised path serves an OpenAPI/Swagger JSON (body has `openapi` or `swagger` plus `paths`), read its `paths` the same way as 2.2.
- Limits: depth 1 (advertised paths are not crawled further), at most 25 new paths per scan, GET only, skip static-asset extensions (`.js .css .png .jpg .jpeg .gif .svg .ico .woff .woff2 .ttf .map .pdf .zip`), skip any path with a whole-word segment `logout|signout|sign-out|log-out|delete|remove|destroy|unsubscribe|revoke|reset|cancel` (GET links that can change state), skip links to other hosts, skip `mailto:`/`javascript:`/`#`.
- Each advertised path becomes a target with `why: ['advertised by GET /x (link)']`, shown in verbose output and the report's probed list, and passes through the same checks as discovered routes (catch-all control still lazy).
- Invariant to test: with zero discovered routes nothing is requested at all (there is no page to read links from).

### 2.4 Measurement

Before: parser matrix 18/59 real routes, 13/34 probeable, 16 wrong-path routes. After: re-run the matrix per stack and report case by case, including regressions. No case deleted; new matrix rows/fixtures added for: OpenAPI (JSON and YAML), advertised links, Next file routes, Nest, each prefix style, each Express style.


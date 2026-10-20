# Common-path probe (opt-in)

By default DeployReady's live tests only touch routes your code defines, your OpenAPI/Swagger file declares, or your running app advertises (see [route discovery](ROUTE-DISCOVERY.md): [OpenAPI/Swagger from disk](ROUTE-DISCOVERY.md#openapiswagger-from-disk) and [advertised links](ROUTE-DISCOVERY.md#advertised-links)). It never guesses paths.

The common-path probe is an **opt-in** extra step that asks a running local app for a short, fixed list of well-known sensitive files and debug pages (`/.env`, `/.git/config`, `/actuator/env`, ...). Because these paths were guessed rather than discovered, anything it reports is labelled **guessed path, lower confidence**.

It is **off by default**: not by interactive defaults, not by `--yes`, not by `--json`, not in CI.

## How to enable

| Situation | What turns it on |
|---|---|
| Any run | `--probe-common-paths` on the `analyze` command |
| Interactive run | the flag, or `"probeCommonPaths": true` in `~/.deployready/config.json` |
| Non-interactive run (`--yes`, `--json`, or the `CI` environment variable set) | **only** the `--probe-common-paths` flag. The config key alone never enables it here |
| One run, force off | `--no-probe-common-paths` (wins over the config key) |

`deployready init` never sets the key to `true`.

The probe also needs the normal dynamic scan: `--no-dynamic` disables it, and it needs a detected local server. It uses the same target as the dynamic scan, and it still runs when the scan discovered zero routes (the "No routes discovered; dynamic checks skipped" note stays; the probe is additional).

```bash
# interactive: lists the paths, then asks (default: No)
deployready analyze . --probe-common-paths

# CI / scripting: the flag is the consent; the list is printed to stderr, no prompt
deployready analyze . --yes --json --probe-common-paths
```

Before sending anything, DeployReady prints the target, the exact path list and the request cap. In an interactive run it then asks for confirmation (default **No**; answering No sends zero requests). With the flag in a non-interactive run it prints the same information and proceeds. Under `--json` this text goes to stderr, so stdout stays valid JSON.

When the probe is off, interactive non-JSON runs print one hint line after the dynamic step. `--yes`, `--json` and CI never print it.

## The exact path list (16 paths)

```
/.env                /.env.local          /.env.production
/.git/config         /.npmrc
/backup.sql          /dump.sql            /db.sqlite3
/actuator/env        /actuator
/phpinfo.php         /metrics             /debug/pprof/
/server-status       /console             /admin
```

A path the normal scan already requested (a discovered or advertised route) is not requested again; it is shown as "covered by the normal scan" and the normal finding stands alone.

## Request rules

- One random-404 **control** request first (`GET /__deployready_probe_<12 hex>`), then the paths above, **sequentially**, 250 ms apart.
- **Hard cap: 20 requests including the control**, enforced inside the request wrapper (the 21st request throws), not just by list length.
- The rest of the probe is aborted after 3 consecutive network errors (recorded in the report).
- GET only. Response body read as bytes and capped at 256 KB. 5 s timeout. Redirects are never followed. Only the existing `User-Agent`.

## Evidence: a status code alone is never a finding

Rules are applied in order to every response; the first one that fails decides the outcome.

| Rule | Check | Outcome |
|---|---|---|
| C1 status | Only `200` continues. `3xx` to a login/auth/sso URL is `protected` ("redirect to login: protected, not exposed"); any other `3xx` is `protected` ("redirect, not followed"). `401`/`403` is `protected`. `404`, `410`, `405`, `5xx` and anything else is `not-found`. | no finding |
| C2 not a catch-all | If the control returned 2xx, a response whose body hash, length or shape (JSON top-level keys; HTML title plus the first 30 tag names) equals the control's is `not-proven` ("catch-all"). | no finding |
| C3 not a login page | A body containing `<input type="password">` is `not-proven` ("login page"). | no finding |
| C4 content signature | The per-path signature below must match. HTML where a data file is expected is `not-proven` ("HTML, not the expected content"). | no finding |
| C5 | All of the above pass: `found`, with the severity from the table. | finding |

Outcomes are `found`, `not-found`, `protected`, `not-proven` and `error`. Everything except `found` is listed in the report as "probed, not found", with its reason.

### Content signature per path

"Conclusive" means the content itself proves a real exposure (secrets, repository, database), which is the only case a `critical` is allowed.

| # | Path(s) | Content signature (all must hold) | Severity | Conclusive |
|---|---|---|---|---|
| 1 | `/.env`, `/.env.local`, `/.env.production` | At least one `KEY=VALUE` line and at least 50% of the non-empty, non-comment lines are `KEY=VALUE`; body at most 64 KB; not HTML | `critical` if a value looks like a high-confidence secret, or a key named like `SECRET`, `PASSWORD`, `TOKEN`, `PRIVATE`, `API_KEY`, `ACCESS_KEY`, `DATABASE_URL`, `CREDENTIAL` has a non-empty, non-placeholder value; otherwise `warning` | secret case only |
| 2 | `/.git/config` | A `[core]` line and one of `repositoryformatversion`, `[remote "`, `[branch "`; not HTML | `critical` | yes |
| 3 | `/.npmrc` | A registry credential line (`_authToken`, `_auth` or `_password` with a value); not HTML | `critical` | yes |
| 4 | `/backup.sql`, `/dump.sql` | In the first 4 KB: a MySQL/PostgreSQL dump header, or `CREATE TABLE`/`INSERT INTO` with at least 2 lines ending in `;`; not HTML | `critical` | yes |
| 5 | `/db.sqlite3` | Starts with the 16 bytes `SQLite format 3\0` | `critical` | yes |
| 6 | `/actuator/env` | JSON object with an array `propertySources` or `activeProfiles` | `warning`; `critical` if an unmasked secret-shaped value is present | critical case only |
| 7 | `/actuator` | JSON `_links` with `self` and at least one of `health`, `env`, `beans`, `mappings`, `info`, each with a string `href` | `info` | no |
| 8 | `/phpinfo.php` | `<title>phpinfo()</title>`, or both `PHP Version` and `phpinfo()` | `warning` | no |
| 9 | `/metrics` | A `# HELP <name>` line and a `# TYPE <name> counter\|gauge\|histogram\|summary\|untyped` line for the same name; not HTML | `info` | no |
| 10 | `/debug/pprof/` | Contains `Types of profiles available` | `warning` | no |
| 11 | `/server-status` | Contains `Apache Server Status for` | `warning` | no |
| 12 | `/console` | Werkzeug debugger page: unlocked (`Interactive Console`, no `Console Locked`) or PIN-locked (`Console Locked`) | unlocked `critical`; locked `warning` | unlocked only |
| 13 | `/admin` | Passes C1 to C3, and the HTML `<title>` or first `<h1>` names an admin area (`admin`, `administration`, `dashboard`, `control panel`, `backoffice`); JSON never matches | `warning` | no (weakest row) |

## Severity, score and gating

- Findings use the rule id `common-path-exposure` (`source: dynamic`, `category: security`) and a title that always ends with `(guessed path, lower confidence)`.
- The severity in the table is a **ceiling**: a non-conclusive row can never be `critical`.
- A guessed finding **scores and gates at its capped severity**, exactly like any other finding of that severity. A conclusive critical (real secrets, a repository, a database) therefore fails `--fail-on critical`, and a non-conclusive warning does not. The cap already encodes the lower confidence. Guessed findings are never "unverified" or "note" findings.
- Baselines work unchanged: a guessed finding is fingerprinted like any other.

## Where it appears in the report

Terminal, markdown export, HTML report and `--json` each get a separate section titled **Common-path probe (opt-in): guessed paths, lower confidence**. It holds the guessed findings (they are not repeated in the normal findings list), **every requested path** with its status, outcome and reason, the control request, and the request cap. In `--json` the section is the `commonPathProbe` key, present only when the probe ran, so default JSON output is unchanged. The summary counts and the score include the guessed findings.

## What it never does

- It never runs unless you opt in, and never from the config key alone in a non-interactive run.
- It never requests anything outside the 16 listed paths and the one control path, never more than 20 requests, never in parallel.
- It never writes: GET only, no request body, no credentials, no cookies, no redirects followed, no crawling and no brute forcing.
- It never targets anything but the local server already selected for the dynamic scan.
- It never prints a secret value, URL credentials or token: evidence shows key names and counts only (for example `3 KEY=VALUE lines; keys: DATABASE_URL, STRIPE_KEY; values not shown`), and all output is redacted.
- It never reports a path because of its status code alone.

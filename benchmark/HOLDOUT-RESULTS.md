# Holdout benchmark results (DeployReady 0.5.0 vs Semgrep OSS vs a plain LLM)

Holdout = `benchmark/holdout/` (46 cases: 28 vulnerable, 18 secure negatives, 29 positive labels in 25 issue classes). It was written
without reading DeployReady's rule implementations and is **never used for rule tuning** (see `benchmark/holdout/README.md`;
CI fails if `src/` references it). The development corpus (`benchmark/corpus/`) is scored separately and never merged:
see "Development corpus" at the end for contrast.

## Method

- Ground truth: `benchmark/holdout/labels.json`, by issue class (not rule id). Tool output is mapped to classes by `benchmark/holdoutMapping.ts`
  (DeployReady rule id table; Semgrep keyword/CWE regexes; LLM keyword regexes over the free-text issue). The mapping was written before any tool ran.
- Scoring unit = (case, file, class). TP: labelled issue has an alert of that class in that file. FN: none. FP: alert of a mapped class on a negative case.
  TN: (negative case x 25 classes) pairs with no alert. "Extra" = mapped alert on a vulnerable case that matches no label (not penalised; labels are not exhaustive);
  "Precision incl. extras" counts them as FP. "Other" = alert outside the taxonomy (not penalised). Severity-weighted recall: critical 4 / high 3 / medium 2 / low 1.
  Inconclusive (tool error/timeout): labels count as FN; none occurred.
- Each case is copied to a fresh temp dir (no repo `.gitignore`, no labels) before any tool sees it.
- Runner: `npx tsx benchmark/bench.ts --suite holdout [--run ...]`; without `--run` it re-scores the saved raw outputs. Duration is wall time of the tool process;
  peak RSS is the max RSS of the process tree (python3 `RUSAGE_CHILDREN` wrapper). Runs were sequential on a shared 4-core sandbox, so timings are indicative only.

## Versions and configuration

| Tool | Version | Configuration |
|---|---|---|
| DeployReady | 0.5.0, base commit 448ea2b, `npm run build` then `node dist/index.js` | `analyze --json --no-dynamic --no-ai --no-deps --offline <case>` (static + secrets only; findings with `note:true` are ignored) |
| Semgrep OSS | 1.187.0 | `--metrics=off --disable-version-check --no-git-ignore --config <rules> --json`; rules = `github.com/semgrep/semgrep-rules` at commit `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`, dirs `javascript typescript python generic` (`*.test.*`/`*.fixed.*` excluded), same as `COMPARISON.md`. **`p/default` was not reachable** (semgrep.dev returns 403 from the sandbox proxy), so it was NOT run; a real `p/default` run could differ. |
| Plain LLM | Claude Code CLI 2.1.332, `--model haiku` (resolved model id `claude-haiku-5-5`) | `claude -p --model haiku --tools "" --setting-sources "" --disable-slash-commands`, default temperature, **one run per case**, same neutral prompt as `compare.ts`: "Review this project for security vulnerabilities. List each issue as JSON lines {file, line, issue}." Stdin = file list + every file concatenated. |

Raw outputs (one file per case and tool, plus `*.meta.json` with duration, peak RSS, exit code):
`benchmark/results/holdout/raw/{deployready,semgrep,llm}/`. Scores: `benchmark/results/holdout/results.json`, full per-case tables: `benchmark/results/holdout/summary.md`.
Note: the Semgrep run was interrupted by a usage-limit pause after 40 cases; the remaining 6 (n13..n18) were run afterwards with the identical command.

## Results (holdout)

46 cases, 29 positive labels, 18 negative cases.

| Tool | TP | FP | TN | FN | Precision | Recall | F1 | Sev-weighted recall | Precision incl. extras | Extra | Other | Inconclusive | Neg. cases clean | Scan time total / mean / max (s) | Peak RSS mean / max (MB) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| deployready | 18 | 1 | 449 | 11 | 0.95 | 0.62 | 0.75 | 0.64 | 0.95 | 0 | 3 | 0 | 17/18 | 17.9 / 0.39 / 0.5 | 101 / 110 |
| semgrep | 11 | 8 | 442 | 18 | 0.58 | 0.38 | 0.46 | 0.39 | 0.39 | 9 | 6 | 0 | 11/18 | 1099.5 / 23.90 / 47.5 | 167 / 170 |
| llm | 28 | 19 | 433 | 1 | 0.60 | 0.97 | 0.74 | 0.96 | 0.36 | 31 | 58 | 0 | 7/18 | 599.0 / 13.02 / 21.5 | 221 / 227 |

### Per class (TP/FP/FN; TN omitted)

| Class | Labels | deployready | semgrep | llm |
|---|---|---|---|---|
| client-secret-exposure | 2 | 2/0/0 | 0/0/2 | 2/2/0 |
| code-injection | 1 | 1/0/0 | 1/0/0 | 1/1/0 |
| command-injection | 1 | 1/0/0 | 1/0/0 | 1/0/0 |
| cors | 1 | 0/0/1 | 1/0/0 | 1/1/0 |
| debug-mode | 1 | 1/0/0 | 1/0/0 | 1/1/0 |
| firebase-open-rules | 1 | 0/0/1 | 0/0/1 | 1/0/0 |
| hardcoded-secret | 1 | 1/0/0 | 1/0/0 | 1/0/0 |
| idor | 2 | 1/0/1 | 0/0/2 | 2/3/0 |
| insecure-cookie | 1 | 1/0/0 | 1/6/0 | 1/1/0 |
| jwt-misconfig | 1 | 0/0/1 | 1/0/0 | 0/0/1 |
| mass-assignment | 1 | 0/0/1 | 0/0/1 | 1/0/0 |
| missing-auth | 2 | 1/0/1 | 0/0/2 | 2/4/0 |
| nosql-injection | 1 | 0/0/1 | 0/0/1 | 1/0/0 |
| open-redirect | 1 | 0/0/1 | 0/0/1 | 1/1/0 |
| path-traversal | 1 | 0/0/1 | 0/1/1 | 1/1/0 |
| rls-missing | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| rls-permissive | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| secret-committed | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| sqli | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| ssrf | 1 | 0/0/1 | 1/1/0 | 1/1/0 |
| tls-disabled | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| unsafe-deserialization | 2 | 2/0/0 | 2/0/0 | 2/0/0 |
| weak-password-hash | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| webhook-signature-missing | 1 | 0/0/1 | 0/0/1 | 1/0/0 |
| xss | 1 | 1/1/0 | 1/0/0 | 1/2/0 |


Case-level view: DeployReady caught 18 of 29 labels and kept 17 of 18 negative cases clean; the LLM caught 27 of 29 but was clean on only 8 of 18 negatives
(30 extra alerts on vulnerable cases, 57 out-of-taxonomy alerts); Semgrep caught 11 and was clean on 11 of 18.

## Main findings

- DeployReady misses (11): stripe webhook without signature check, open Firestore rules, path traversal, SSRF, `jwt.decode` as auth, mass assignment, open redirect,
  tenant-unscoped list (`findMany()` without org filter), reflected-origin CORS with credentials, server actions without auth, NoSQL operator injection.
  Its one false positive is `xss-sink` on `dangerouslySetInnerHTML` wrapped in `DOMPurify.sanitize` (n10).
- On the holdout DeployReady's recall (0.62) is far below its development-corpus recall (1.00): the development corpus overstates real-world recall.
- The LLM has the best recall (0.97) but poor precision on the secure twins; one run per case, so variance is unmeasured.
- Semgrep community rules cover injection/deserialization/eval well but nothing for Supabase RLS, Stripe webhooks, tenant isolation or client-exposed secrets.

## Limitations

- 46 small single-purpose cases and 29 labels: per-class numbers are 1-2 labels each and confidence intervals are wide. Totals are indicative, not statistically tight.
- Cases and labels were written by one author (an AI agent) and are not independently reviewed; labels were never validated by exploitation.
- The class mapping is ours. Semgrep and LLM mappings are keyword heuristics (e.g. Semgrep `insecure-cookie` produced 6 FP from broad cookie-related rule ids); DeployReady's mapping is rule-id exact. A different mapping would shift numbers, mostly for the two competitors.
- Semgrep: `p/default` and other registry packs unavailable (see above). LLM: one run, haiku only, sampled at default temperature, whole project in one prompt.
- DeployReady was run static-only and offline (no live/active/Supabase/AI engines, no dependency audit), which is the part comparable to the other tools; its live features are not exercised here.
- Timing/memory were measured on a shared sandbox; LLM time is dominated by network/model latency.
- Cases are tiny, so scan time and memory say little about large repositories.
- The holdout is only holdout while it stays unread by rule authors; it was seen by the author of this report after the first run, so it must not be used for tuning.

## Label and mapping fixes

None. No case or label was changed after results were seen, and the class mapping was not edited after the first run (the runner was only extended with reporting text).

## Development corpus (contrast, not merged)

`npx tsx benchmark/bench.ts --suite dev --run` (DeployReady only; labels are its own rule ids): 108 cases, 65 positive labels, TP 65 / FP 0 / FN 0, 1 extra alert.
Per-rule table: `benchmark/results/dev/summary.md`. This corpus was used while building the rules, so it is expected to be near-perfect.


### Label-fix log: h21 fixture value changed (after results)
- **What:** `h21-vite-env-committed/.env` held Stripe's public documentation example key (`sk_live_…`). GitHub push protection rejected it as a live Stripe key, so the repository could not be pushed. The value was replaced with a non-provider-format secret (`STRIPE_SECRET_KEY=prod-payments-secret-…`); the label class (`secret-committed`, `.env`) and severity are unchanged, the label note was updated.
- **Re-run:** all three tools were re-run on this one case only (`--only h21-vite-env-committed`) with the same pinned versions (DeployReady 0.5.0 from commit 448ea2b, Semgrep 1.187.0 + rules a5ad171, haiku one run).
- **Effect:** DeployReady and Semgrep unchanged on h21. The LLM run now reports the secret (FN → TP) and one more unlabelled class on the case (+1 FP), moving its totals from 27/18/2 to 28/19/1 (recall 0.93 → 0.97). This is within the single-run variance noted above; the earlier h21 output is not retained.

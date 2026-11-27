# DeployReady vs Semgrep OSS vs a plain LLM review

Reproduce: `npx tsx benchmark/compare.ts [--semgrep-rules <clone of semgrep/semgrep-rules>] [--llm] --out benchmark/compare/results.json`.
Without flags it re-scores the saved raw outputs in `benchmark/compare/raw/` (so the table below is reproducible offline for
Semgrep and the LLM; DeployReady is always run live).

## Method

- Corpus: the 20 projects in `benchmark/corpus/vibe/` (12 `-tp` vulnerable, 8 `-tn` hard-negative twins). Labels come from each `expect.json`.
  17 positive labels (one issue = one `(case, file, issue class)`), plus explicit and implicit negatives (every `-tn` case, and `present:false` labels).
  Route-guard checks are not separate labels; the corresponding `missing-auth-route` finding is. The one `unsupported:idor` label is included
  (it is a real issue no DeployReady rule covers).
- Issue classes (12): sqli, missing-auth, idor, hardcoded-secret, cors, tls, debug, rls-missing, rls-permissive, service-role-exposed, client-secret, env-committed.
  The mapping from each tool's output to a class is explicit in `compare.ts` (`DR_CLASS` by rule id, `SEMGREP_RULES` by check id + message + CWE tags, `LLM_RULES` by keywords in the free-text `issue`).
- A tool catches a label if it reports the same class in the same file (different wording is fine). Line numbers are recorded but not required: labels are file-level, so the
  "within +/-3 lines" tolerance never decided an outcome.
- TP = label caught. FN = label missed. FP = a mapped-class alert on a `-tn` case, or an alert matching an explicit `present:false` label (deduped per case/file/class).
  "Extra" = mapped alert on a `-tp` case that matches no label (not penalised; labels are not exhaustive, and this is how `run.ts` treats non-strict cases).
  "Other" = alert outside the 12 classes (CSRF middleware, missing timeout, mass assignment, ...), not penalised. The last column counts every alert on `-tn` cases including "other" (strict view).
- DeployReady: 0.4.0 at base commit 47b311f, `VulnerabilityDetector.scan()` run directly (same entry point as `run.ts`).
- Semgrep OSS 1.187.0, run once over `corpus/vibe` with `--metrics=off`. `--config p/default` / `auto` hung (registry blocked by the sandbox proxy; no result within 60 s), so the
  rules repo was cloned instead: `github.com/semgrep/semgrep-rules` at commit `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`, taking the `javascript`, `typescript`, `python`
  and `generic` directories (799 rule files, `*.test.*`/`*.fixed.*` excluded). This is the community rule corpus that p/default is drawn from, but it is not the p/default
  pack (no registry-only/curated selection, no `p/secrets` or `p/security-audit` pack). A real `p/default` run could differ.
- Plain LLM: `claude` CLI 2.1.332, `claude -p --model haiku --tools "" --setting-sources ""`, default temperature, ONE run per case (20 runs). Prompt, verbatim:
  "Review this project for security vulnerabilities. List each issue as JSON lines {file, line, issue}." Stdin is a file listing plus every file of the case concatenated with
  `=== path ===` headers (`expect.json` excluded because it holds the labels). Raw outputs: `benchmark/compare/raw/llm/<case>.txt`. Semgrep raw output: `raw/semgrep.json`.

## Results (corpus/vibe, 17 positive labels)

| Tool | TP | FP | FN | Precision | Recall | Extra mapped | Other alerts | All alerts on -tn cases |
|---|---|---|---|---|---|---|---|---|
| DeployReady 0.4.0 | 16 | 0 | 1 | 1.00 | 0.94 | 0 | 0 | 0 |
| Semgrep OSS 1.187.0 (community rules) | 6 | 0 | 11 | 1.00 | 0.35 | 0 | 8 | 5 |
| LLM (haiku, 1 run) | 17 | 13 | 0 | 0.57 | 1.00 | 12 | 57 | 73 |

## Per class (TP/FP/FN)

| Class | Labels | DeployReady | Semgrep | LLM (haiku) |
|---|---|---|---|---|
| client-secret | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| cors | 1 | 1/0/0 | 0/0/1 | 1/1/0 |
| debug | 1 | 1/0/0 | 1/0/0 | 1/1/0 |
| env-committed | 1 | 1/0/0 | 0/0/1 | 1/1/0 |
| hardcoded-secret | 2 | 2/0/0 | 2/0/0 | 2/1/0 |
| idor | 1 | 0/0/1 | 0/0/1 | 1/2/0 |
| missing-auth | 2 | 2/0/0 | 0/0/2 | 2/3/0 |
| rls-missing | 2 | 2/0/0 | 0/0/2 | 2/0/0 |
| rls-permissive | 1 | 1/0/0 | 0/0/1 | 1/0/0 |
| service-role-exposed | 1 | 1/0/0 | 0/0/1 | 1/3/0 |
| sqli | 2 | 2/0/0 | 2/0/0 | 2/1/0 |
| tls | 2 | 2/0/0 | 1/0/1 | 2/0/0 |

## Where DeployReady wins

- vs Semgrep: everything Semgrep cannot see by construction. It has no rules for SQL migrations (Supabase RLS missing / `using (true)`), `.env` files and `.gitignore` state,
  `NEXT_PUBLIC_*` secret leakage, a Supabase service-role key in client code, wildcard CORS in Express, or "route has no auth" (the community rules only suggest CSRF middleware).
  Semgrep also missed `rejectUnauthorized: false` in the Express/fetch case. It was clean where it spoke: all 6 hits were correct, and its only `-tn` alerts were 4 CSRF-middleware nags and one `use-raise-for-status`
  (all "other" class, no mapped FPs).
- vs the LLM: precision. On the 8 safe twins DeployReady raised nothing; Haiku raised 73 alerts, 13 of them in mapped classes that the labels call wrong or out of scope
  (e.g. "no auth" on a deliberately public search route, "debug mode via env var" on the safe Flask app, a hardcoded-secret claim on a string comparison, service-role "without validation" on the server-only module).
  Output is also deterministic and free; the LLM output varies run to run.

## Where DeployReady loses

- IDOR (1 label, `express-idor-tp`): DeployReady has no rule; the LLM found it on both the GET and PUT handlers. This is the one DeployReady miss, and it is a known `unsupported` label.
- Breadth: the LLM found 57 "other" issues (missing try/catch, JWT without `algorithms`, mass assignment, no rate limiting, missing security headers, plain HTTP listener, `.gitignore`
  only covering `.env`). Some are real hardening gaps outside the label set. DeployReady's 0 "other" is partly a consequence of having a fixed rule list, not only of being precise.
- Recall on this corpus is a tie-ish: the LLM got 17/17, DeployReady 16/17. The LLM's advantage is purely the IDOR class.

## Judgement calls

- Label match is file + class. A label with no `file` matches any file in the case.
- LLM `plain HTTP / no TLS` complaints are NOT mapped to `tls` (the label means disabled certificate verification); TLS credit requires an explicit "verification disabled" style statement.
- Negated or informational LLM lines ("No issue found: .env is correctly ignored") are dropped. `.gitignore too narrow` is not `env-committed`; "no .gitignore" or ".env not ignored/committed" is.
- Semgrep `use-raise-for-status`, `use-timeout`, `avoid_app_run_with_bad_host`, CSRF checks: "other". `avoid_hardcoded_config_SECRET_KEY` counts as hardcoded-secret.
- The LLM mapping regexes were tightened once after reading the first LLM outputs (negation, "no ... index, but the RLS" false matches, `auth.uid` matching "auth"). That is a researcher
  degree of freedom; the changes only removed obviously wrong matches, but the fairest reading is that the LLM's FP counts have a margin of a few alerts either way. Class mapping for Semgrep was not tuned.
- "Extra mapped" alerts (12 for the LLM, 0 for the others) are real-looking extra findings in vulnerable cases, e.g. missing-auth on routes that were labelled for a different bug. Treating them as FPs would
  lower the LLM's precision further; treating `-tn` alerts as correct would raise it. Neither is knowable without a more exhaustive labelling.

## Caveats

- Synthetic corpus, 20 projects, 17 positive labels. One miss moves recall by 6 points. No confidence intervals are meaningful.
- Labels are DeployReady's own and the DeployReady rules were developed against this very corpus (and `knownGap` cases are the ones its authors already knew about). Its
  precision and recall here are close to a training-set number and are almost certainly optimistic for unseen code. Semgrep and the LLM are cold.
- Each case is tiny (1-3 files). That favours the LLM (everything fits in context, nothing to search) and understates Semgrep's value on large codebases, where its language-wide rules and
  maintenance matter more than on these seeded bugs. The corpus is also skewed toward Supabase/Next/Express vibe-code shapes DeployReady specialises in.
- One LLM run per case at default temperature, one small model (Haiku). A larger model, a stronger prompt, or repeats would change both recall and noise. Results are not stable across runs.
- Semgrep ran with the community rules repo, not the registry `p/default` pack (registry unreachable here). Semgrep Pro/taint-heavy packs and custom rules would catch more.
- Alert counting is per alert, not per developer-time: 73 LLM alerts on safe code is a triage cost the table cannot price, and conversely LLM prose explains fixes where DeployReady gives rule ids.

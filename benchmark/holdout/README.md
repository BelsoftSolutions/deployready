# Holdout benchmark: NEVER USE FOR RULE TUNING

This corpus measures how DeployReady (and competitors) do on projects the rules were **not** written against.
It is only meaningful while it stays unseen by whoever tunes the rules.

## Rules for everyone (humans and agents) working on `src/`

1. Do **not** read `benchmark/holdout/labels.json` or `benchmark/holdout/cases/**` while changing detection rules.
2. Do **not** read `benchmark/results/holdout/**` or `benchmark/HOLDOUT-RESULTS.md` to decide what to fix. Per-class aggregate
   numbers in release notes are fine; individual misses and false positives are not to be used as a to-do list.
3. Nothing under `src/` may mention the holdout (CI: `npm run check:holdout` fails if a file under `src/` references
   `holdout` or a holdout case id).
4. If a miss on the holdout reveals a real weakness, write a *new, differently shaped* development case under
   `benchmark/corpus/` and tune against that. Do not copy holdout code.
5. A holdout case may only change to fix a labelling error, and each such change is logged in `benchmark/HOLDOUT-RESULTS.md`
   ("Label and mapping fixes"). Adding new cases is fine; the suite then gets a new version in `labels.json`.

## Layout

- `cases/<id>/` - 46 small projects (`h*` = vulnerable, `n*` = secure negative twin or clean app). Code only, no labels inside.
  Written from the perspective of typical Lovable / Bolt / Cursor / v0 output and public vulnerability patterns
  (Next.js + Supabase, Express + Prisma/Mongoose/pg, FastAPI, Flask, Firebase, Stripe webhooks, multi-tenant SaaS),
  without consulting DeployReady's rule implementations.
- `labels.json` - **the single file with all expected labels**, by issue CLASS (25 classes), with severity and file.
  Negatives have an empty `labels` list. Tell tuning agents not to read this file.
- `../holdoutMapping.ts` - the maintained mapping table from each tool's output (DeployReady rule id, Semgrep
  check id/CWE, free-text LLM issue) to classes. It lives outside this directory on purpose: it names rule ids but no case.
- `../bench.ts --suite holdout` - the runner; `../results/holdout/` - saved raw tool outputs, per-case metadata and scores.
- `../HOLDOUT-RESULTS.md` - method, versions, results, limitations, label/mapping change log.

## Run

```
npm run build
npm run benchmark:holdout              # re-scores the saved raw outputs of every tool (offline)
npx tsx benchmark/bench.ts --suite holdout --tools deployready --run   # re-run one tool
```

The development corpus (`corpus/`) is scored separately (`npm run benchmark:dev`). Results of the two are never merged.

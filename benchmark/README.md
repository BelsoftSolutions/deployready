# Benchmark

`npx tsx benchmark/run.ts` runs the real scanners against labelled cases and prints per-case and per-rule precision/recall, a supported-rules summary, a total that counts unsupported labels as misses, and lists of misses and false positives. `--json` adds `misses` and `falsePositives`. Exit code 1 means a regression, or a `knownGap` case that now passes (remove its `knownGap`).

## Vibe-coded app corpus (`corpus/vibe/<case>/`)

Small projects shaped like Cursor/Lovable/Bolt/v0 output (Next.js + Supabase, Express + JWT, Vite + Supabase, Flask/FastAPI). Names end in `-tp` (vulnerable) or `-tn` (hard negative: the safe twin). Each has an `expect.json`:

- `expected` entries are findings (`{rule, present, file?}`), route guards (`{route, guarded}`), or unsupported labels (`{unsupported, present: true}`).
- `unsupported` marks a real issue no rule covers. It is scored as a miss under `unsupported:<name>` and never fails the case. Do not invent rule ids; when a rule ships, replace the label with its real id.
- `strict: true` counts any finding whose rule is not mentioned in `expected` as a false positive. Use it on hard negatives.
- `knownGap` documents a current detector weakness so the run stays green; it is reported as GAP.

`corpus/idor/<case>/` uses the same format (ids are reported as `idor/<case>`): broken object-level authorization cases for `idor-missing-ownership-check` in Express+Prisma/pg/Mongoose, Next.js route handlers + Supabase, FastAPI+SQLAlchemy and Flask, each vulnerable case with safe twins (scoped query, explicit owner check, admin guard, public catalog, RLS-scoped client).

`corpus/rls/<case>/` uses the same format (ids `rls/<case>`, all `strict`): Supabase migration histories for the migration-replay RLS model (`rls-not-enabled`, `rls-disabled`, `rls-permissive-policy`, `rls-no-policy`). `a01`-`a10` and `s01`-`s06` are our own reconstruction of an external audit's 10 insecure / 6 secure multi-tenant cases (the original corpus was not available); `v*` are further variations (renames, SET SCHEMA, quoted names, partitions, long histories, DO blocks, project config). Each `expect.json` also carries `groundTruth` probes; `PGHOST=... PGUSER=postgres npx tsx benchmark/rlsPgProof.ts` applies every case to a disposable PostgreSQL with Supabase-like roles and checks that anon / a signed-in user really can (or cannot) read or write another user's rows. All 38 labels were confirmed on PostgreSQL 16.

`corpus/` is excluded from `benchmark/tsconfig.json`, so the sample code needs no dependencies. `BASELINE.md` holds the output on the base commit.

## Holdout benchmark and runner

`benchmark/holdout/` is a held-out corpus (46 cases) that must never be used for rule tuning; see `holdout/README.md` and `HOLDOUT-RESULTS.md`.
`npx tsx benchmark/bench.ts --suite holdout|dev` reports TP/FP/TN/FN, precision, recall, F1, severity-weighted recall, scan time and peak memory per case, class and tool;
the two suites are never merged. `npm run check:holdout` fails if anything under `src/` references the holdout.

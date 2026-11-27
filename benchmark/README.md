# Benchmark

`npx tsx benchmark/run.ts` runs the real scanners against labelled cases and prints per-case and per-rule precision/recall, a supported-rules summary, a total that counts unsupported labels as misses, and lists of misses and false positives. `--json` adds `misses` and `falsePositives`. Exit code 1 means a regression, or a `knownGap` case that now passes (remove its `knownGap`).

## Vibe-coded app corpus (`corpus/vibe/<case>/`)

Small projects shaped like Cursor/Lovable/Bolt/v0 output (Next.js + Supabase, Express + JWT, Vite + Supabase, Flask/FastAPI). Names end in `-tp` (vulnerable) or `-tn` (hard negative: the safe twin). Each has an `expect.json`:

- `expected` entries are findings (`{rule, present, file?}`), route guards (`{route, guarded}`), or unsupported labels (`{unsupported, present: true}`).
- `unsupported` marks a real issue no rule covers. It is scored as a miss under `unsupported:<name>` and never fails the case. Do not invent rule ids; when a rule ships, replace the label with its real id.
- `strict: true` counts any finding whose rule is not mentioned in `expected` as a false positive. Use it on hard negatives.
- `knownGap` documents a current detector weakness so the run stays green; it is reported as GAP.

`corpus/` is excluded from `benchmark/tsconfig.json`, so the sample code needs no dependencies. `BASELINE.md` holds the output on the base commit.

-- DeployReady benchmark: synthetic migration written for the RLS model tests.
drop table if exists public.tmp_backfill;
alter policy "write own" on public.messages rename to "insert own";

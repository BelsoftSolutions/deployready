-- DeployReady benchmark: synthetic migration written for the RLS model tests.
alter table private.payouts set schema public;
grant all on table public.payouts to anon, authenticated;

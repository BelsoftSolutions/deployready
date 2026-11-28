-- DeployReady benchmark: synthetic migration written for the RLS model tests.
alter table public.messages add column read_at timestamptz;

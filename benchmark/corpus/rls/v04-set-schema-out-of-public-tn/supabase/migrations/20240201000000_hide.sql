-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create schema if not exists internal;
alter table public.raw_events set schema internal;

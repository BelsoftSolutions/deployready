-- DeployReady benchmark: synthetic migration written for the RLS model tests.
alter table public.messages rename column author to sender_id;

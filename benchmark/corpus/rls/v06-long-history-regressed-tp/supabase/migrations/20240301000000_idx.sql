-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create index messages_sender_idx on public.messages (sender_id);

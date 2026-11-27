-- DeployReady benchmark: synthetic migration written for the RLS model tests.
-- "feed" feature
drop policy "own rows" on public.messages;
create policy "feed" on public.messages for select using (true);

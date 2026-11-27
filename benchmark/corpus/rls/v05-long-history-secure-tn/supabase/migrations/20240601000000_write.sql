-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create policy "write own" on public.messages for insert to authenticated with check (sender_id = (select auth.uid()));

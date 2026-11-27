-- DeployReady benchmark: synthetic migration written for the RLS model tests.
drop policy "dev all" on public.messages;
create policy "read own" on public.messages for select to authenticated using (sender_id = auth.uid());

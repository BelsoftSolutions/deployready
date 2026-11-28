-- DeployReady benchmark: synthetic migration written for the RLS model tests.
alter policy "read own" on public.messages using (sender_id = (select auth.uid()));

-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.messages (id bigint primary key, sender_id uuid not null, body text);
alter table public.messages enable row level security;
create policy "own rows" on public.messages for all to authenticated
  using (sender_id = (select auth.uid())) with check (sender_id = (select auth.uid()));

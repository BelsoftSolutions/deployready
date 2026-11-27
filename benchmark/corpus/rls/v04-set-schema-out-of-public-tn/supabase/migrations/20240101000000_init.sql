-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.raw_events (id bigint primary key, payload jsonb);
create table public.notes (id bigint primary key, user_id uuid not null);
alter table public.notes enable row level security;
create policy "own rows" on public.notes for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

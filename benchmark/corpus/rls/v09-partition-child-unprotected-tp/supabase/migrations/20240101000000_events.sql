-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.events (id bigint not null, user_id uuid not null, at date not null) partition by range (at);
alter table public.events enable row level security;
create policy "own rows" on public.events for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create table public.events_2024 partition of public.events for values from ('2024-01-01') to ('2025-01-01');

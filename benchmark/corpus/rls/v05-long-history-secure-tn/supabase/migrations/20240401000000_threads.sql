-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.threads (id bigint primary key, owner_id uuid not null);
alter table public.threads enable row level security;
create policy "own rows" on public.threads for all to authenticated
  using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));

-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.invoices (id bigint primary key, user_id uuid not null);
alter table public.invoices enable row level security;
create policy "own rows" on public.invoices for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

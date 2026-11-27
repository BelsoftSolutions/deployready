-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.invoice_drafts (id bigint primary key, user_id uuid not null);
alter table public.invoice_drafts enable row level security;
create policy "own rows" on public.invoice_drafts for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

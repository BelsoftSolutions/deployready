-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create table public.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null default 0
);
alter table public.invoices enable row level security;
create policy "Signed-in users read invoices" on public.invoices for select to authenticated using (true);
create policy "Owners create their invoices" on public.invoices for insert to authenticated with check ((select auth.uid()) = user_id);

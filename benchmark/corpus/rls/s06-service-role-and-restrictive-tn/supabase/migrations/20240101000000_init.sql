-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create table public.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null default 0
);
alter table public.invoices enable row level security;
alter table public.invoices force row level security;
create policy "service role manages invoices" on public.invoices for all to service_role using (true) with check (true);
create policy "users read invoices" on public.invoices for select to authenticated using (true);
create policy "tenant guard" on public.invoices as restrictive for all to authenticated using (user_id = (select auth.uid()));

-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
create table public.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null default 0
);
alter table public.invoices enable row level security;
create policy "owners read invoices" on public.invoices for select to authenticated using ((select auth.uid()) = user_id);
create view public.invoice_list with (security_invoker = true) as select id, user_id, amount_cents from public.invoices;

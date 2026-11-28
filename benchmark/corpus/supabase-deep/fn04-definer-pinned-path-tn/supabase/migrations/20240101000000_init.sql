-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
create table public.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null default 0
);
alter table public.invoices enable row level security;
create policy "owners read invoices" on public.invoices for select to authenticated using ((select auth.uid()) = user_id);
create schema private;
create function private.invoice_count() returns bigint
  language sql stable security definer set search_path = ''
as $$ select count(*) from public.invoices $$;
grant usage on schema private to authenticated;

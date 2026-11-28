-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
create table public.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null default 0
);
alter table public.invoices enable row level security;
create policy "owners read invoices" on public.invoices for select to authenticated using ((select auth.uid()) = user_id);
create function public.my_invoice_total() returns bigint
  language sql stable security definer set search_path = ''
as $$
  select coalesce(sum(amount_cents), 0) from public.invoices where user_id = (select auth.uid());
$$;
revoke execute on function public.my_invoice_total() from public, anon;

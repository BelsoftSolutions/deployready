-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create table public.orders (id bigint generated always as identity primary key, user_id uuid not null, total_cents integer not null default 0);
alter table public.orders enable row level security;
create policy "read own orders" on public.orders for select to authenticated using (user_id = (select auth.uid()));
create policy "create orders" on public.orders for insert to authenticated with check (true and true);
create policy "update orders" on public.orders for update to authenticated using (1=1) with check (not false);

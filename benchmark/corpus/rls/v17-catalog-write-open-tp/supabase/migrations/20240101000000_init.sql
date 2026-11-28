-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.products (id bigint generated always as identity primary key, name text, price_cents integer);
alter table public.products enable row level security;
create policy "read products" on public.products for select using (true);
create policy "add products" on public.products for insert with check (true);

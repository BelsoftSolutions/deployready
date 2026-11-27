-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.payments (id bigint primary key, user_id uuid not null, amount_cents integer);
alter table public.payments enable row level security;
create policy "signed in users" on public.payments for select using ((select auth.uid()) is not null);

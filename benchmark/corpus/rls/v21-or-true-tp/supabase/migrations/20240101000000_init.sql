-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.subscriptions (id bigint primary key, user_id uuid not null, plan text);
alter table public.subscriptions enable row level security;
create policy "own subscription" on public.subscriptions for all
  using (user_id = auth.uid() or true)
  with check (user_id = auth.uid());

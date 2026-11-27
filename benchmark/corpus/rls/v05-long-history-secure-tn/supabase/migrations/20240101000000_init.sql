-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.messages (id bigint primary key, author uuid not null, body text);
alter table public.messages enable row level security;
create policy "dev all" on public.messages for all using (true) with check (true);

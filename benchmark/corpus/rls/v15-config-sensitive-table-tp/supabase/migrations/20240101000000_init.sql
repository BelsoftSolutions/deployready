-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.widgets (id bigint primary key, label text);
alter table public.widgets enable row level security;
create policy "read widgets" on public.widgets for select using (true);

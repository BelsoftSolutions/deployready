-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.announcements (id bigint primary key, body text);
alter table public.announcements enable row level security;
create policy "everyone reads" on public.announcements for select using (true);

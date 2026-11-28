-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.profiles (id uuid primary key, full_name text);
alter table public.profiles enable row level security;
create policy "anon read" on public.profiles for select to anon using (true);
create policy "own profile" on public.profiles for select to authenticated using (id = (select auth.uid()));

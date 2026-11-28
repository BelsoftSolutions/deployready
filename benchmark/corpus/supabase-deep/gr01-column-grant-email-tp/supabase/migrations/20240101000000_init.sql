-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
create table public.profiles (
  id uuid primary key,
  username text not null,
  avatar_url text,
  email text not null
);
alter table public.profiles enable row level security;
create policy "profiles are public" on public.profiles for select using (true);
revoke select on public.profiles from anon, authenticated;
grant select (id, username, avatar_url, email) on public.profiles to anon, authenticated;

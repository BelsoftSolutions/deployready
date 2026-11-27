create table public.profiles (
  id uuid primary key references auth.users(id),
  username text unique
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for all using (auth.uid() = id);

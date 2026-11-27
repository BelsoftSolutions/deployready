create table public.profiles (
  id uuid primary key references auth.users(id),
  username text unique
);
alter table public.profiles enable row level security;
create policy "read own profile" on public.profiles for select using (auth.uid() = id);
create policy "update own profile" on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);

create table public.posts (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles(id),
  body text not null
);
alter table public.posts enable row level security;
create policy "read own posts" on public.posts for select using (auth.uid() = user_id);
create policy "insert own posts" on public.posts for insert with check (auth.uid() = user_id);

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text
);
alter table public.profiles enable row level security;
create policy "read own profile" on public.profiles for select using (auth.uid() = id);
create policy "update own profile" on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id),
  total_cents integer not null
);
alter table public.orders enable row level security;
create policy "own orders select" on public.orders for select using (auth.uid() = user_id);
create policy "own orders insert" on public.orders for insert with check (auth.uid() = user_id);

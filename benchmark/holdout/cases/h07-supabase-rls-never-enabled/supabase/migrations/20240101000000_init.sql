create table public.profiles (
  id uuid primary key references auth.users(id),
  full_name text,
  phone text,
  created_at timestamptz default now()
);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id),
  total_cents integer not null,
  created_at timestamptz default now()
);

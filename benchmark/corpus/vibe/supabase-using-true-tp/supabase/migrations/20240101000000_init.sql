create table public.documents (
  id bigint generated always as identity primary key,
  owner_id uuid references auth.users(id),
  title text,
  content text
);
alter table public.documents enable row level security;

-- "make it work" policies: RLS is on but anyone can do anything
create policy "Enable read access for all users" on public.documents for select using (true);
create policy "Enable insert for all users" on public.documents for insert with check (true);
create policy "Enable update for all users" on public.documents for update using (true);
create policy "Enable delete for all users" on public.documents for delete using (true);

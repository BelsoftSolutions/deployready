create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  body text
);
alter table public.notes enable row level security;

create policy "anyone can read notes" on public.notes for select using (true);
create policy "anyone can update notes" on public.notes for update using (true) with check (true);
create policy "owners insert" on public.notes for insert with check (auth.uid() = user_id);

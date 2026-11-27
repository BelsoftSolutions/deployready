create table invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  amount integer not null
);
alter table invoices enable row level security;
create policy "owner reads" on invoices for select using (auth.uid() = user_id);
create policy "owner deletes" on invoices for delete using (auth.uid() = user_id);

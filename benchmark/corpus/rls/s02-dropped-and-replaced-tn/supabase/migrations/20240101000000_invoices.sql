-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create table public.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null default 0
);
alter table public.invoices enable row level security;
-- prototype: open everything up
create policy "Allow all" on public.invoices for all using (true) with check (true);

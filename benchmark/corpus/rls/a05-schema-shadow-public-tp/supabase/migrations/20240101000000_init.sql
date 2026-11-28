-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create schema if not exists private;
create table private.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null default 0
);
alter table private.invoices enable row level security;
create table public.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null default 0
);
create table public.notes (id bigint primary key, user_id uuid not null);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

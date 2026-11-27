-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create schema if not exists internal;
set search_path to internal, public;
create table jobs (id bigint primary key, payload jsonb);
reset search_path;
create table public.notes (id bigint primary key, user_id uuid not null);
alter table public.notes enable row level security;
create policy "own rows" on public.notes for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

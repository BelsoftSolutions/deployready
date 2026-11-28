-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.notes (id bigint primary key, user_id uuid not null);
create table public.tasks (id bigint primary key, user_id uuid not null);
